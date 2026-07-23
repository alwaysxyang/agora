use super::NetworkState;
use super::inspection::{DomainObservation, ProtocolInspector};
use crate::audit::AuditCallback;
use crate::protocol::{
    HANDSHAKE_TIMEOUT, MAX_FRAME_SIZE, ProtocolError, ProxyRequest, RouteRegistration,
    encode_proxy_response, parse_proxy_request, request_body_length,
};
use anyhow::{Context, Result};
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinSet;

pub(super) struct ProxyServer<C>
where
    C: AuditCallback,
{
    listener: TcpListener,
    state: Arc<NetworkState<C>>,
}

impl<C> ProxyServer<C>
where
    C: AuditCallback,
{
    pub(super) fn new(listener: TcpListener, state: Arc<NetworkState<C>>) -> Self {
        Self { listener, state }
    }

    pub(super) async fn run(self, mut shutdown: watch::Receiver<bool>) -> Result<()> {
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                accepted = self.listener.accept() => {
                    let (client, source) = accepted.context("sandbox proxy accept failed")?;
                    let state = Arc::clone(&self.state);
                    connections.spawn(async move {
                        Self::handle_connection(state, client, source).await;
                    });
                }
                Some(_) = connections.join_next(), if !connections.is_empty() => {}
            }
        }
        let drained = tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while connections.join_next().await.is_some() {}
        })
        .await;
        if drained.is_err() {
            connections.shutdown().await;
        }
        Ok(())
    }

    async fn handle_connection(
        state: Arc<NetworkState<C>>,
        mut client: TcpStream,
        source: std::net::SocketAddr,
    ) {
        let request =
            match tokio::time::timeout(HANDSHAKE_TIMEOUT, Self::read_request(&mut client)).await {
                Ok(Ok(request)) => request,
                Ok(Err(error)) => {
                    Self::reject(&mut client, error.status(), None).await;
                    return;
                }
                Err(_) => {
                    Self::reject(&mut client, 408, Some(libc::ETIMEDOUT)).await;
                    return;
                }
            };

        if let Err(error) = state.validate_request(&request) {
            Self::reject(&mut client, error.status(), None).await;
            return;
        }

        match request {
            ProxyRequest::CoverageGap(gap) => {
                state.publish_coverage_gap(&gap);
                let _ = client.write_all(&encode_proxy_response(204, None)).await;
                let _ = client.shutdown().await;
            }
            ProxyRequest::Connect(request) => {
                let registration = request.into_registration(source);
                match state.connect_upstream(&registration).await {
                    Ok(upstream) => Self::relay(state, client, upstream, registration).await,
                    Err(error) => {
                        let status = if error.kind() == io::ErrorKind::TimedOut {
                            504
                        } else {
                            502
                        };
                        Self::reject(&mut client, status, error.raw_os_error()).await;
                    }
                }
            }
        }
    }

    async fn read_request(client: &mut TcpStream) -> Result<ProxyRequest, ProtocolError> {
        let mut head = Vec::with_capacity(1024);
        while head.len() < MAX_FRAME_SIZE {
            let mut byte = 0_u8;
            let read = client
                .read(std::slice::from_mut(&mut byte))
                .await
                .map_err(|error| {
                    ProtocolError::bad_request(format!("failed to read HTTP request: {error}"))
                })?;
            if read == 0 {
                return Err(ProtocolError::bad_request(
                    "proxy connection closed before the HTTP request was complete",
                ));
            }
            head.push(byte);
            if head.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        if !head.ends_with(b"\r\n\r\n") {
            return Err(ProtocolError::bad_request(format!(
                "HTTP request head exceeds {MAX_FRAME_SIZE} bytes",
            )));
        }

        let body_length = request_body_length(&head)?;
        if head.len().saturating_add(body_length) > MAX_FRAME_SIZE {
            return Err(ProtocolError::bad_request(format!(
                "HTTP request exceeds {MAX_FRAME_SIZE} bytes",
            )));
        }
        let mut body = vec![0_u8; body_length];
        client.read_exact(&mut body).await.map_err(|error| {
            ProtocolError::bad_request(format!("failed to read HTTP request body: {error}"))
        })?;
        parse_proxy_request(&head, &body)
    }

    async fn reject(client: &mut TcpStream, status: u16, errno: Option<i32>) {
        let _ = client
            .write_all(&encode_proxy_response(status, errno))
            .await;
        let _ = client.shutdown().await;
    }

    async fn relay(
        state: Arc<NetworkState<C>>,
        mut client: TcpStream,
        upstream: TcpStream,
        registration: RouteRegistration,
    ) {
        let started = Instant::now();
        if let Err(error) = client.write_all(&encode_proxy_response(200, None)).await {
            state.publish_closed(&registration, Err(error), 0, None);
            return;
        }
        let outcome = Self::copy_with_inspection(&state, &registration, client, upstream).await;
        let duration_ms = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
        state.publish_closed(
            &registration,
            outcome.result,
            duration_ms,
            outcome.domain.as_ref(),
        );
    }

    async fn copy_with_inspection(
        state: &NetworkState<C>,
        registration: &RouteRegistration,
        client: TcpStream,
        upstream: TcpStream,
    ) -> RelayOutcome {
        let (mut client_reader, mut client_writer) = client.into_split();
        let (mut upstream_reader, mut upstream_writer) = upstream.into_split();
        let observed_domain = Arc::new(Mutex::new(None));
        let client_domain = Arc::clone(&observed_domain);
        let client_to_upstream = async {
            let mut inspector = ProtocolInspector::new();
            let mut bytes_sent = 0_u64;
            let mut buffer = [0_u8; 16 * 1024];
            loop {
                let read = client_reader.read(&mut buffer).await?;
                if read == 0 {
                    upstream_writer.shutdown().await?;
                    break;
                }
                if let Some(domain) = inspector.inspect(&buffer[..read]) {
                    state.publish_domain_observed(registration, &domain);
                    *client_domain
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(domain);
                }
                upstream_writer.write_all(&buffer[..read]).await?;
                bytes_sent = bytes_sent.saturating_add(read as u64);
            }
            Ok::<_, io::Error>(bytes_sent)
        };
        let upstream_to_client = async {
            let bytes_received = tokio::io::copy(&mut upstream_reader, &mut client_writer).await?;
            client_writer.shutdown().await?;
            Ok::<_, io::Error>(bytes_received)
        };
        let result = tokio::try_join!(client_to_upstream, upstream_to_client);
        let domain = observed_domain
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        RelayOutcome { result, domain }
    }
}

struct RelayOutcome {
    result: io::Result<(u64, u64)>,
    domain: Option<DomainObservation>,
}
