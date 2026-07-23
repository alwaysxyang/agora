use super::NetworkState;
use super::inspection::{DomainObservation, ProtocolInspector};
use crate::audit::AuditCallback;
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
                        Self::relay(state, client, source).await;
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

    async fn relay(
        state: Arc<NetworkState<C>>,
        mut client: TcpStream,
        source: std::net::SocketAddr,
    ) {
        let Some(route) = state.routes.take(source) else {
            let _ = client.shutdown().await;
            return;
        };
        let started = Instant::now();
        let outcome =
            Self::copy_with_inspection(&state, &route.registration, client, route.upstream).await;
        let duration_ms = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
        state.publish_closed(
            &route.registration,
            outcome.result,
            duration_ms,
            outcome.domain.as_ref(),
        );
    }

    async fn copy_with_inspection(
        state: &NetworkState<C>,
        registration: &crate::protocol::RouteRegistration,
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
