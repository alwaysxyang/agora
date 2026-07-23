use super::NetworkState;
use crate::audit::AuditCallback;
use crate::protocol::{ControlRequest, ControlResponse, MAX_FRAME_SIZE};
use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::watch;
use tokio::task::JoinSet;

pub(super) struct ControlServer<C>
where
    C: AuditCallback,
{
    listener: UnixListener,
    state: Arc<NetworkState<C>>,
}

impl<C> ControlServer<C>
where
    C: AuditCallback,
{
    pub(super) fn new(listener: UnixListener, state: Arc<NetworkState<C>>) -> Self {
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
                    let (stream, _) = accepted.context("sandbox control accept failed")?;
                    let state = Arc::clone(&self.state);
                    connections.spawn(async move {
                        let _ = ControlConnection::new(stream, state).serve().await;
                    });
                }
                Some(_) = connections.join_next(), if !connections.is_empty() => {}
            }
        }
        connections.shutdown().await;
        Ok(())
    }
}

struct ControlConnection<C>
where
    C: AuditCallback,
{
    stream: UnixStream,
    state: Arc<NetworkState<C>>,
}

impl<C> ControlConnection<C>
where
    C: AuditCallback,
{
    fn new(stream: UnixStream, state: Arc<NetworkState<C>>) -> Self {
        Self { stream, state }
    }

    async fn serve(mut self) -> Result<()> {
        let request = self.read_request().await?;
        let response = self.state.handle_request(request).await;
        self.write_response(&response).await
    }

    async fn read_request(&mut self) -> Result<ControlRequest> {
        let mut length = [0_u8; 4];
        self.stream
            .read_exact(&mut length)
            .await
            .context("failed to read sandbox control frame length")?;
        let length = u32::from_be_bytes(length) as usize;
        anyhow::ensure!(
            length <= MAX_FRAME_SIZE,
            "sandbox control frame exceeds {MAX_FRAME_SIZE} bytes"
        );
        let mut payload = vec![0_u8; length];
        self.stream
            .read_exact(&mut payload)
            .await
            .context("failed to read sandbox control frame")?;
        serde_json::from_slice(&payload).context("invalid sandbox control request")
    }

    async fn write_response(&mut self, response: &ControlResponse) -> Result<()> {
        let payload = serde_json::to_vec(response).context("failed to encode control response")?;
        anyhow::ensure!(
            payload.len() <= MAX_FRAME_SIZE,
            "sandbox control response exceeds {MAX_FRAME_SIZE} bytes"
        );
        self.stream
            .write_all(&(payload.len() as u32).to_be_bytes())
            .await
            .context("failed to write sandbox control frame length")?;
        self.stream
            .write_all(&payload)
            .await
            .context("failed to write sandbox control response")
    }
}
