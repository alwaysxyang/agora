use super::protocol::{
    PROTOCOL_VERSION, Request, RequestEnvelope, Response, ResponseEnvelope, valid_request_id,
};
use super::service::LocalBroker;
use crate::filesystem::FileCipher;
use crate::ipc;
use anyhow::{Context, Result};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;
use uuid::Uuid;

const MAX_CONNECTIONS: usize = 128;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(1);
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug)]
pub(crate) struct LocalRuntime {
    socket: PathBuf,
    token: String,
}

impl LocalRuntime {
    pub(crate) fn socket(&self) -> &Path {
        &self.socket
    }

    pub(crate) fn token(&self) -> &str {
        &self.token
    }
}

pub(crate) struct LocalController {
    runtime: LocalRuntime,
    broker: Arc<LocalBroker>,
    shutdown: watch::Sender<bool>,
    tasks: JoinSet<Result<()>>,
}

impl LocalController {
    pub(crate) async fn start(
        root: &Path,
        cipher: FileCipher,
        runtime_directory: &Path,
    ) -> Result<Self> {
        std::fs::create_dir_all(runtime_directory)?;
        let socket = runtime_directory.join("local-filesystem.sock");
        let listener = UnixListener::bind(&socket).with_context(|| {
            format!(
                "failed to bind local filesystem broker {}",
                socket.display()
            )
        })?;
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))?;
        let broker = Arc::new(LocalBroker::new(root, cipher)?);
        let runtime = LocalRuntime {
            socket,
            token: Uuid::new_v4().simple().to_string(),
        };
        let state = Arc::new(ServerState {
            token: runtime.token.clone(),
            broker: Arc::clone(&broker),
        });
        let (shutdown, receiver) = watch::channel(false);
        let mut tasks = JoinSet::new();
        tasks.spawn(Server::new(listener, state).run(receiver));
        Ok(Self {
            runtime,
            broker,
            shutdown,
            tasks,
        })
    }

    pub(crate) fn runtime(&self) -> &LocalRuntime {
        &self.runtime
    }

    pub(crate) async fn wait_failure(&mut self) -> anyhow::Error {
        match self.tasks.join_next().await {
            Some(Ok(Ok(()))) => anyhow::anyhow!("local filesystem broker stopped unexpectedly"),
            Some(Ok(Err(error))) => error.context("local filesystem broker failed"),
            Some(Err(error)) => {
                anyhow::Error::from(error).context("local filesystem broker task failed")
            }
            None => anyhow::anyhow!("local filesystem broker has no active task"),
        }
    }

    pub(crate) async fn shutdown(mut self) -> Result<()> {
        let _ = self.shutdown.send(true);
        let mut first = None;
        while let Some(result) = self.tasks.join_next().await {
            match result {
                Ok(Ok(())) => {}
                Ok(Err(error)) if first.is_none() => first = Some(error),
                Err(error) if first.is_none() => first = Some(error.into()),
                _ => {}
            }
        }
        let broker = Arc::clone(&self.broker);
        tokio::task::spawn_blocking(move || broker.flush_all())
            .await
            .context("local filesystem final flush task failed")??;
        let _ = std::fs::remove_file(&self.runtime.socket);
        match first {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

impl Drop for LocalController {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
        self.tasks.abort_all();
        let _ = std::fs::remove_file(&self.runtime.socket);
    }
}

struct ServerState {
    token: String,
    broker: Arc<LocalBroker>,
}

struct Server {
    listener: UnixListener,
    state: Arc<ServerState>,
    connections: Arc<Semaphore>,
}

impl Server {
    fn new(listener: UnixListener, state: Arc<ServerState>) -> Self {
        Self {
            listener,
            state,
            connections: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
        }
    }

    async fn run(self, mut shutdown: watch::Receiver<bool>) -> Result<()> {
        let mut tasks = JoinSet::new();
        let mut expiry = tokio::time::interval(Duration::from_secs(30));
        expiry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                biased;
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
                _ = expiry.tick() => {
                    self.state.broker.expire_closed();
                    self.state.broker.expire_requests();
                },
                accepted = self.listener.accept() => {
                    let (stream, _) = accepted?;
                    let Ok(permit) = Arc::clone(&self.connections).try_acquire_owned() else {
                        drop(stream);
                        continue;
                    };
                    let state = Arc::clone(&self.state);
                    tasks.spawn(async move {
                        let _permit = permit;
                        let _ = Self::handle(stream, state).await;
                    });
                }
            }
        }
        while tasks.join_next().await.is_some() {}
        Ok(())
    }

    async fn handle(stream: UnixStream, state: Arc<ServerState>) -> Result<()> {
        let stream = stream.into_std()?;
        stream.set_nonblocking(false)?;
        stream.set_read_timeout(Some(REQUEST_TIMEOUT))?;
        stream.set_write_timeout(Some(RESPONSE_TIMEOUT))?;
        tokio::task::spawn_blocking(move || {
            let mut stream = stream;
            let (request, descriptor) = ipc::receive::<RequestEnvelope>(&mut stream)?;
            let response = if request.version != PROTOCOL_VERSION {
                Response::Error {
                    errno: libc::EPROTO,
                    message: "unsupported local filesystem protocol version".to_string(),
                }
            } else if !constant_time_equal(request.token.as_bytes(), state.token.as_bytes()) {
                Response::Error {
                    errno: libc::EACCES,
                    message: "invalid local filesystem token".to_string(),
                }
            } else if !valid_request_id(&request.request_id)
                || matches!(
                    &request.request,
                    Request::Claim { request_id } if !valid_request_id(request_id)
                )
                || matches!(
                    &request.request,
                    Request::BeginWrite { write_id, .. }
                        | Request::FinishWrite { write_id, .. }
                        | Request::CancelWrite { write_id, .. }
                        if !valid_request_id(write_id)
                )
            {
                Response::Error {
                    errno: libc::EPROTO,
                    message: "invalid local filesystem request ID".to_string(),
                }
            } else {
                state
                    .broker
                    .handle_request(request.request_id.clone(), request.request, descriptor)
                    .response
            };
            ipc::send(
                &mut stream,
                &ResponseEnvelope {
                    version: PROTOCOL_VERSION,
                    request_id: request.request_id,
                    response,
                },
                None,
            )
        })
        .await
        .context("local filesystem request task failed")??;
        Ok(())
    }
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

#[cfg(test)]
#[path = "controller/tests.rs"]
mod tests;
