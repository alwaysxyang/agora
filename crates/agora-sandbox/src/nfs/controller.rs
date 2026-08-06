use crate::nfs::backend::RemoteStorage;
use crate::nfs::broker::Broker;
use crate::nfs::protocol::{PROTOCOL_VERSION, RequestEnvelope, Response, ResponseEnvelope};
use crate::nfs::transport;
use anyhow::{Context, Result};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;
use uuid::Uuid;

const REMOTE_MAX_CONNECTIONS: usize = 128;
const REMOTE_REQUEST_TIMEOUT: Duration = Duration::from_secs(1);
const REMOTE_RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum RemoteConnectionStatus {
    Connected { root: u32 },
    Unavailable { root: u32, errno: libc::c_int },
}

impl RemoteConnectionStatus {
    pub(crate) fn root(&self) -> u32 {
        match self {
            Self::Connected { root } | Self::Unavailable { root, .. } => *root,
        }
    }
}

pub(crate) enum RemoteControllerEvent {
    Connection(RemoteConnectionStatus),
    Failure(anyhow::Error),
}

#[derive(Clone, Debug)]
pub(crate) struct RemoteRuntime {
    socket: PathBuf,
    token: String,
}

impl RemoteRuntime {
    pub(crate) fn socket(&self) -> &Path {
        &self.socket
    }

    pub(crate) fn token(&self) -> &str {
        &self.token
    }
}

pub(crate) struct RemoteController {
    runtime: RemoteRuntime,
    shutdown: watch::Sender<bool>,
    tasks: JoinSet<Result<()>>,
    connection_probes: JoinSet<RemoteConnectionStatus>,
}

impl RemoteController {
    pub(crate) async fn start_with_storage<S>(
        storage: Arc<S>,
        runtime_directory: &Path,
    ) -> Result<Self>
    where
        S: RemoteStorage,
    {
        std::fs::create_dir_all(runtime_directory).with_context(|| {
            format!(
                "failed to create remote filesystem runtime directory {}",
                runtime_directory.display()
            )
        })?;
        let socket = runtime_directory.join("nfs.sock");
        let listener = UnixListener::bind(&socket).with_context(|| {
            format!(
                "failed to bind remote filesystem broker {}",
                socket.display()
            )
        })?;
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))
            .context("failed to secure remote filesystem broker socket")?;
        let broker = Arc::new(Broker::new(storage, runtime_directory)?);
        let token = Uuid::new_v4().simple().to_string();
        let state = Arc::new(RemoteState {
            token: token.clone(),
            broker,
        });
        let (shutdown, receiver) = watch::channel(false);
        let mut tasks = JoinSet::new();
        tasks.spawn(RemoteServer::new(listener, state).run(receiver));
        Ok(Self {
            runtime: RemoteRuntime { socket, token },
            shutdown,
            tasks,
            connection_probes: JoinSet::new(),
        })
    }

    pub(crate) async fn start_with_storage_and_connection_probes<S>(
        storage: Arc<S>,
        runtime_directory: &Path,
        roots: u32,
    ) -> Result<Self>
    where
        S: RemoteStorage,
    {
        let mut controller =
            Self::start_with_storage(Arc::clone(&storage), runtime_directory).await?;
        for root in 0..roots {
            let storage = Arc::clone(&storage);
            controller.connection_probes.spawn(async move {
                match storage.connect(root).await {
                    Ok(()) => RemoteConnectionStatus::Connected { root },
                    Err(error) => RemoteConnectionStatus::Unavailable {
                        root,
                        errno: error.errno(),
                    },
                }
            });
        }
        Ok(controller)
    }

    pub(crate) fn runtime(&self) -> &RemoteRuntime {
        &self.runtime
    }

    pub(crate) async fn wait_event(&mut self) -> RemoteControllerEvent {
        tokio::select! {
            result = self.tasks.join_next() => RemoteControllerEvent::Failure(match result {
                Some(Ok(Ok(()))) => {
                    anyhow::anyhow!("remote filesystem broker stopped unexpectedly")
                }
                Some(Ok(Err(error))) => error.context("remote filesystem broker failed"),
                Some(Err(error)) => {
                    anyhow::Error::from(error).context("remote filesystem broker task failed")
                }
                None => anyhow::anyhow!("remote filesystem broker has no active task"),
            }),
            result = self.connection_probes.join_next(), if !self.connection_probes.is_empty() => {
                match result {
                    Some(Ok(status)) => RemoteControllerEvent::Connection(status),
                    Some(Err(error)) => RemoteControllerEvent::Failure(
                        anyhow::Error::from(error)
                            .context("remote filesystem connection probe task failed"),
                    ),
                    None => unreachable!("non-empty connection probe set returned no task"),
                }
            }
        }
    }

    #[cfg(test)]
    pub(crate) async fn wait_failure(&mut self) -> anyhow::Error {
        loop {
            if let RemoteControllerEvent::Failure(error) = self.wait_event().await {
                return error;
            }
        }
    }

    pub(crate) async fn shutdown(mut self) -> Result<()> {
        let _ = self.shutdown.send(true);
        self.connection_probes.abort_all();
        while self.connection_probes.join_next().await.is_some() {}
        let mut first_error = None;
        while let Some(task) = self.tasks.join_next().await {
            match task {
                Ok(Ok(())) => {}
                Ok(Err(error)) if first_error.is_none() => first_error = Some(error),
                Err(error) if first_error.is_none() => first_error = Some(error.into()),
                _ => {}
            }
        }
        let remove = std::fs::remove_file(&self.runtime.socket);
        if let Err(error) = remove
            && error.kind() != std::io::ErrorKind::NotFound
            && first_error.is_none()
        {
            first_error = Some(error.into());
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    #[cfg(test)]
    pub(crate) fn abort_server_for_test(&mut self) {
        self.tasks.spawn(async {
            anyhow::bail!("injected remote filesystem failure");
        });
    }
}

impl Drop for RemoteController {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
        self.tasks.abort_all();
        self.connection_probes.abort_all();
        let _ = std::fs::remove_file(&self.runtime.socket);
    }
}

struct RemoteState<S>
where
    S: RemoteStorage,
{
    token: String,
    broker: Arc<Broker<S>>,
}

struct RemoteServer<S>
where
    S: RemoteStorage,
{
    listener: UnixListener,
    state: Arc<RemoteState<S>>,
    connections: Arc<Semaphore>,
}

impl<S> RemoteServer<S>
where
    S: RemoteStorage,
{
    fn new(listener: UnixListener, state: Arc<RemoteState<S>>) -> Self {
        Self {
            listener,
            state,
            connections: Arc::new(Semaphore::new(REMOTE_MAX_CONNECTIONS)),
        }
    }

    async fn run(self, mut shutdown: watch::Receiver<bool>) -> Result<()> {
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                biased;
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                Some(_) = connections.join_next(), if !connections.is_empty() => {}
                accepted = self.listener.accept() => {
                    let (stream, _) = accepted.context("remote filesystem accept failed")?;
                    let Ok(permit) = Arc::clone(&self.connections).try_acquire_owned() else {
                        drop(stream);
                        continue;
                    };
                    let state = Arc::clone(&self.state);
                    connections.spawn(async move {
                        let _permit = permit;
                        let _ = Self::handle(stream, state).await;
                    });
                }
            }
        }
        connections.abort_all();
        while connections.join_next().await.is_some() {}
        Ok(())
    }

    async fn handle(stream: UnixStream, state: Arc<RemoteState<S>>) -> Result<()> {
        let stream = stream.into_std()?;
        configure_server_stream(&stream, REMOTE_REQUEST_TIMEOUT, REMOTE_RESPONSE_TIMEOUT)?;
        let (mut stream, received) = tokio::task::spawn_blocking(move || {
            let mut stream = stream;
            let result = transport::receive::<RequestEnvelope>(&mut stream);
            (stream, result)
        })
        .await
        .context("remote filesystem receive task failed")?;
        let (request, descriptor) = received?;
        let reply = if descriptor.is_some() {
            crate::nfs::broker::BrokerReply {
                response: Response::Error {
                    errno: libc::EPROTO,
                    message: "remote request unexpectedly included a descriptor".to_string(),
                },
                descriptor: None,
            }
        } else if request.version != PROTOCOL_VERSION {
            crate::nfs::broker::BrokerReply {
                response: Response::Error {
                    errno: libc::EPROTO,
                    message: "unsupported remote filesystem protocol version".to_string(),
                },
                descriptor: None,
            }
        } else if !constant_time_equal(request.token.as_bytes(), state.token.as_bytes()) {
            crate::nfs::broker::BrokerReply {
                response: Response::Error {
                    errno: libc::EACCES,
                    message: "invalid remote filesystem token".to_string(),
                },
                descriptor: None,
            }
        } else {
            state.broker.handle(request.request).await
        };
        let response = ResponseEnvelope {
            version: PROTOCOL_VERSION,
            response: reply.response,
        };
        tokio::task::spawn_blocking(move || {
            transport::send(
                &mut stream,
                &response,
                reply.descriptor.as_ref().map(AsRawFd::as_raw_fd),
            )
        })
        .await
        .context("remote filesystem send task failed")??;
        Ok(())
    }
}

fn configure_server_stream(
    stream: &std::os::unix::net::UnixStream,
    read_timeout: Duration,
    write_timeout: Duration,
) -> std::io::Result<()> {
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(read_timeout))?;
    stream.set_write_timeout(Some(write_timeout))
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    for index in 0..left.len().max(right.len()) {
        let left = left.get(index).copied().unwrap_or(0);
        let right = right.get(index).copied().unwrap_or(0);
        difference |= usize::from(left ^ right);
    }
    difference == 0
}

#[cfg(test)]
mod tests;
