use super::protocol::{
    PrepareResponse, decode_prepare_request, encode_prepare_response, frame_length,
};
use super::store::ExecutableStore;
use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinSet;
use uuid::Uuid;

#[derive(Clone, Debug)]
pub(crate) struct ExecutionRuntime {
    token: String,
    control: SocketAddr,
}

impl ExecutionRuntime {
    pub(crate) fn token(&self) -> &str {
        &self.token
    }

    pub(crate) fn control(&self) -> SocketAddr {
        self.control
    }
}

pub(crate) struct ExecutionController {
    runtime: ExecutionRuntime,
    store: Arc<Mutex<ExecutableStore>>,
    directory: PathBuf,
    shutdown: watch::Sender<bool>,
    tasks: JoinSet<Result<()>>,
}

impl ExecutionController {
    pub(crate) async fn start(run_id: &str) -> Result<Self> {
        let directory = std::env::temp_dir().join(format!("agora-sandbox-{run_id}"));
        let store = Arc::new(Mutex::new(ExecutableStore::new(directory.clone())?));
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .context("failed to bind sandbox execution controller")?;
        let control = listener.local_addr()?;
        let token = Uuid::new_v4().simple().to_string();
        let (shutdown, receiver) = watch::channel(false);
        let state = Arc::new(ExecutionState {
            token: token.clone(),
            store: Arc::clone(&store),
        });
        let mut tasks = JoinSet::new();
        tasks.spawn(ExecutionServer::new(listener, state).run(receiver));
        Ok(Self {
            runtime: ExecutionRuntime { token, control },
            store,
            directory,
            shutdown,
            tasks,
        })
    }

    pub(crate) fn runtime(&self) -> &ExecutionRuntime {
        &self.runtime
    }

    pub(crate) async fn prepare(&self, executable: PathBuf) -> Result<PathBuf> {
        let store = Arc::clone(&self.store);
        tokio::task::spawn_blocking(move || lock(&store).prepare(&executable))
            .await
            .context("sandbox executable preparation task failed")?
    }

    pub(crate) async fn wait_failure(&mut self) -> anyhow::Error {
        match self.tasks.join_next().await {
            Some(Ok(Ok(()))) => {
                anyhow::anyhow!("sandbox execution controller stopped unexpectedly")
            }
            Some(Ok(Err(error))) => error.context("sandbox execution controller failed"),
            Some(Err(error)) => anyhow::Error::from(error).context("sandbox execution task failed"),
            None => anyhow::anyhow!("sandbox execution controller has no active task"),
        }
    }

    pub(crate) async fn shutdown(mut self) -> Result<()> {
        let _ = self.shutdown.send(true);
        let mut first_error = None;
        while let Some(task) = self.tasks.join_next().await {
            match task {
                Ok(Ok(())) => {}
                Ok(Err(error)) if first_error.is_none() => first_error = Some(error),
                Err(error) if first_error.is_none() => first_error = Some(error.into()),
                _ => {}
            }
        }
        let cleanup = lock(&self.store).cleanup();
        if let Some(error) = first_error {
            return Err(error);
        }
        cleanup
    }

    #[cfg(test)]
    pub(crate) fn abort_server_for_test(&mut self) {
        self.tasks.spawn(async {
            anyhow::bail!("injected execution controller failure");
        });
    }
}

impl Drop for ExecutionController {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
        self.tasks.abort_all();
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

struct ExecutionState {
    token: String,
    store: Arc<Mutex<ExecutableStore>>,
}

struct ExecutionServer {
    listener: TcpListener,
    state: Arc<ExecutionState>,
}

impl ExecutionServer {
    fn new(listener: TcpListener, state: Arc<ExecutionState>) -> Self {
        Self { listener, state }
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
                accepted = self.listener.accept() => {
                    let (stream, _) = accepted.context("sandbox execution accept failed")?;
                    let state = Arc::clone(&self.state);
                    connections.spawn(async move { Self::handle(stream, state).await });
                }
                completed = connections.join_next(), if !connections.is_empty() => {
                    match completed {
                        Some(Ok(Ok(()))) => {}
                        Some(Ok(Err(error))) => return Err(error),
                        Some(Err(error)) => return Err(error.into()),
                        None => {}
                    }
                }
            }
        }
        connections.abort_all();
        while connections.join_next().await.is_some() {}
        Ok(())
    }

    async fn handle(mut stream: TcpStream, state: Arc<ExecutionState>) -> Result<()> {
        let frame = Self::read_frame(&mut stream).await?;
        let request = decode_prepare_request(&frame)?;
        let response = if request.token != state.token {
            PrepareResponse::Error("invalid execution token".to_string())
        } else {
            let store = Arc::clone(&state.store);
            let executable = request.executable;
            match tokio::task::spawn_blocking(move || lock(&store).prepare(&executable)).await {
                Ok(Ok(path)) => PrepareResponse::Ready(path),
                Ok(Err(error)) => PrepareResponse::Error(format!("{error:#}")),
                Err(error) => PrepareResponse::Error(format!(
                    "sandbox executable preparation task failed: {error}"
                )),
            }
        };
        stream
            .write_all(&encode_prepare_response(&response)?)
            .await?;
        stream.shutdown().await?;
        Ok(())
    }

    async fn read_frame(stream: &mut TcpStream) -> Result<Vec<u8>> {
        let mut prefix = [0_u8; 4];
        stream.read_exact(&mut prefix).await?;
        let mut frame = vec![0_u8; frame_length(prefix)?];
        stream.read_exact(&mut frame).await?;
        Ok(frame)
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}
