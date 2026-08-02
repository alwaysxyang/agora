use super::protocol::{
    AuditEventRequest, AuditResponse, FileOperation, decode_request, encode_response, frame_length,
};
use crate::callback::{
    Callback, EVENT_SCHEMA_VERSION, Event, EventResult, EventStatus, EventType, FileEvent,
    ProcessEvent, Subsystem,
};
use crate::trace::TraceContext;
use anyhow::{Context, Result};
use chrono::{SecondsFormat, Utc};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;
use uuid::Uuid;

const AUDIT_MAX_CONNECTIONS: usize = 64;
const AUDIT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Clone, Debug)]
pub(crate) struct AuditRuntime {
    token: String,
    control: SocketAddr,
}

impl AuditRuntime {
    pub(crate) fn token(&self) -> &str {
        &self.token
    }

    pub(crate) fn control(&self) -> SocketAddr {
        self.control
    }
}

pub(crate) struct AuditController {
    runtime: AuditRuntime,
    shutdown: watch::Sender<bool>,
    tasks: JoinSet<Result<()>>,
}

impl AuditController {
    pub(crate) async fn start<C>(
        sandbox_id: String,
        run_id: String,
        callback: C,
        callback_timeout: Duration,
    ) -> Result<Self>
    where
        C: Callback,
    {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .context("failed to bind sandbox audit controller")?;
        let control = listener.local_addr()?;
        let token = Uuid::new_v4().simple().to_string();
        let (shutdown, receiver) = watch::channel(false);
        let state = Arc::new(AuditState {
            token: token.clone(),
            sandbox_id,
            run_id,
            callback,
            callback_timeout,
        });
        let mut tasks = JoinSet::new();
        tasks.spawn(AuditServer::new(listener, state).run(receiver));
        Ok(Self {
            runtime: AuditRuntime { token, control },
            shutdown,
            tasks,
        })
    }

    pub(crate) fn runtime(&self) -> &AuditRuntime {
        &self.runtime
    }

    pub(crate) async fn wait_failure(&mut self) -> anyhow::Error {
        match self.tasks.join_next().await {
            Some(Ok(Ok(()))) => anyhow::anyhow!("sandbox audit controller stopped unexpectedly"),
            Some(Ok(Err(error))) => error.context("sandbox audit controller failed"),
            Some(Err(error)) => anyhow::Error::from(error).context("sandbox audit task failed"),
            None => anyhow::anyhow!("sandbox audit controller has no active task"),
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
        if let Some(error) = first_error {
            return Err(error);
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn abort_server_for_test(&mut self) {
        self.tasks.spawn(async {
            anyhow::bail!("injected audit controller failure");
        });
    }
}

impl Drop for AuditController {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
        self.tasks.abort_all();
    }
}

struct AuditState<C>
where
    C: Callback,
{
    token: String,
    sandbox_id: String,
    run_id: String,
    callback: C,
    callback_timeout: Duration,
}

impl<C> AuditState<C>
where
    C: Callback,
{
    async fn publish(&self, request: AuditEventRequest) -> Result<()> {
        let event = match request {
            AuditEventRequest::Process {
                trace_id,
                process,
                command,
            } => Event::Process(ProcessEvent {
                schema_version: EVENT_SCHEMA_VERSION,
                event_id: Uuid::new_v4().to_string(),
                occurred_at: now(),
                subsystem: Subsystem::Process,
                event_type: EventType::ProcessExecAttempt,
                sandbox_id: self.sandbox_id.clone(),
                run_id: self.run_id.clone(),
                trace_id: validate_trace(trace_id)?,
                process,
                command,
                result: started(),
            }),
            AuditEventRequest::File {
                trace_id,
                process,
                operation,
                file,
            } => Event::File(FileEvent {
                schema_version: EVENT_SCHEMA_VERSION,
                event_id: Uuid::new_v4().to_string(),
                occurred_at: now(),
                subsystem: Subsystem::Filesystem,
                event_type: match operation {
                    FileOperation::Open => EventType::FilesystemOpen,
                    FileOperation::Close => EventType::FilesystemClose,
                },
                sandbox_id: self.sandbox_id.clone(),
                run_id: self.run_id.clone(),
                trace_id: validate_trace(trace_id)?,
                process,
                file,
                result: started(),
            }),
        };
        let _ = tokio::time::timeout(self.callback_timeout, self.callback.on_event(event)).await;
        Ok(())
    }
}

struct AuditServer<C>
where
    C: Callback,
{
    listener: TcpListener,
    state: Arc<AuditState<C>>,
    connections: Arc<Semaphore>,
}

impl<C> AuditServer<C>
where
    C: Callback,
{
    fn new(listener: TcpListener, state: Arc<AuditState<C>>) -> Self {
        Self {
            listener,
            state,
            connections: Arc::new(Semaphore::new(AUDIT_MAX_CONNECTIONS)),
        }
    }

    async fn run(self, mut shutdown: watch::Receiver<bool>) -> Result<()> {
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                biased;
                _ = shutdown.changed() => break,
                Some(_) = connections.join_next(), if !connections.is_empty() => {}
                accepted = self.listener.accept() => {
                    let (stream, _) = accepted.context("sandbox audit accept failed")?;
                    let Ok(permit) = Arc::clone(&self.connections).try_acquire_owned() else {
                        drop(stream);
                        continue;
                    };
                    let state = Arc::clone(&self.state);
                    connections.spawn(async move {
                        let _permit = permit;
                        Self::handle(stream, state).await
                    });
                }
            }
        }
        connections.abort_all();
        while connections.join_next().await.is_some() {}
        Ok(())
    }

    async fn handle(mut stream: TcpStream, state: Arc<AuditState<C>>) -> Result<()> {
        let frame = tokio::time::timeout(AUDIT_HANDSHAKE_TIMEOUT, read_frame(&mut stream))
            .await
            .context("sandbox audit handshake timed out")??;
        let request = decode_request(&frame)?;
        let response = if request.token != state.token {
            AuditResponse::Error {
                errno: libc::EACCES,
                message: "invalid audit token".to_string(),
            }
        } else {
            match state.publish(request.event).await {
                Ok(()) => AuditResponse::Accepted,
                Err(error) => AuditResponse::Error {
                    errno: libc::EINVAL,
                    message: format!("{error:#}"),
                },
            }
        };
        stream.write_all(&encode_response(&response)?).await?;
        stream.shutdown().await?;
        Ok(())
    }
}

async fn read_frame(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut prefix = [0_u8; 4];
    stream.read_exact(&mut prefix).await?;
    let mut frame = vec![0_u8; frame_length(prefix)?];
    stream.read_exact(&mut frame).await?;
    Ok(frame)
}

fn validate_trace(trace_id: String) -> Result<String> {
    TraceContext::parse(&trace_id)
        .map(|trace| trace.encode())
        .map_err(|error| anyhow::anyhow!("invalid audit trace id: {error}"))
}

fn now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn started() -> EventResult {
    EventResult {
        status: EventStatus::Started,
        error_code: None,
        error_message: None,
    }
}

#[cfg(test)]
mod tests;
