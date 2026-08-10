use super::protocol::{
    BackingPath, ByteRange, PROTOCOL_VERSION, Request, RequestEnvelope, Response, ResponseEnvelope,
};
use crate::ipc;
#[cfg(target_os = "macos")]
use crate::ipc::InheritedControlStream;
use std::fmt;
use std::os::fd::RawFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
#[cfg(target_os = "macos")]
use std::sync::Arc;
use std::time::Duration;

const CLIENT_TIMEOUT: Duration = Duration::from_secs(30);
const IDEMPOTENT_ATTEMPTS: usize = 2;

#[derive(Clone, Debug)]
pub(crate) struct LocalClient {
    socket: PathBuf,
    token: String,
    #[cfg(target_os = "macos")]
    shared: Option<Arc<InheritedControlStream<UnixStream>>>,
}

pub(crate) struct LocalOpen {
    pub(crate) handle: String,
}

pub(crate) struct LocalWrite {
    id: String,
}

#[derive(Debug)]
pub(crate) struct LocalClientError {
    errno: libc::c_int,
    message: String,
    retryable: bool,
}

impl LocalClient {
    pub(crate) fn new(socket: impl Into<PathBuf>, token: impl Into<String>) -> Self {
        Self {
            socket: socket.into(),
            token: token.into(),
            #[cfg(target_os = "macos")]
            shared: None,
        }
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn with_shared(
        socket: impl Into<PathBuf>,
        token: impl Into<String>,
        shared: Arc<InheritedControlStream<UnixStream>>,
    ) -> Self {
        let mut client = Self::new(socket, token);
        client.shared = Some(shared);
        client
    }

    #[cfg(all(target_os = "macos", any(agora_sandbox_hook_build, test, coverage)))]
    pub(crate) fn ping_shared(&self) -> Result<(), LocalClientError> {
        let request_id = uuid::Uuid::new_v4().simple().to_string();
        match self.request_shared(request_id, Request::Ping, None)? {
            Response::Success => Ok(()),
            _ => Err(LocalClientError::protocol(
                "local filesystem ping returned an unexpected response",
            )),
        }
    }

    pub(crate) fn open(
        &self,
        path: &Path,
        descriptor: RawFd,
        writable: bool,
    ) -> Result<LocalOpen, LocalClientError> {
        let request_id = uuid::Uuid::new_v4().simple().to_string();
        let response = self.request_with_id(
            request_id.clone(),
            Request::Open {
                path: BackingPath::from_path(path),
                writable,
            },
            Some(descriptor),
            IDEMPOTENT_ATTEMPTS,
        )?;
        let Response::Open { handle } = response else {
            return Err(LocalClientError::protocol(
                "local filesystem open returned an unexpected response",
            ));
        };
        if let Err(error) = self.success(Request::Claim { request_id }, IDEMPOTENT_ATTEMPTS) {
            let _ = self.success(
                Request::Abort {
                    handle: handle.clone(),
                },
                IDEMPOTENT_ATTEMPTS,
            );
            return Err(error);
        }
        Ok(LocalOpen { handle })
    }

    pub(crate) fn sync(
        &self,
        handle: &str,
        ranges: Vec<ByteRange>,
        durable: bool,
    ) -> Result<(), LocalClientError> {
        self.success(
            Request::Sync {
                handle: handle.to_string(),
                ranges,
                durable,
            },
            IDEMPOTENT_ATTEMPTS,
        )
    }

    pub(crate) fn potentially_dirty(
        &self,
        handle: &str,
        range: ByteRange,
    ) -> Result<(), LocalClientError> {
        self.success(
            Request::PotentiallyDirty {
                handle: handle.to_string(),
                range,
            },
            IDEMPOTENT_ATTEMPTS,
        )
    }

    pub(crate) fn begin_write(
        &self,
        handle: &str,
        range: ByteRange,
    ) -> Result<LocalWrite, LocalClientError> {
        let write_id = uuid::Uuid::new_v4().simple().to_string();
        self.success(
            Request::BeginWrite {
                handle: handle.to_string(),
                write_id: write_id.clone(),
                range,
            },
            IDEMPOTENT_ATTEMPTS,
        )?;
        Ok(LocalWrite { id: write_id })
    }

    pub(crate) fn finish_write(
        &self,
        handle: &str,
        write: &LocalWrite,
        range: ByteRange,
    ) -> Result<(), LocalClientError> {
        self.success(
            Request::FinishWrite {
                handle: handle.to_string(),
                write_id: write.id.clone(),
                range,
            },
            IDEMPOTENT_ATTEMPTS,
        )
    }

    pub(crate) fn cancel_write(
        &self,
        handle: &str,
        write: &LocalWrite,
    ) -> Result<(), LocalClientError> {
        self.success(
            Request::CancelWrite {
                handle: handle.to_string(),
                write_id: write.id.clone(),
            },
            IDEMPOTENT_ATTEMPTS,
        )
    }

    pub(crate) fn close(
        &self,
        handle: &str,
        ranges: Vec<ByteRange>,
    ) -> Result<(), LocalClientError> {
        self.success(
            Request::Close {
                handle: handle.to_string(),
                ranges,
            },
            IDEMPOTENT_ATTEMPTS,
        )
    }

    pub(crate) fn retain(&self, handles: Vec<String>) -> Result<(), LocalClientError> {
        if handles.is_empty() {
            return Ok(());
        }
        self.success(Request::Retain { handles }, IDEMPOTENT_ATTEMPTS)
    }

    pub(crate) fn release_retained(&self, handles: Vec<String>) -> Result<(), LocalClientError> {
        if handles.is_empty() {
            return Ok(());
        }
        self.success(Request::ReleaseRetain { handles }, IDEMPOTENT_ATTEMPTS)
    }

    fn success(&self, request: Request, attempts: usize) -> Result<(), LocalClientError> {
        match self.request(request, None, attempts)? {
            Response::Success => Ok(()),
            _ => Err(LocalClientError::protocol(
                "local filesystem broker returned an unexpected response",
            )),
        }
    }

    fn request(
        &self,
        request: Request,
        descriptor: Option<RawFd>,
        attempts: usize,
    ) -> Result<Response, LocalClientError> {
        let request_id = uuid::Uuid::new_v4().simple().to_string();
        self.request_with_id(request_id, request, descriptor, attempts)
    }

    fn request_with_id(
        &self,
        request_id: String,
        request: Request,
        descriptor: Option<RawFd>,
        attempts: usize,
    ) -> Result<Response, LocalClientError> {
        let mut last = None;
        for _ in 0..attempts {
            match self.request_once(request_id.clone(), request.clone(), descriptor) {
                Ok(response) => return Ok(response),
                Err(error) if error.retryable => last = Some(error),
                Err(error) => return Err(error),
            }
        }
        Err(last.expect("local request attempts is non-zero"))
    }

    fn request_once(
        &self,
        request_id: String,
        request: Request,
        descriptor: Option<RawFd>,
    ) -> Result<Response, LocalClientError> {
        let mut stream = match UnixStream::connect(&self.socket) {
            Ok(stream) => stream,
            Err(error) => {
                #[cfg(target_os = "macos")]
                if self.shared.is_some() {
                    return self.request_shared(request_id, request, descriptor);
                }
                return Err(LocalClientError::io(
                    "failed to connect to local filesystem broker",
                    error,
                    true,
                ));
            }
        };
        stream
            .set_read_timeout(Some(CLIENT_TIMEOUT))
            .and_then(|()| stream.set_write_timeout(Some(CLIENT_TIMEOUT)))
            .map_err(|error| {
                LocalClientError::io("failed to configure local filesystem broker", error, false)
            })?;
        Self::exchange(&mut stream, &self.token, request_id, request, descriptor)
    }

    #[cfg(target_os = "macos")]
    fn request_shared(
        &self,
        request_id: String,
        request: Request,
        descriptor: Option<RawFd>,
    ) -> Result<Response, LocalClientError> {
        let shared = self.shared.as_ref().ok_or_else(|| {
            LocalClientError::protocol("shared local filesystem control stream is unavailable")
        })?;
        shared
            .transact(|stream| Self::exchange(stream, &self.token, request_id, request, descriptor))
            .map_err(|error| {
                LocalClientError::io(
                    "failed to serialize inherited local filesystem request",
                    error,
                    true,
                )
            })?
    }

    fn exchange(
        stream: &mut UnixStream,
        token: &str,
        request_id: String,
        request: Request,
        descriptor: Option<RawFd>,
    ) -> Result<Response, LocalClientError> {
        ipc::send(
            stream,
            &RequestEnvelope {
                version: PROTOCOL_VERSION,
                token: token.to_string(),
                request_id: request_id.clone(),
                request,
            },
            descriptor,
        )
        .map_err(|error| {
            LocalClientError::io("failed to send local filesystem request", error, true)
        })?;
        let (response, descriptor) = ipc::receive::<ResponseEnvelope>(stream).map_err(|error| {
            LocalClientError::io("failed to receive local filesystem response", error, true)
        })?;
        if descriptor.is_some() {
            return Err(LocalClientError::protocol(
                "local filesystem response unexpectedly included a descriptor",
            ));
        }
        if response.version != PROTOCOL_VERSION || response.request_id != request_id {
            return Err(LocalClientError::protocol(
                "local filesystem response did not match the request",
            ));
        }
        match response.response {
            Response::Error { errno, message } => Err(LocalClientError {
                errno,
                message,
                retryable: false,
            }),
            response => Ok(response),
        }
    }
}

impl LocalClientError {
    fn protocol(message: impl Into<String>) -> Self {
        Self {
            errno: libc::EPROTO,
            message: message.into(),
            retryable: false,
        }
    }

    fn io(context: &str, error: std::io::Error, retryable: bool) -> Self {
        Self {
            errno: error.raw_os_error().unwrap_or(libc::EIO),
            message: format!("{context}: {error}"),
            retryable,
        }
    }

    pub(crate) fn errno(&self) -> libc::c_int {
        self.errno
    }
}

impl fmt::Display for LocalClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for LocalClientError {}

#[cfg(test)]
#[path = "client/tests.rs"]
mod tests;
