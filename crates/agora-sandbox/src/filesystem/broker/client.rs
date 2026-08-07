use super::protocol::{
    BackingPath, ByteRange, PROTOCOL_VERSION, Request, RequestEnvelope, Response, ResponseEnvelope,
};
use crate::ipc;
use std::fmt;
use std::os::fd::RawFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

const CLIENT_TIMEOUT: Duration = Duration::from_secs(30);
const IDEMPOTENT_ATTEMPTS: usize = 2;

#[derive(Clone, Debug)]
pub(crate) struct LocalClient {
    socket: PathBuf,
    token: String,
}

pub(crate) struct LocalOpen {
    pub(crate) handle: String,
}

#[derive(Debug)]
pub(crate) struct LocalClientError {
    errno: libc::c_int,
    message: String,
}

impl LocalClient {
    pub(crate) fn new(socket: impl Into<PathBuf>, token: impl Into<String>) -> Self {
        Self {
            socket: socket.into(),
            token: token.into(),
        }
    }

    pub(crate) fn open(
        &self,
        path: &Path,
        descriptor: RawFd,
        writable: bool,
    ) -> Result<LocalOpen, LocalClientError> {
        match self.request(
            Request::Open {
                path: BackingPath::from_path(path),
                writable,
            },
            Some(descriptor),
            1,
        )? {
            Response::Open { handle } => Ok(LocalOpen { handle }),
            _ => Err(LocalClientError::protocol(
                "local filesystem open returned an unexpected response",
            )),
        }
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

    pub(crate) fn close(&self, handle: &str) -> Result<(), LocalClientError> {
        self.success(
            Request::Close {
                handle: handle.to_string(),
            },
            1,
        )
    }

    pub(crate) fn retain(&self, handles: Vec<String>) -> Result<(), LocalClientError> {
        if handles.is_empty() {
            return Ok(());
        }
        self.success(Request::Retain { handles }, 1)
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
        let mut last = None;
        for _ in 0..attempts {
            match self.request_once(request_id.clone(), request.clone(), descriptor) {
                Ok(response) => return Ok(response),
                Err(error) => last = Some(error),
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
        let mut stream = UnixStream::connect(&self.socket).map_err(|error| {
            LocalClientError::io("failed to connect to local filesystem broker", error)
        })?;
        stream
            .set_read_timeout(Some(CLIENT_TIMEOUT))
            .and_then(|()| stream.set_write_timeout(Some(CLIENT_TIMEOUT)))
            .map_err(|error| {
                LocalClientError::io("failed to configure local filesystem broker", error)
            })?;
        ipc::send(
            &mut stream,
            &RequestEnvelope {
                version: PROTOCOL_VERSION,
                token: self.token.clone(),
                request_id: request_id.clone(),
                request,
            },
            descriptor,
        )
        .map_err(|error| LocalClientError::io("failed to send local filesystem request", error))?;
        let (response, descriptor) =
            ipc::receive::<ResponseEnvelope>(&mut stream).map_err(|error| {
                LocalClientError::io("failed to receive local filesystem response", error)
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
            Response::Error { errno, message } => Err(LocalClientError { errno, message }),
            response => Ok(response),
        }
    }
}

impl LocalClientError {
    fn protocol(message: impl Into<String>) -> Self {
        Self {
            errno: libc::EPROTO,
            message: message.into(),
        }
    }

    fn io(context: &str, error: std::io::Error) -> Self {
        Self {
            errno: error.raw_os_error().unwrap_or(libc::EIO),
            message: format!("{context}: {error}"),
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
