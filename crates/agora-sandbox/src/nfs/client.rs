use crate::nfs::protocol::{
    PROTOCOL_VERSION, Request, RequestEnvelope, RequestId, Response, ResponseEnvelope,
};
use crate::nfs::transport;
use std::fmt;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

const REMOTE_CLIENT_TIMEOUT: Duration = Duration::from_secs(30);
const REMOTE_REQUEST_ATTEMPTS: usize = 2;

#[derive(Clone, Debug)]
pub(crate) struct RemoteClient {
    socket: PathBuf,
    token: String,
    timeout: Duration,
}

impl RemoteClient {
    pub(crate) fn new(socket: impl Into<PathBuf>, token: impl Into<String>) -> Self {
        Self::new_with_timeout(socket, token, REMOTE_CLIENT_TIMEOUT)
    }

    fn new_with_timeout(
        socket: impl Into<PathBuf>,
        token: impl Into<String>,
        timeout: Duration,
    ) -> Self {
        Self {
            socket: socket.into(),
            token: token.into(),
            timeout,
        }
    }

    pub(crate) fn request(&self, request: Request) -> Result<RemoteReply, RemoteClientError> {
        let request_id = RequestId::new(uuid::Uuid::new_v4().simple().to_string())
            .expect("UUID is a valid remote request ID");
        let reply = self.request_with_id(request_id.clone(), request)?;
        let resource = match &reply.response {
            Response::Open { handle, .. } => Some((Some(handle.clone()), None)),
            Response::Stat { anchor, .. } | Response::List { anchor, .. } => {
                Some((None, Some(anchor.clone())))
            }
            _ => None,
        };
        if let Some((handle, anchor)) = resource
            && let Err(error) = self.request_with_id(
                RequestId::new(uuid::Uuid::new_v4().simple().to_string())
                    .expect("UUID is a valid remote request ID"),
                Request::Claim { request_id },
            )
        {
            if let Some(handle) = handle {
                let _ = self.request(Request::Abort { handle });
            }
            if let Some(anchor) = anchor {
                remove_anchor(self.socket.parent(), &anchor);
            }
            return Err(error);
        }
        Ok(reply)
    }

    fn request_with_id(
        &self,
        request_id: RequestId,
        request: Request,
    ) -> Result<RemoteReply, RemoteClientError> {
        let mut last_error = None;
        for _ in 0..REMOTE_REQUEST_ATTEMPTS {
            match self.request_once(request_id.clone(), request.clone()) {
                Ok(reply) => return Ok(reply),
                Err(error) if error.retryable => last_error = Some(error),
                Err(error) => return Err(error),
            }
        }
        Err(last_error.expect("remote request attempts is non-zero"))
    }

    fn request_once(
        &self,
        request_id: RequestId,
        request: Request,
    ) -> Result<RemoteReply, RemoteClientError> {
        let mut stream = UnixStream::connect(&self.socket).map_err(|error| {
            RemoteClientError::io("failed to connect to remote broker", error, true)
        })?;
        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(|error| {
                RemoteClientError::io("failed to configure remote broker", error, false)
            })?;
        stream
            .set_write_timeout(Some(self.timeout))
            .map_err(|error| {
                RemoteClientError::io("failed to configure remote broker", error, false)
            })?;
        let request = RequestEnvelope {
            version: PROTOCOL_VERSION,
            token: self.token.clone(),
            request_id: request_id.clone(),
            request,
        };
        transport::send(&mut stream, &request, None)
            .map_err(|error| RemoteClientError::io("failed to send remote request", error, true))?;
        let (response, descriptor) =
            transport::receive::<ResponseEnvelope>(&mut stream).map_err(|error| {
                RemoteClientError::io("failed to receive remote response", error, true)
            })?;
        if response.version != PROTOCOL_VERSION {
            return Err(RemoteClientError::new(
                libc::EPROTO,
                "unsupported remote broker protocol version",
            ));
        }
        if response.request_id != request_id {
            return Err(RemoteClientError::new(
                libc::EPROTO,
                "remote broker response request ID did not match",
            ));
        }
        response_result(response.response, descriptor)
    }
}

fn remove_anchor(runtime: Option<&std::path::Path>, anchor: &str) {
    let Some(runtime) = runtime else {
        return;
    };
    let path = runtime.join(anchor);
    let _ = std::fs::remove_file(&path).or_else(|_| std::fs::remove_dir(&path));
}

#[derive(Debug)]
pub(crate) struct RemoteReply {
    pub(crate) response: Response,
    pub(crate) descriptor: Option<OwnedFd>,
}

#[derive(Debug)]
pub(crate) struct RemoteClientError {
    errno: libc::c_int,
    message: String,
    retryable: bool,
}

impl RemoteClientError {
    fn new(errno: libc::c_int, message: impl Into<String>) -> Self {
        Self {
            errno,
            message: message.into(),
            retryable: false,
        }
    }

    fn io(context: &str, error: std::io::Error, retryable: bool) -> Self {
        let errno = match error.kind() {
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => libc::ETIMEDOUT,
            _ => error.raw_os_error().unwrap_or(libc::EIO),
        };
        Self {
            errno,
            message: format!("{context}: {error}"),
            retryable,
        }
    }

    pub(crate) fn errno(&self) -> libc::c_int {
        self.errno
    }
}

impl fmt::Display for RemoteClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for RemoteClientError {}

fn response_result(
    response: Response,
    descriptor: Option<OwnedFd>,
) -> Result<RemoteReply, RemoteClientError> {
    if let Response::Error { errno, message } = response {
        return Err(RemoteClientError::new(errno, message));
    }
    let expects_descriptor = matches!(response, Response::Open { .. });
    if expects_descriptor != descriptor.is_some() {
        return Err(RemoteClientError::new(
            libc::EPROTO,
            "remote broker descriptor response did not match operation",
        ));
    }
    Ok(RemoteReply {
        response,
        descriptor,
    })
}

#[cfg(test)]
mod tests;
