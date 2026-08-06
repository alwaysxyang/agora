use crate::nfs::protocol::{
    PROTOCOL_VERSION, Request, RequestEnvelope, Response, ResponseEnvelope,
};
use crate::nfs::transport;
use std::fmt;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

const REMOTE_CLIENT_TIMEOUT: Duration = Duration::from_secs(30);

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
        let mut stream = UnixStream::connect(&self.socket)
            .map_err(|error| RemoteClientError::io("failed to connect to remote broker", error))?;
        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(|error| RemoteClientError::io("failed to configure remote broker", error))?;
        stream
            .set_write_timeout(Some(self.timeout))
            .map_err(|error| RemoteClientError::io("failed to configure remote broker", error))?;
        let request = RequestEnvelope {
            version: PROTOCOL_VERSION,
            token: self.token.clone(),
            request,
        };
        transport::send(&mut stream, &request, None)
            .map_err(|error| RemoteClientError::io("failed to send remote request", error))?;
        let (response, descriptor) = transport::receive::<ResponseEnvelope>(&mut stream)
            .map_err(|error| RemoteClientError::io("failed to receive remote response", error))?;
        if response.version != PROTOCOL_VERSION {
            return Err(RemoteClientError::new(
                libc::EPROTO,
                "unsupported remote broker protocol version",
            ));
        }
        response_result(response.response, descriptor)
    }
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
}

impl RemoteClientError {
    fn new(errno: libc::c_int, message: impl Into<String>) -> Self {
        Self {
            errno,
            message: message.into(),
        }
    }

    fn io(context: &str, error: std::io::Error) -> Self {
        let errno = match error.kind() {
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => libc::ETIMEDOUT,
            _ => error.raw_os_error().unwrap_or(libc::EIO),
        };
        Self::new(errno, format!("{context}: {error}"))
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
