use super::protocol::{
    AuditEventRequest, AuditResponse, decode_response, encode_request, frame_length,
};
use std::cell::RefCell;
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

const AUDIT_CLIENT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct AuditEndpoint {
    control: SocketAddr,
    token: String,
}

struct AuditConnection {
    pid: u32,
    stream: TcpStream,
}

thread_local! {
    static CONNECTIONS: RefCell<HashMap<AuditEndpoint, AuditConnection>> =
        RefCell::new(HashMap::new());
}

#[derive(Clone, Debug)]
pub(crate) struct AuditClient {
    endpoint: AuditEndpoint,
}

impl AuditClient {
    pub(crate) fn new(control: SocketAddr, token: impl Into<String>) -> Self {
        Self {
            endpoint: AuditEndpoint {
                control,
                token: token.into(),
            },
        }
    }

    pub(crate) fn publish(&self, event: AuditEventRequest) -> Result<(), AuditError> {
        let request = encode_request(&self.endpoint.token, event).map_err(AuditError::from_io)?;
        CONNECTIONS
            .try_with(|connections| {
                let mut connections = connections.borrow_mut();
                let pid = std::process::id();
                if connections
                    .get(&self.endpoint)
                    .is_some_and(|connection| connection.pid != pid)
                {
                    connections.remove(&self.endpoint);
                }
                if !connections.contains_key(&self.endpoint) {
                    connections.insert(
                        self.endpoint.clone(),
                        AuditConnection {
                            pid,
                            stream: Self::connect(self.endpoint.control)?,
                        },
                    );
                }
                let result = Self::publish_on(
                    &mut connections
                        .get_mut(&self.endpoint)
                        .expect("audit connection was inserted")
                        .stream,
                    &request,
                );
                if result.as_ref().is_err_and(AuditError::disconnects) {
                    connections.remove(&self.endpoint);
                }
                result
            })
            .unwrap_or_else(|_| {
                let mut stream = Self::connect(self.endpoint.control)?;
                Self::publish_on(&mut stream, &request)
            })
    }

    fn connect(control: SocketAddr) -> Result<TcpStream, AuditError> {
        let stream = TcpStream::connect(control).map_err(AuditError::from_io)?;
        stream
            .set_read_timeout(Some(AUDIT_CLIENT_TIMEOUT))
            .map_err(AuditError::from_io)?;
        stream
            .set_write_timeout(Some(AUDIT_CLIENT_TIMEOUT))
            .map_err(AuditError::from_io)?;
        Ok(stream)
    }

    fn publish_on(stream: &mut TcpStream, request: &[u8]) -> Result<(), AuditError> {
        stream.write_all(request).map_err(AuditError::from_io)?;
        let mut prefix = [0_u8; 4];
        stream
            .read_exact(&mut prefix)
            .map_err(AuditError::from_io)?;
        let mut response = vec![0_u8; frame_length(prefix).map_err(AuditError::from_io)?];
        stream
            .read_exact(&mut response)
            .map_err(AuditError::from_io)?;
        match decode_response(&response).map_err(AuditError::from_io)? {
            AuditResponse::Accepted => Ok(()),
            AuditResponse::Error { errno, message } => Err(AuditError {
                errno,
                message,
                disconnect: false,
            }),
        }
    }
}

#[derive(Debug)]
pub(crate) struct AuditError {
    errno: libc::c_int,
    message: String,
    disconnect: bool,
}

impl AuditError {
    pub(crate) fn errno(&self) -> libc::c_int {
        self.errno
    }

    fn disconnects(&self) -> bool {
        self.disconnect
    }

    fn from_io(error: io::Error) -> Self {
        Self {
            errno: error.raw_os_error().unwrap_or(match error.kind() {
                io::ErrorKind::PermissionDenied => libc::EACCES,
                io::ErrorKind::InvalidInput | io::ErrorKind::InvalidData => libc::EINVAL,
                io::ErrorKind::TimedOut => libc::ETIMEDOUT,
                _ => libc::EIO,
            }),
            message: error.to_string(),
            disconnect: true,
        }
    }
}

impl std::fmt::Display for AuditError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for AuditError {}

#[cfg(test)]
mod tests;
