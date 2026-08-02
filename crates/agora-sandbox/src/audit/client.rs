use super::protocol::{
    AuditEventRequest, AuditResponse, decode_response, encode_request, frame_length,
};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

const AUDIT_CLIENT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug)]
pub(crate) struct AuditClient {
    control: SocketAddr,
    token: String,
}

impl AuditClient {
    pub(crate) fn new(control: SocketAddr, token: impl Into<String>) -> Self {
        Self {
            control,
            token: token.into(),
        }
    }

    pub(crate) fn publish(&self, event: AuditEventRequest) -> Result<(), AuditError> {
        let request = encode_request(&self.token, event).map_err(AuditError::from_io)?;
        let mut stream = TcpStream::connect(self.control).map_err(AuditError::from_io)?;
        stream
            .set_read_timeout(Some(AUDIT_CLIENT_TIMEOUT))
            .map_err(AuditError::from_io)?;
        stream
            .set_write_timeout(Some(AUDIT_CLIENT_TIMEOUT))
            .map_err(AuditError::from_io)?;
        stream.write_all(&request).map_err(AuditError::from_io)?;
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
            AuditResponse::Error { errno, message } => Err(AuditError { errno, message }),
        }
    }
}

#[derive(Debug)]
pub(crate) struct AuditError {
    errno: libc::c_int,
    message: String,
}

impl AuditError {
    pub(crate) fn errno(&self) -> libc::c_int {
        self.errno
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
