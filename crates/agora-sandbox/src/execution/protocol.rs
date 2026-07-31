use std::ffi::OsString;
use std::io;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

pub(super) const EXECUTION_PROTOCOL_VERSION: u16 = 2;
pub(super) const MAX_EXECUTION_FRAME_SIZE: usize = 64 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct PrepareRequest {
    pub(crate) token: String,
    pub(crate) executable: PathBuf,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PrepareResponse {
    Ready(PathBuf),
    Error { errno: i32, message: String },
}

pub(crate) fn encode_prepare_request(token: &str, executable: &Path) -> io::Result<Vec<u8>> {
    if token.is_empty() || token.len() > u16::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid execution token length",
        ));
    }
    let executable = executable.as_os_str().as_bytes();
    let executable_length = u32::try_from(executable.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "executable path is too long"))?;
    let mut body = Vec::with_capacity(8 + token.len() + executable.len());
    body.extend_from_slice(&EXECUTION_PROTOCOL_VERSION.to_be_bytes());
    body.extend_from_slice(&(token.len() as u16).to_be_bytes());
    body.extend_from_slice(&executable_length.to_be_bytes());
    body.extend_from_slice(token.as_bytes());
    body.extend_from_slice(executable);
    encode_frame(body)
}

pub(super) fn decode_prepare_request(frame: &[u8]) -> io::Result<PrepareRequest> {
    if frame.len() < 8 {
        return Err(invalid_data("execution request is truncated"));
    }
    let version = u16::from_be_bytes([frame[0], frame[1]]);
    if version != EXECUTION_PROTOCOL_VERSION {
        return Err(invalid_data("unsupported execution protocol version"));
    }
    let token_length = u16::from_be_bytes([frame[2], frame[3]]) as usize;
    let path_length = u32::from_be_bytes([frame[4], frame[5], frame[6], frame[7]]) as usize;
    let expected = 8_usize
        .checked_add(token_length)
        .and_then(|length| length.checked_add(path_length))
        .ok_or_else(|| invalid_data("execution request length overflow"))?;
    if expected != frame.len() || token_length == 0 || path_length == 0 {
        return Err(invalid_data("invalid execution request lengths"));
    }
    let token_end = 8 + token_length;
    let token = std::str::from_utf8(&frame[8..token_end])
        .map_err(|_| invalid_data("execution token is not UTF-8"))?
        .to_string();
    let executable = PathBuf::from(OsString::from_vec(frame[token_end..].to_vec()));
    Ok(PrepareRequest { token, executable })
}

pub(super) fn encode_prepare_response(response: &PrepareResponse) -> io::Result<Vec<u8>> {
    let (status, content) = match response {
        PrepareResponse::Ready(path) => (0_u8, path.as_os_str().as_bytes().to_vec()),
        PrepareResponse::Error { errno, message } => {
            if *errno <= 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid execution response errno",
                ));
            }
            let mut content = Vec::with_capacity(4 + message.len());
            content.extend_from_slice(&errno.to_be_bytes());
            content.extend_from_slice(message.as_bytes());
            (1_u8, content)
        }
    };
    let content_length = u32::try_from(content.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "response is too large"))?;
    let mut body = Vec::with_capacity(7 + content.len());
    body.extend_from_slice(&EXECUTION_PROTOCOL_VERSION.to_be_bytes());
    body.push(status);
    body.extend_from_slice(&content_length.to_be_bytes());
    body.extend_from_slice(&content);
    encode_frame(body)
}

pub(crate) fn decode_prepare_response(frame: &[u8]) -> io::Result<PrepareResponse> {
    if frame.len() < 7 {
        return Err(invalid_data("execution response is truncated"));
    }
    let version = u16::from_be_bytes([frame[0], frame[1]]);
    if version != EXECUTION_PROTOCOL_VERSION {
        return Err(invalid_data("unsupported execution protocol version"));
    }
    let content_length = u32::from_be_bytes([frame[3], frame[4], frame[5], frame[6]]) as usize;
    if 7_usize.checked_add(content_length) != Some(frame.len()) {
        return Err(invalid_data("invalid execution response length"));
    }
    match frame[2] {
        0 => Ok(PrepareResponse::Ready(PathBuf::from(OsString::from_vec(
            frame[7..].to_vec(),
        )))),
        1 if content_length >= 4 => {
            let errno = i32::from_be_bytes(frame[7..11].try_into().unwrap());
            if errno <= 0 {
                return Err(invalid_data("invalid execution response errno"));
            }
            Ok(PrepareResponse::Error {
                errno,
                message: std::str::from_utf8(&frame[11..])
                    .map_err(|_| invalid_data("execution error is not UTF-8"))?
                    .to_string(),
            })
        }
        1 => Err(invalid_data("execution error is truncated")),
        _ => Err(invalid_data("invalid execution response status")),
    }
}

pub(crate) fn frame_length(prefix: [u8; 4]) -> io::Result<usize> {
    let length = u32::from_be_bytes(prefix) as usize;
    if length == 0 || length > MAX_EXECUTION_FRAME_SIZE {
        return Err(invalid_data("invalid execution frame length"));
    }
    Ok(length)
}

fn encode_frame(body: Vec<u8>) -> io::Result<Vec<u8>> {
    if body.is_empty() || body.len() > MAX_EXECUTION_FRAME_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid execution frame length",
        ));
    }
    let mut frame = Vec::with_capacity(4 + body.len());
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
