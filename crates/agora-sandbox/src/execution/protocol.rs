pub(crate) use crate::callback::ProcessOperation;
use serde::{Deserialize, Serialize};
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
    pub(crate) command: Option<CommandRequest>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CommandRequest {
    pub(crate) trace_ids: Vec<String>,
    pub(crate) pid: u32,
    pub(crate) ppid: u32,
    pub(crate) process_executable: String,
    pub(crate) executable: String,
    pub(crate) arguments: Vec<String>,
    pub(crate) current_dir: String,
    pub(crate) operation: ProcessOperation,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PrepareResponse {
    Ready(PathBuf),
    Error { errno: i32, message: String },
}

pub(crate) fn encode_prepare_request(token: &str, executable: &Path) -> io::Result<Vec<u8>> {
    encode_request(token, executable, None)
}

pub(crate) fn encode_prepare_request_with_command(
    token: &str,
    executable: &Path,
    command: &CommandRequest,
) -> io::Result<Vec<u8>> {
    encode_request(token, executable, Some(command))
}

fn encode_request(
    token: &str,
    executable: &Path,
    command: Option<&CommandRequest>,
) -> io::Result<Vec<u8>> {
    if token.is_empty() || token.len() > u16::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid execution token length",
        ));
    }
    let executable = executable.as_os_str().as_bytes();
    let executable_length = u32::try_from(executable.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "executable path is too long"))?;
    let command = command
        .map(serde_json::to_vec)
        .transpose()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?
        .unwrap_or_default();
    let command_length = u32::try_from(command.len()).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, "command metadata is too large")
    })?;
    let mut body = Vec::with_capacity(12 + token.len() + executable.len() + command.len());
    body.extend_from_slice(&EXECUTION_PROTOCOL_VERSION.to_be_bytes());
    body.extend_from_slice(&(token.len() as u16).to_be_bytes());
    body.extend_from_slice(&executable_length.to_be_bytes());
    body.extend_from_slice(&command_length.to_be_bytes());
    body.extend_from_slice(token.as_bytes());
    body.extend_from_slice(executable);
    body.extend_from_slice(&command);
    encode_frame(body)
}

pub(crate) fn decode_prepare_request(frame: &[u8]) -> io::Result<PrepareRequest> {
    if frame.len() < 12 {
        return Err(invalid_data("execution request is truncated"));
    }
    let version = u16::from_be_bytes([frame[0], frame[1]]);
    if version != EXECUTION_PROTOCOL_VERSION {
        return Err(invalid_data("unsupported execution protocol version"));
    }
    let token_length = u16::from_be_bytes([frame[2], frame[3]]) as usize;
    let path_length = u32::from_be_bytes([frame[4], frame[5], frame[6], frame[7]]) as usize;
    let command_length = u32::from_be_bytes([frame[8], frame[9], frame[10], frame[11]]) as usize;
    let expected = 12_usize
        .checked_add(token_length)
        .and_then(|length| length.checked_add(path_length))
        .and_then(|length| length.checked_add(command_length))
        .ok_or_else(|| invalid_data("execution request length overflow"))?;
    if expected != frame.len() || token_length == 0 || path_length == 0 {
        return Err(invalid_data("invalid execution request lengths"));
    }
    let token_end = 12 + token_length;
    let path_end = token_end + path_length;
    let token = std::str::from_utf8(&frame[12..token_end])
        .map_err(|_| invalid_data("execution token is not UTF-8"))?
        .to_string();
    let executable = PathBuf::from(OsString::from_vec(frame[token_end..path_end].to_vec()));
    let command = if command_length == 0 {
        None
    } else {
        Some(
            serde_json::from_slice(&frame[path_end..])
                .map_err(|_| invalid_data("invalid command metadata"))?,
        )
    };
    Ok(PrepareRequest {
        token,
        executable,
        command,
    })
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
