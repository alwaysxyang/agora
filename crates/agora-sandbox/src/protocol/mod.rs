use serde::{Deserialize, Serialize};
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::time::Duration;

pub const PROTOCOL_VERSION: u16 = 3;
pub const MAX_FRAME_SIZE: usize = 16 * 1024;
pub const MAX_HEADERS: usize = 32;
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

const COVERAGE_GAP_TARGET: &str = "/_agora/coverage-gap";
const CONTENT_TYPE_JSON: &str = "application/json";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectRequest {
    pub protocol_version: u16,
    pub token: String,
    pub sandbox_id: String,
    pub run_id: String,
    pub connection_id: String,
    pub destination: SocketAddr,
    pub process: ProcessIdentity,
    pub operation: HookOperation,
}

impl ConnectRequest {
    pub fn into_registration(self, source: SocketAddr) -> RouteRegistration {
        RouteRegistration {
            sandbox_id: self.sandbox_id,
            run_id: self.run_id,
            connection_id: self.connection_id,
            source,
            destination: self.destination,
            process: self.process,
            operation: self.operation,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteRegistration {
    pub sandbox_id: String,
    pub run_id: String,
    pub connection_id: String,
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub process: ProcessIdentity,
    pub operation: HookOperation,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProxyRequest {
    Connect(ConnectRequest),
    CoverageGap(CoverageGap),
}

impl ProxyRequest {
    pub fn token(&self) -> &str {
        match self {
            Self::Connect(request) => &request.token,
            Self::CoverageGap(gap) => &gap.token,
        }
    }

    pub fn protocol_version(&self) -> u16 {
        match self {
            Self::Connect(request) => request.protocol_version,
            Self::CoverageGap(gap) => gap.protocol_version,
        }
    }

    pub fn run(&self) -> (&str, &str) {
        match self {
            Self::Connect(request) => (&request.sandbox_id, &request.run_id),
            Self::CoverageGap(gap) => (&gap.sandbox_id, &gap.run_id),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageGap {
    pub protocol_version: u16,
    pub token: String,
    pub sandbox_id: String,
    pub run_id: String,
    pub connection_id: Option<String>,
    pub destination: Option<SocketAddr>,
    pub process: ProcessIdentity,
    pub operation: HookOperation,
    pub reason: String,
    pub fallback: CoverageFallback,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub ppid: u32,
    pub executable: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookOperation {
    Connect,
    Connectx,
}

impl HookOperation {
    fn as_str(self) -> &'static str {
        match self {
            Self::Connect => "connect",
            Self::Connectx => "connectx",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "connect" => Some(Self::Connect),
            "connectx" => Some(Self::Connectx),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageFallback {
    FailOpen,
    FailClosed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProxyResponse {
    pub status: u16,
    pub errno: Option<i32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtocolError {
    status: u16,
    message: String,
}

impl ProtocolError {
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(400, message)
    }

    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(407, message)
    }

    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::new(403, message)
    }

    pub fn version_not_supported(message: impl Into<String>) -> Self {
        Self::new(505, message)
    }

    pub fn status(&self) -> u16 {
        self.status
    }

    fn new(status: u16, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ProtocolError {}

pub fn encode_connect_request(request: &ConnectRequest) -> io::Result<Vec<u8>> {
    validate_token(&request.token)?;
    validate_header_value("sandbox id", &request.sandbox_id, false)?;
    validate_header_value("run id", &request.run_id, false)?;
    validate_header_value("connection id", &request.connection_id, false)?;

    let authority = request.destination.to_string();
    let executable = hex_encode(request.process.executable.as_bytes());
    let message = format!(
        "CONNECT {authority} HTTP/1.1\r\n\
         Host: {authority}\r\n\
         Proxy-Authorization: Bearer {}\r\n\
         Agora-Version: {}\r\n\
         Agora-Sandbox-Id: {}\r\n\
         Agora-Run-Id: {}\r\n\
         Agora-Connection-Id: {}\r\n\
         Agora-Pid: {}\r\n\
         Agora-Ppid: {}\r\n\
         Agora-Operation: {}\r\n\
         Agora-Executable-Hex: {}\r\n\
         \r\n",
        request.token,
        request.protocol_version,
        request.sandbox_id,
        request.run_id,
        request.connection_id,
        request.process.pid,
        request.process.ppid,
        request.operation.as_str(),
        executable,
    );
    ensure_frame_size(message.len())?;
    Ok(message.into_bytes())
}

pub fn encode_coverage_gap_request(gap: &CoverageGap) -> io::Result<Vec<u8>> {
    validate_token(&gap.token)?;
    let body = serde_json::to_vec(gap).map_err(invalid_data)?;
    ensure_frame_size(body.len())?;
    let head = format!(
        "POST {COVERAGE_GAP_TARGET} HTTP/1.1\r\n\
         Host: agora-sandbox\r\n\
         Proxy-Authorization: Bearer {}\r\n\
         Agora-Version: {}\r\n\
         Content-Type: {CONTENT_TYPE_JSON}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        gap.token,
        gap.protocol_version,
        body.len(),
    );
    ensure_frame_size(head.len().saturating_add(body.len()))?;
    let mut message = Vec::with_capacity(head.len() + body.len());
    message.extend_from_slice(head.as_bytes());
    message.extend_from_slice(&body);
    Ok(message)
}

pub fn parse_proxy_request(head: &[u8], body: &[u8]) -> Result<ProxyRequest, ProtocolError> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut parsed = httparse::Request::new(&mut headers);
    let consumed = match parsed.parse(head) {
        Ok(httparse::Status::Complete(consumed)) => consumed,
        Ok(httparse::Status::Partial) => {
            return Err(ProtocolError::bad_request("incomplete HTTP request head"));
        }
        Err(error) => {
            return Err(ProtocolError::bad_request(format!(
                "invalid HTTP request: {error}"
            )));
        }
    };
    if consumed != head.len() || parsed.version != Some(1) {
        return Err(ProtocolError::bad_request(
            "proxy requests must use HTTP/1.1",
        ));
    }

    let token = bearer_token(parsed.headers)?.to_string();
    let protocol_version = required_header_string(parsed.headers, "Agora-Version")?
        .parse::<u16>()
        .map_err(|_| ProtocolError::bad_request("invalid Agora-Version"))?;
    match (parsed.method, parsed.path) {
        (Some("CONNECT"), Some(target)) => {
            if !body.is_empty() || request_body_length_from_headers(parsed.headers)? != 0 {
                return Err(ProtocolError::bad_request(
                    "CONNECT request bodies are not supported",
                ));
            }
            let destination = target
                .parse::<SocketAddr>()
                .map_err(|_| ProtocolError::bad_request("CONNECT target must be an IP:port"))?;
            let host = required_header_string(parsed.headers, "Host")?
                .parse::<SocketAddr>()
                .map_err(|_| ProtocolError::bad_request("Host must be an IP:port"))?;
            if host != destination {
                return Err(ProtocolError::bad_request(
                    "Host does not match CONNECT target",
                ));
            }
            let operation =
                HookOperation::parse(required_header_string(parsed.headers, "Agora-Operation")?)
                    .ok_or_else(|| ProtocolError::bad_request("invalid Agora-Operation"))?;
            let executable = hex_decode(required_header_string(
                parsed.headers,
                "Agora-Executable-Hex",
            )?)?;
            let executable = String::from_utf8(executable)
                .map_err(|_| ProtocolError::bad_request("invalid executable encoding"))?;
            Ok(ProxyRequest::Connect(ConnectRequest {
                protocol_version,
                token,
                sandbox_id: required_header_string(parsed.headers, "Agora-Sandbox-Id")?.to_string(),
                run_id: required_header_string(parsed.headers, "Agora-Run-Id")?.to_string(),
                connection_id: required_header_string(parsed.headers, "Agora-Connection-Id")?
                    .to_string(),
                destination,
                process: ProcessIdentity {
                    pid: parse_u32_header(parsed.headers, "Agora-Pid")?,
                    ppid: parse_u32_header(parsed.headers, "Agora-Ppid")?,
                    executable,
                },
                operation,
            }))
        }
        (Some("POST"), Some(COVERAGE_GAP_TARGET)) => {
            let content_type = required_header_string(parsed.headers, "Content-Type")?;
            if !content_type.eq_ignore_ascii_case(CONTENT_TYPE_JSON) {
                return Err(ProtocolError::bad_request("unsupported Content-Type"));
            }
            let expected = request_body_length_from_headers(parsed.headers)?;
            if expected != body.len() {
                return Err(ProtocolError::bad_request(
                    "coverage-gap body length does not match Content-Length",
                ));
            }
            let gap = serde_json::from_slice::<CoverageGap>(body).map_err(|error| {
                ProtocolError::bad_request(format!("invalid JSON body: {error}"))
            })?;
            if gap.token != token || gap.protocol_version != protocol_version {
                return Err(ProtocolError::bad_request(
                    "coverage-gap envelope does not match HTTP headers",
                ));
            }
            Ok(ProxyRequest::CoverageGap(gap))
        }
        _ => Err(ProtocolError::new(405, "unsupported proxy request")),
    }
}

pub fn request_body_length(head: &[u8]) -> Result<usize, ProtocolError> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut parsed = httparse::Request::new(&mut headers);
    match parsed.parse(head) {
        Ok(httparse::Status::Complete(consumed)) if consumed == head.len() => {
            request_body_length_from_headers(parsed.headers)
        }
        Ok(httparse::Status::Complete(_)) => {
            Err(ProtocolError::bad_request("invalid HTTP request framing"))
        }
        Ok(httparse::Status::Partial) => {
            Err(ProtocolError::bad_request("incomplete HTTP request head"))
        }
        Err(error) => Err(ProtocolError::bad_request(format!(
            "invalid HTTP request: {error}"
        ))),
    }
}

pub fn encode_proxy_response(status: u16, errno: Option<i32>) -> Vec<u8> {
    let reason = match status {
        200 => "Connection Established",
        204 => "No Content",
        400 => "Bad Request",
        403 => "Forbidden",
        405 => "Method Not Allowed",
        407 => "Proxy Authentication Required",
        408 => "Request Timeout",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        504 => "Gateway Timeout",
        505 => "HTTP Version Not Supported",
        _ => "Error",
    };
    let mut response = format!("HTTP/1.1 {status} {reason}\r\n");
    if status == 407 {
        response.push_str("Proxy-Authenticate: Bearer realm=\"agora-sandbox\"\r\n");
    }
    if let Some(errno) = errno {
        response.push_str(&format!("Agora-Errno: {errno}\r\n"));
    }
    if status != 200 {
        response.push_str("Content-Length: 0\r\nConnection: close\r\n");
    }
    response.push_str("\r\n");
    response.into_bytes()
}

pub fn parse_proxy_response(head: &[u8]) -> Result<ProxyResponse, ProtocolError> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut parsed = httparse::Response::new(&mut headers);
    let consumed = match parsed.parse(head) {
        Ok(httparse::Status::Complete(consumed)) => consumed,
        Ok(httparse::Status::Partial) => {
            return Err(ProtocolError::bad_request("incomplete HTTP response head"));
        }
        Err(error) => {
            return Err(ProtocolError::bad_request(format!(
                "invalid HTTP response: {error}"
            )));
        }
    };
    if consumed != head.len() || parsed.version != Some(1) {
        return Err(ProtocolError::bad_request(
            "proxy responses must use HTTP/1.1",
        ));
    }
    let status = parsed
        .code
        .ok_or_else(|| ProtocolError::bad_request("missing HTTP response status"))?;
    let errno = optional_header_string(parsed.headers, "Agora-Errno")?
        .map(|value| {
            value
                .parse::<i32>()
                .map_err(|_| ProtocolError::bad_request("invalid Agora-Errno"))
        })
        .transpose()?;
    Ok(ProxyResponse { status, errno })
}

fn request_body_length_from_headers(
    headers: &[httparse::Header<'_>],
) -> Result<usize, ProtocolError> {
    if optional_header(headers, "Transfer-Encoding")?.is_some() {
        return Err(ProtocolError::bad_request(
            "Transfer-Encoding is not supported",
        ));
    }
    let Some(value) = optional_header_string(headers, "Content-Length")? else {
        return Ok(0);
    };
    let length = value
        .parse::<usize>()
        .map_err(|_| ProtocolError::bad_request("invalid Content-Length"))?;
    if length > MAX_FRAME_SIZE {
        return Err(ProtocolError::bad_request(format!(
            "request body exceeds {MAX_FRAME_SIZE} bytes"
        )));
    }
    Ok(length)
}

fn bearer_token<'a>(headers: &[httparse::Header<'a>]) -> Result<&'a str, ProtocolError> {
    let credentials = required_header_string(headers, "Proxy-Authorization")?;
    let Some((scheme, token)) = credentials.split_once(' ') else {
        return Err(ProtocolError::unauthorized(
            "invalid Proxy-Authorization credentials",
        ));
    };
    if !scheme.eq_ignore_ascii_case("Bearer") || !is_token68(token) {
        return Err(ProtocolError::unauthorized(
            "invalid Proxy-Authorization credentials",
        ));
    }
    Ok(token)
}

fn parse_u32_header(headers: &[httparse::Header<'_>], name: &str) -> Result<u32, ProtocolError> {
    required_header_string(headers, name)?
        .parse::<u32>()
        .map_err(|_| ProtocolError::bad_request(format!("invalid {name}")))
}

fn required_header_string<'a>(
    headers: &[httparse::Header<'a>],
    name: &str,
) -> Result<&'a str, ProtocolError> {
    let value = optional_header(headers, name)?
        .ok_or_else(|| ProtocolError::bad_request(format!("missing {name} header")))?;
    std::str::from_utf8(value)
        .map_err(|_| ProtocolError::bad_request(format!("invalid {name} header")))
}

fn optional_header_string<'a>(
    headers: &[httparse::Header<'a>],
    name: &str,
) -> Result<Option<&'a str>, ProtocolError> {
    optional_header(headers, name)?
        .map(|value| {
            std::str::from_utf8(value)
                .map_err(|_| ProtocolError::bad_request(format!("invalid {name} header")))
        })
        .transpose()
}

fn optional_header<'a>(
    headers: &[httparse::Header<'a>],
    name: &str,
) -> Result<Option<&'a [u8]>, ProtocolError> {
    let mut matching = headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case(name));
    let value = matching.next().map(|header| header.value);
    if matching.next().is_some() {
        return Err(ProtocolError::bad_request(format!(
            "duplicate {name} header"
        )));
    }
    Ok(value)
}

fn validate_token(token: &str) -> io::Result<()> {
    if is_token68(token) {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid bearer token",
        ))
    }
}

fn is_token68(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/' | b'=')
        })
}

fn validate_header_value(name: &str, value: &str, allow_empty: bool) -> io::Result<()> {
    if (allow_empty || !value.is_empty())
        && value
            .bytes()
            .all(|byte| byte.is_ascii() && !byte.is_ascii_control())
    {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid {name}"),
        ))
    }
}

fn ensure_frame_size(length: usize) -> io::Result<()> {
    if length <= MAX_FRAME_SIZE {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("HTTP frame exceeds {MAX_FRAME_SIZE} bytes"),
        ))
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn hex_decode(value: &str) -> Result<Vec<u8>, ProtocolError> {
    if !value.len().is_multiple_of(2) {
        return Err(ProtocolError::bad_request("invalid executable encoding"));
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_digit(pair[0])?;
            let low = hex_digit(pair[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_digit(value: u8) -> Result<u8, ProtocolError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(ProtocolError::bad_request("invalid executable encoding")),
    }
}

fn invalid_data(error: impl std::error::Error + Send + Sync + 'static) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

#[cfg(test)]
mod tests;
