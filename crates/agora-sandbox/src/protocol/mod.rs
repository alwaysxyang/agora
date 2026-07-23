use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};
use std::net::SocketAddr;

pub const PROTOCOL_VERSION: u16 = 2;
pub const MAX_FRAME_SIZE: usize = 16 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload", rename_all = "snake_case")]
pub enum ControlRequest {
    RegisterRoute(RouteRegistration),
    CoverageGap(CoverageGap),
}

impl ControlRequest {
    pub fn token(&self) -> &str {
        match self {
            Self::RegisterRoute(registration) => &registration.token,
            Self::CoverageGap(gap) => &gap.token,
        }
    }

    pub fn protocol_version(&self) -> u16 {
        match self {
            Self::RegisterRoute(registration) => registration.protocol_version,
            Self::CoverageGap(gap) => gap.protocol_version,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ControlResponse {
    Route {
        connection_id: String,
        outcome: RouteOutcome,
        errno: Option<i32>,
        message: Option<String>,
    },
    CoverageGapRecorded,
    ProtocolRejected {
        message: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteRegistration {
    pub protocol_version: u16,
    pub token: String,
    pub sandbox_id: String,
    pub run_id: String,
    pub connection_id: String,
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub process: ProcessIdentity,
    pub operation: HookOperation,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageFallback {
    FailOpen,
    FailClosed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteOutcome {
    Accepted,
    Rejected,
}

pub fn write_message<W, T>(writer: &mut W, message: &T) -> io::Result<()>
where
    W: Write,
    T: Serialize,
{
    let payload = serde_json::to_vec(message).map_err(invalid_data)?;
    if payload.len() > MAX_FRAME_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("control frame exceeds {MAX_FRAME_SIZE} bytes"),
        ));
    }

    writer.write_all(&(payload.len() as u32).to_be_bytes())?;
    writer.write_all(&payload)
}

pub fn read_message<R, T>(reader: &mut R) -> io::Result<T>
where
    R: Read,
    T: DeserializeOwned,
{
    let mut length = [0_u8; 4];
    reader.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if length > MAX_FRAME_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("control frame exceeds {MAX_FRAME_SIZE} bytes"),
        ));
    }

    let mut payload = vec![0_u8; length];
    reader.read_exact(&mut payload)?;
    serde_json::from_slice(&payload).map_err(invalid_data)
}

fn invalid_data(error: impl std::error::Error + Send + Sync + 'static) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

#[cfg(test)]
mod tests;
