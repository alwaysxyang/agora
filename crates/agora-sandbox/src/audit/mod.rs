use serde::{Deserialize, Serialize};
use std::net::IpAddr;

pub const AUDIT_SCHEMA_VERSION: u16 = 3;

pub trait AuditCallback: Send + Sync + 'static {
    fn on_event(&self, event: AuditEvent);
}

impl<F> AuditCallback for F
where
    F: Fn(AuditEvent) + Send + Sync + 'static,
{
    fn on_event(&self, event: AuditEvent) {
        self(event);
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct NoopAuditCallback;

impl AuditCallback for NoopAuditCallback {
    fn on_event(&self, _event: AuditEvent) {}
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub schema_version: u16,
    pub event_id: String,
    pub occurred_at: String,
    pub subsystem: AuditSubsystem,
    pub event_type: AuditEventType,
    pub sandbox_id: String,
    pub run_id: String,
    pub connection_id: Option<String>,
    pub sequence: Option<u64>,
    pub process: ProcessAudit,
    pub network: Option<NetworkAudit>,
    pub tls: Option<TlsAudit>,
    pub decision: AuditDecision,
    pub result: AuditResult,
    pub metrics: Option<AuditMetrics>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditSubsystem {
    Network,
    Filesystem,
    Process,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditEventType {
    #[serde(rename = "network.connect.attempt")]
    NetworkConnectAttempt,
    #[serde(rename = "network.connect.established")]
    NetworkConnectEstablished,
    #[serde(rename = "network.domain.observed")]
    NetworkDomainObserved,
    #[serde(rename = "network.connect.failed")]
    NetworkConnectFailed,
    #[serde(rename = "network.connection.closed")]
    NetworkConnectionClosed,
    #[serde(rename = "filesystem.read")]
    FilesystemRead,
    #[serde(rename = "filesystem.write")]
    FilesystemWrite,
    #[serde(rename = "process.started")]
    ProcessStarted,
    #[serde(rename = "process.exited")]
    ProcessExited,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessAudit {
    pub pid: u32,
    pub ppid: u32,
    pub executable: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkAudit {
    pub protocol: NetworkProtocol,
    pub destination_ip: IpAddr,
    pub destination_port: u16,
    pub http_host: Option<String>,
    pub tls_sni: Option<String>,
    pub domain: Option<String>,
    pub domain_source: Option<DomainSource>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkProtocol {
    Tcp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainSource {
    HttpHost,
    TlsSni,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsAudit {
    pub policy: TlsPolicy,
    pub outcome: TlsOutcome,
    pub alpn: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsPolicy {
    Off,
    Auto,
    Require,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsOutcome {
    NotAttempted,
    Terminated,
    Passthrough,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditDecision {
    Observed,
    Allowed,
    Denied,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditResult {
    pub status: AuditResultStatus,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditResultStatus {
    Started,
    Succeeded,
    Failed,
    Interrupted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditMetrics {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub duration_ms: u64,
}
