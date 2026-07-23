mod config;
mod control;
mod inspection;
mod proxy;
mod route;

pub use config::{NetworkConfig, NetworkEnforcement, TlsMode};

use crate::audit::{
    AUDIT_SCHEMA_VERSION, AuditCallback, AuditDecision, AuditEvent, AuditEventType, AuditMetrics,
    AuditResult, AuditResultStatus, AuditSubsystem, DomainSource, NetworkAudit, NetworkProtocol,
    ProcessAudit,
};
use crate::protocol::{
    ControlRequest, ControlResponse, CoverageFallback, CoverageGap, PROTOCOL_VERSION, RouteOutcome,
    RouteRegistration,
};
use anyhow::{Context, Result};
use chrono::{SecondsFormat, Utc};
use inspection::DomainObservation;
use route::RouteRegistry;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream, UnixListener};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkRunContext {
    sandbox_id: String,
    run_id: String,
}

impl NetworkRunContext {
    pub fn new(sandbox_id: impl Into<String>, run_id: impl Into<String>) -> Self {
        Self {
            sandbox_id: sandbox_id.into(),
            run_id: run_id.into(),
        }
    }

    pub fn sandbox_id(&self) -> &str {
        &self.sandbox_id
    }

    pub fn run_id(&self) -> &str {
        &self.run_id
    }
}

#[derive(Clone, Debug)]
pub struct NetworkRuntime {
    control_socket: PathBuf,
    token: String,
    proxy_ipv4: SocketAddr,
    proxy_ipv6: SocketAddr,
}

impl NetworkRuntime {
    pub fn control_socket(&self) -> &Path {
        &self.control_socket
    }

    pub fn token(&self) -> &str {
        &self.token
    }

    pub fn proxy_ipv4(&self) -> SocketAddr {
        self.proxy_ipv4
    }

    pub fn proxy_ipv6(&self) -> SocketAddr {
        self.proxy_ipv6
    }
}

pub struct NetworkController<C>
where
    C: AuditCallback,
{
    runtime: NetworkRuntime,
    shutdown: watch::Sender<bool>,
    tasks: Vec<JoinHandle<Result<()>>>,
    marker: std::marker::PhantomData<C>,
}

impl<C> NetworkController<C>
where
    C: AuditCallback,
{
    pub async fn start(
        config: NetworkConfig,
        context: NetworkRunContext,
        callback: C,
    ) -> Result<Self> {
        config.validate()?;

        let token = Uuid::new_v4().simple().to_string();
        let control_socket = std::env::temp_dir().join(format!(
            "agora-sbx-{}-{}.sock",
            std::process::id(),
            &token[..12]
        ));
        let control_listener = UnixListener::bind(&control_socket).with_context(|| {
            format!(
                "failed to bind sandbox control socket {}",
                control_socket.display()
            )
        })?;
        Self::restrict_control_socket(&control_socket)?;

        let ipv4_listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .context("failed to bind IPv4 sandbox proxy")?;
        let ipv6_listener = TcpListener::bind((std::net::Ipv6Addr::LOCALHOST, 0))
            .await
            .context("failed to bind IPv6 sandbox proxy")?;
        let proxy_ipv4 = ipv4_listener.local_addr()?;
        let proxy_ipv6 = ipv6_listener.local_addr()?;

        let state = Arc::new(NetworkState {
            config,
            context,
            token: token.clone(),
            routes: RouteRegistry::new(config.route_ttl),
            callback,
        });
        let (shutdown, shutdown_receiver) = watch::channel(false);
        let control = control::ControlServer::new(control_listener, Arc::clone(&state));
        let ipv4 = proxy::ProxyServer::new(ipv4_listener, Arc::clone(&state));
        let ipv6 = proxy::ProxyServer::new(ipv6_listener, state);
        let tasks = vec![
            tokio::spawn(control.run(shutdown_receiver.clone())),
            tokio::spawn(ipv4.run(shutdown_receiver.clone())),
            tokio::spawn(ipv6.run(shutdown_receiver)),
        ];

        Ok(Self {
            runtime: NetworkRuntime {
                control_socket,
                token,
                proxy_ipv4,
                proxy_ipv6,
            },
            shutdown,
            tasks,
            marker: std::marker::PhantomData,
        })
    }

    pub fn runtime(&self) -> &NetworkRuntime {
        &self.runtime
    }

    pub async fn shutdown(mut self) -> Result<()> {
        let _ = self.shutdown.send(true);
        let mut first_error = None;
        while let Some(task) = self.tasks.pop() {
            match task.await {
                Ok(Ok(())) => {}
                Ok(Err(error)) if first_error.is_none() => first_error = Some(error),
                Err(error) if first_error.is_none() => first_error = Some(error.into()),
                _ => {}
            }
        }
        self.remove_control_socket();
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    #[cfg(unix)]
    fn restrict_control_socket(path: &Path) -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).with_context(|| {
            format!(
                "failed to restrict sandbox control socket {}",
                path.display()
            )
        })
    }

    #[cfg(not(unix))]
    fn restrict_control_socket(_path: &Path) -> Result<()> {
        Ok(())
    }

    fn remove_control_socket(&self) {
        match std::fs::remove_file(&self.runtime.control_socket) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => {}
        }
    }
}

impl<C> Drop for NetworkController<C>
where
    C: AuditCallback,
{
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
        for task in &self.tasks {
            task.abort();
        }
        self.remove_control_socket();
    }
}

struct NetworkState<C>
where
    C: AuditCallback,
{
    config: NetworkConfig,
    context: NetworkRunContext,
    token: String,
    routes: RouteRegistry,
    callback: C,
}

impl<C> NetworkState<C>
where
    C: AuditCallback,
{
    fn validate_request(&self, request: &ControlRequest) -> Result<(), String> {
        if request.protocol_version() != PROTOCOL_VERSION {
            return Err(format!(
                "unsupported control protocol version {}",
                request.protocol_version()
            ));
        }
        if request.token() != self.token {
            return Err("invalid control token".to_string());
        }
        Ok(())
    }

    async fn handle_request(&self, request: ControlRequest) -> ControlResponse {
        if let Err(message) = self.validate_request(&request) {
            return ControlResponse::ProtocolRejected { message };
        }

        match request {
            ControlRequest::RegisterRoute(registration) => {
                if !self.matches_run(&registration.sandbox_id, &registration.run_id) {
                    return ControlResponse::ProtocolRejected {
                        message: "route registration does not belong to this run".to_string(),
                    };
                }
                self.register_route(registration).await
            }
            ControlRequest::CoverageGap(gap) => {
                if !self.matches_run(&gap.sandbox_id, &gap.run_id) {
                    return ControlResponse::ProtocolRejected {
                        message: "coverage gap does not belong to this run".to_string(),
                    };
                }
                self.publish_coverage_gap(&gap);
                ControlResponse::CoverageGapRecorded
            }
        }
    }

    async fn register_route(&self, registration: RouteRegistration) -> ControlResponse {
        self.publish_route_event(
            &registration,
            AuditEventType::NetworkConnectAttempt,
            0,
            AuditDecision::Observed,
            AuditResult {
                status: AuditResultStatus::Started,
                error_code: None,
                error_message: None,
            },
        );

        let upstream = tokio::time::timeout(
            self.config.upstream_connect_timeout,
            TcpStream::connect(registration.destination),
        )
        .await;
        let result = match upstream {
            Ok(Ok(stream)) => self.routes.insert(registration.clone(), stream),
            Ok(Err(error)) => Err(error),
            Err(_) => Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "upstream connection timed out",
            )),
        };

        match result {
            Ok(()) => {
                self.publish_route_event(
                    &registration,
                    AuditEventType::NetworkConnectEstablished,
                    1,
                    AuditDecision::Allowed,
                    AuditResult {
                        status: AuditResultStatus::Succeeded,
                        error_code: None,
                        error_message: None,
                    },
                );
                ControlResponse::Route {
                    connection_id: registration.connection_id,
                    outcome: RouteOutcome::Accepted,
                    errno: None,
                    message: None,
                }
            }
            Err(error) => {
                let errno = error.raw_os_error();
                let message = error.to_string();
                self.publish_route_event(
                    &registration,
                    AuditEventType::NetworkConnectFailed,
                    1,
                    AuditDecision::Denied,
                    AuditResult {
                        status: AuditResultStatus::Failed,
                        error_code: errno.map(|value| value.to_string()),
                        error_message: Some(message.clone()),
                    },
                );
                ControlResponse::Route {
                    connection_id: registration.connection_id,
                    outcome: RouteOutcome::Rejected,
                    errno,
                    message: Some(message),
                }
            }
        }
    }

    fn matches_run(&self, sandbox_id: &str, run_id: &str) -> bool {
        sandbox_id == self.context.sandbox_id && run_id == self.context.run_id
    }

    fn publish_route_event(
        &self,
        registration: &RouteRegistration,
        event_type: AuditEventType,
        sequence: u64,
        decision: AuditDecision,
        result: AuditResult,
    ) {
        self.callback.on_event(AuditEvent {
            schema_version: AUDIT_SCHEMA_VERSION,
            event_id: Uuid::new_v4().to_string(),
            occurred_at: Self::now(),
            subsystem: AuditSubsystem::Network,
            event_type,
            sandbox_id: self.context.sandbox_id.clone(),
            run_id: self.context.run_id.clone(),
            connection_id: Some(registration.connection_id.clone()),
            sequence: Some(sequence),
            process: Self::process_audit(&registration.process),
            network: Some(Self::network_audit(registration, None)),
            tls: None,
            decision,
            result,
            metrics: None,
        });
    }

    fn publish_domain_observed(
        &self,
        registration: &RouteRegistration,
        observation: &DomainObservation,
    ) {
        self.callback.on_event(AuditEvent {
            schema_version: AUDIT_SCHEMA_VERSION,
            event_id: Uuid::new_v4().to_string(),
            occurred_at: Self::now(),
            subsystem: AuditSubsystem::Network,
            event_type: AuditEventType::NetworkDomainObserved,
            sandbox_id: self.context.sandbox_id.clone(),
            run_id: self.context.run_id.clone(),
            connection_id: Some(registration.connection_id.clone()),
            sequence: Some(2),
            process: Self::process_audit(&registration.process),
            network: Some(Self::network_audit(registration, Some(observation))),
            tls: None,
            decision: AuditDecision::Observed,
            result: AuditResult {
                status: AuditResultStatus::Succeeded,
                error_code: None,
                error_message: None,
            },
            metrics: None,
        });
    }

    fn publish_closed(
        &self,
        registration: &RouteRegistration,
        result: std::io::Result<(u64, u64)>,
        duration_ms: u64,
        observation: Option<&DomainObservation>,
    ) {
        let (status, error_code, error_message, metrics) = match result {
            Ok((bytes_sent, bytes_received)) => (
                AuditResultStatus::Succeeded,
                None,
                None,
                AuditMetrics {
                    bytes_sent,
                    bytes_received,
                    duration_ms,
                },
            ),
            Err(error) => (
                AuditResultStatus::Failed,
                error.raw_os_error().map(|value| value.to_string()),
                Some(error.to_string()),
                AuditMetrics {
                    bytes_sent: 0,
                    bytes_received: 0,
                    duration_ms,
                },
            ),
        };
        self.callback.on_event(AuditEvent {
            schema_version: AUDIT_SCHEMA_VERSION,
            event_id: Uuid::new_v4().to_string(),
            occurred_at: Self::now(),
            subsystem: AuditSubsystem::Network,
            event_type: AuditEventType::NetworkConnectionClosed,
            sandbox_id: self.context.sandbox_id.clone(),
            run_id: self.context.run_id.clone(),
            connection_id: Some(registration.connection_id.clone()),
            sequence: Some(if observation.is_some() { 3 } else { 2 }),
            process: Self::process_audit(&registration.process),
            network: Some(Self::network_audit(registration, observation)),
            tls: None,
            decision: AuditDecision::Allowed,
            result: AuditResult {
                status,
                error_code,
                error_message,
            },
            metrics: Some(metrics),
        });
    }

    fn publish_coverage_gap(&self, gap: &CoverageGap) {
        let network = gap.destination.map(|destination| NetworkAudit {
            protocol: NetworkProtocol::Tcp,
            source_ip: None,
            source_port: None,
            destination_ip: destination.ip(),
            destination_port: destination.port(),
            http_host: None,
            tls_sni: None,
            domain: None,
            domain_source: None,
        });
        self.callback.on_event(AuditEvent {
            schema_version: AUDIT_SCHEMA_VERSION,
            event_id: Uuid::new_v4().to_string(),
            occurred_at: Self::now(),
            subsystem: AuditSubsystem::Network,
            event_type: AuditEventType::NetworkCoverageGap,
            sandbox_id: self.context.sandbox_id.clone(),
            run_id: self.context.run_id.clone(),
            connection_id: gap.connection_id.clone(),
            sequence: gap.connection_id.as_ref().map(|_| 0),
            process: Self::process_audit(&gap.process),
            network,
            tls: None,
            decision: match gap.fallback {
                CoverageFallback::FailOpen => AuditDecision::FailedOpen,
                CoverageFallback::FailClosed => AuditDecision::Denied,
            },
            result: AuditResult {
                status: AuditResultStatus::Failed,
                error_code: Some("interception_coverage_gap".to_string()),
                error_message: Some(gap.reason.clone()),
            },
            metrics: None,
        });
    }

    fn process_audit(process: &crate::protocol::ProcessIdentity) -> ProcessAudit {
        ProcessAudit {
            pid: process.pid,
            ppid: process.ppid,
            executable: process.executable.clone(),
        }
    }

    fn network_audit(
        registration: &RouteRegistration,
        observation: Option<&DomainObservation>,
    ) -> NetworkAudit {
        NetworkAudit {
            protocol: NetworkProtocol::Tcp,
            source_ip: Some(registration.source.ip()),
            source_port: Some(registration.source.port()),
            destination_ip: registration.destination.ip(),
            destination_port: registration.destination.port(),
            http_host: observation
                .filter(|value| value.source == DomainSource::HttpHost)
                .map(|value| value.domain.clone()),
            tls_sni: observation
                .filter(|value| value.source == DomainSource::TlsSni)
                .map(|value| value.domain.clone()),
            domain: observation.map(|value| value.domain.clone()),
            domain_source: observation.map(|value| value.source),
        }
    }

    fn now() -> String {
        Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
    }
}

#[cfg(test)]
mod inspection_tests;
#[cfg(test)]
mod integration_tests;
#[cfg(test)]
mod tests;
