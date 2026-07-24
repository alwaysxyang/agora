mod proxy;

use super::inspection::DomainObservation;
use super::{NetworkConfig, NetworkController, NetworkRunContext, NetworkState};
use crate::audit::{DomainSource, NoopAuditCallback};
use crate::protocol::{HookOperation, ProcessIdentity, RouteRegistration};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

fn registration() -> RouteRegistration {
    RouteRegistration {
        connection_id: "connection-1".to_string(),
        destination: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443),
        process: ProcessIdentity {
            pid: 1,
            ppid: 0,
            executable: "/tmp/client".to_string(),
        },
        operation: HookOperation::Connect,
    }
}

#[test]
fn network_config_requires_a_positive_connection_limit() {
    let mut config = NetworkConfig::default();
    assert!(config.max_connections > 0);

    config.max_connections = 0;
    assert!(
        config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("max_connections")
    );
}

#[tokio::test]
async fn controller_reports_an_unexpected_listener_exit() {
    let mut controller = NetworkController::start(
        NetworkConfig::default(),
        NetworkRunContext::new("sandbox", "run"),
        NoopAuditCallback,
    )
    .await
    .unwrap();
    controller.abort_listener_for_test();

    let error = controller.wait_failure().await;

    assert!(error.to_string().contains("proxy listener"));
}

#[test]
fn tls_sni_populates_only_the_tls_domain_fields() {
    let registration = registration();
    let observation = DomainObservation {
        domain: "secure.example.com".to_string(),
        source: DomainSource::TlsSni,
    };

    let audit = NetworkState::<NoopAuditCallback>::network_audit(&registration, Some(&observation));

    assert_eq!(audit.http_host, None);
    assert_eq!(audit.tls_sni.as_deref(), Some("secure.example.com"));
    assert_eq!(audit.domain.as_deref(), Some("secure.example.com"));
    assert_eq!(audit.domain_source, Some(DomainSource::TlsSni));
}
