mod proxy;

use super::inspection::DomainObservation;
use super::{NetworkConfig, NetworkController, NetworkRunContext, NetworkState};
use crate::callback::{DomainSource, NoopCallback};
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

#[test]
fn network_config_requires_positive_inspection_and_callback_timeouts() {
    let config = NetworkConfig {
        domain_inspection_timeout: std::time::Duration::ZERO,
        ..NetworkConfig::default()
    };
    assert!(
        config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("domain_inspection_timeout")
    );

    let config = NetworkConfig {
        callback_timeout: std::time::Duration::ZERO,
        ..NetworkConfig::default()
    };
    assert!(
        config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("callback_timeout")
    );
}

#[tokio::test]
async fn controller_reports_an_unexpected_listener_exit() {
    let mut controller = NetworkController::start(
        NetworkConfig::default(),
        NetworkRunContext::new("sandbox", "run"),
        NoopCallback,
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

    let context = NetworkState::<NoopCallback>::network_context(&registration, Some(&observation));

    assert_eq!(context.http_host, None);
    assert_eq!(context.tls_sni.as_deref(), Some("secure.example.com"));
    assert_eq!(context.domain.as_deref(), Some("secure.example.com"));
    assert_eq!(context.domain_source, Some(DomainSource::TlsSni));
}
