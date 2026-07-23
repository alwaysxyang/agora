use super::NetworkState;
use super::inspection::DomainObservation;
use crate::audit::{DomainSource, NoopAuditCallback};
use crate::protocol::{HookOperation, ProcessIdentity, RouteRegistration};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

fn registration() -> RouteRegistration {
    RouteRegistration {
        sandbox_id: "sandbox".to_string(),
        run_id: "run".to_string(),
        connection_id: "connection-1".to_string(),
        source: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 49155),
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
