use super::NetworkState;
use super::inspection::DomainObservation;
use super::route::RouteRegistry;
use crate::audit::{DomainSource, NoopAuditCallback};
use crate::protocol::{HookOperation, PROTOCOL_VERSION, ProcessIdentity, RouteRegistration};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};

fn registration(source_port: u16) -> RouteRegistration {
    RouteRegistration {
        protocol_version: PROTOCOL_VERSION,
        token: "token".to_string(),
        sandbox_id: "sandbox".to_string(),
        run_id: "run".to_string(),
        connection_id: format!("connection-{source_port}"),
        source: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), source_port),
        destination: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443),
        process: ProcessIdentity {
            pid: 1,
            ppid: 0,
            executable: "/tmp/client".to_string(),
        },
        operation: HookOperation::Connect,
    }
}

async fn connected_stream() -> TcpStream {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let client = TcpStream::connect(address);
    let server = listener.accept();
    let (client, server) = tokio::join!(client, server);
    drop(client.unwrap());
    server.unwrap().0
}

#[tokio::test]
async fn registered_route_can_be_consumed_exactly_once() {
    let registry = RouteRegistry::new(Duration::from_secs(1));
    let registration = registration(49152);
    registry
        .insert(registration.clone(), connected_stream().await)
        .unwrap();

    let route = registry.take(registration.source).unwrap();

    assert_eq!(route.registration.connection_id, "connection-49152");
    assert!(registry.take(registration.source).is_none());
}

#[tokio::test]
async fn expired_routes_are_not_consumed() {
    let registry = RouteRegistry::new(Duration::from_millis(10));
    let registration = registration(49153);
    registry
        .insert(registration.clone(), connected_stream().await)
        .unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;

    assert!(registry.take(registration.source).is_none());
}

#[tokio::test]
async fn duplicate_live_source_is_rejected() {
    let registry = RouteRegistry::new(Duration::from_secs(1));
    let registration = registration(49154);
    registry
        .insert(registration.clone(), connected_stream().await)
        .unwrap();

    let error = registry
        .insert(registration, connected_stream().await)
        .unwrap_err();

    assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
}

#[test]
fn tls_sni_populates_only_the_tls_domain_fields() {
    let registration = registration(49155);
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
