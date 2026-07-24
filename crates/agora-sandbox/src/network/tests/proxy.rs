use super::super::{NetworkConfig, NetworkController, NetworkRunContext, NetworkRuntime};
use crate::audit::{AuditCallback, AuditEvent, AuditEventType, DomainSource};
use crate::protocol::{
    ConnectRequest, HookOperation, PROTOCOL_VERSION, ProcessIdentity, encode_connect_request,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[derive(Clone, Default)]
struct EventLog(Arc<Mutex<Vec<AuditEvent>>>);

impl AuditCallback for EventLog {
    fn on_event(&self, event: AuditEvent) {
        self.0.lock().unwrap().push(event);
    }
}

impl EventLog {
    fn snapshot(&self) -> Vec<AuditEvent> {
        self.0.lock().unwrap().clone()
    }

    async fn wait_for_len(&self, expected: usize) {
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if self.0.lock().unwrap().len() >= expected {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
}

struct ProxyFixture {
    controller: NetworkController,
    events: EventLog,
}

impl ProxyFixture {
    async fn start() -> Self {
        Self::start_with_config(NetworkConfig::default()).await
    }

    async fn start_with_config(config: NetworkConfig) -> Self {
        let events = EventLog::default();
        let controller = NetworkController::start(
            config,
            NetworkRunContext::new("sandbox-1", "run-1"),
            events.clone(),
        )
        .await
        .unwrap();
        Self { controller, events }
    }
}

fn connect_request(
    runtime: &NetworkRuntime,
    destination: SocketAddr,
    connection_id: &str,
) -> ConnectRequest {
    ConnectRequest {
        protocol_version: PROTOCOL_VERSION,
        token: runtime.token().to_string(),
        connection_id: connection_id.to_string(),
        destination,
        process: ProcessIdentity {
            pid: std::process::id(),
            ppid: 1,
            executable: "/tmp/test-client".to_string(),
        },
        operation: HookOperation::Connect,
    }
}

async fn echo_server() -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut bytes = [0_u8; 64];
                loop {
                    let read = stream.read(&mut bytes).await.unwrap();
                    if read == 0 {
                        break;
                    }
                    stream.write_all(&bytes[..read]).await.unwrap();
                }
            });
        }
    });
    address
}

async fn open_tunnel(
    runtime: &NetworkRuntime,
    request: &ConnectRequest,
    initial_data: &[u8],
) -> TcpStream {
    let mut stream = TcpStream::connect(runtime.proxy_ipv4()).await.unwrap();
    let mut bytes = encode_connect_request(request).unwrap();
    bytes.extend_from_slice(initial_data);
    stream.write_all(&bytes).await.unwrap();
    stream
}

async fn assert_rejected(runtime: &NetworkRuntime, request: &ConnectRequest) {
    let mut client = open_tunnel(runtime, request, &[]).await;
    let mut byte = [0_u8; 1];
    let read = tokio::time::timeout(std::time::Duration::from_secs(1), client.read(&mut byte))
        .await
        .unwrap();
    match read {
        Ok(0) => {}
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
        other => panic!("rejected tunnel remained usable: {other:?}"),
    }
}

#[tokio::test]
async fn connect_request_relays_bytes_and_emits_ordered_audit_events() {
    let destination = echo_server().await;
    let fixture = ProxyFixture::start().await;
    let runtime = fixture.controller.runtime().clone();
    let request = connect_request(&runtime, destination, "connection-1");
    let mut client = open_tunnel(&runtime, &request, b"hello").await;

    let mut echoed = [0_u8; 5];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"hello");
    client.shutdown().await.unwrap();

    fixture.events.wait_for_len(3).await;
    let events = fixture.events.snapshot();
    assert_eq!(
        events
            .iter()
            .map(|event| event.event_type)
            .collect::<Vec<_>>(),
        vec![
            AuditEventType::NetworkConnectAttempt,
            AuditEventType::NetworkConnectEstablished,
            AuditEventType::NetworkConnectionClosed,
        ]
    );
    let network = events[0].network.as_ref().unwrap();
    assert_eq!(network.destination_ip, destination.ip());
    assert_eq!(network.destination_port, destination.port());

    fixture.controller.shutdown().await.unwrap();
}

#[tokio::test]
async fn connect_preface_is_not_visible_to_the_application() {
    let destination = echo_server().await;
    let fixture = ProxyFixture::start().await;
    let runtime = fixture.controller.runtime().clone();
    let request = connect_request(&runtime, destination, "connection-transparent");
    let mut client = open_tunnel(&runtime, &request, b"hello").await;

    let mut echoed = [0_u8; 5];
    client.read_exact(&mut echoed).await.unwrap();

    assert_eq!(&echoed, b"hello");
    drop(client);
    fixture.controller.shutdown().await.unwrap();
}

#[tokio::test]
async fn initial_payload_is_relayed_and_audited() {
    let destination = echo_server().await;
    let fixture = ProxyFixture::start().await;
    let runtime = fixture.controller.runtime().clone();
    let connect = connect_request(&runtime, destination, "connection-initial-http");
    let request = b"GET / HTTP/1.1\r\nHost: Initial.Example\r\n\r\n";
    let mut client = open_tunnel(&runtime, &connect, request).await;

    let mut echoed = vec![0_u8; request.len()];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(echoed, request);
    client.shutdown().await.unwrap();

    fixture.events.wait_for_len(4).await;
    let events = fixture.events.snapshot();
    let observed = events
        .iter()
        .find(|event| event.event_type == AuditEventType::NetworkDomainObserved)
        .unwrap();
    assert_eq!(
        observed.network.as_ref().unwrap().domain.as_deref(),
        Some("initial.example")
    );

    fixture.controller.shutdown().await.unwrap();
}

#[tokio::test]
async fn server_first_bytes_are_relayed_without_a_proxy_response() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let destination = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        stream.write_all(b"banner").await.unwrap();
    });
    let fixture = ProxyFixture::start().await;
    let runtime = fixture.controller.runtime().clone();
    let request = connect_request(&runtime, destination, "connection-banner");
    let mut client = open_tunnel(&runtime, &request, &[]).await;

    let mut banner = [0_u8; 6];
    client.read_exact(&mut banner).await.unwrap();

    assert_eq!(&banner, b"banner");
    drop(client);
    fixture.controller.shutdown().await.unwrap();
}

#[tokio::test]
async fn http_host_is_audited_from_relayed_payload() {
    let destination = echo_server().await;
    let fixture = ProxyFixture::start().await;
    let runtime = fixture.controller.runtime().clone();
    let connect = connect_request(&runtime, destination, "connection-http");
    let request = b"GET / HTTP/1.1\r\nHost: Audit.Example:8080\r\n\r\n";
    let mut client = open_tunnel(&runtime, &connect, request).await;

    let mut echoed = vec![0_u8; request.len()];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(echoed, request);
    client.shutdown().await.unwrap();

    fixture.events.wait_for_len(4).await;
    let events = fixture.events.snapshot();
    let event = events
        .iter()
        .find(|event| event.event_type == AuditEventType::NetworkDomainObserved)
        .unwrap();
    let network = event.network.as_ref().unwrap();
    assert_eq!(network.http_host.as_deref(), Some("audit.example"));
    assert_eq!(network.tls_sni, None);
    assert_eq!(network.domain.as_deref(), Some("audit.example"));
    assert_eq!(network.domain_source, Some(DomainSource::HttpHost));
    let closed = events
        .iter()
        .find(|event| event.event_type == AuditEventType::NetworkConnectionClosed)
        .unwrap();
    assert_eq!(closed.sequence, Some(3));
    assert_eq!(closed.network.as_ref().unwrap(), network);

    fixture.controller.shutdown().await.unwrap();
}

#[tokio::test]
async fn invalid_credentials_and_versions_are_rejected_without_audit_events() {
    let fixture = ProxyFixture::start().await;
    let runtime = fixture.controller.runtime().clone();
    let destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9);

    let mut request = connect_request(&runtime, destination, "connection-auth");
    request.token = "wrong-token".to_string();
    assert_rejected(&runtime, &request).await;

    request.token = runtime.token().to_string();
    request.protocol_version += 1;
    assert_rejected(&runtime, &request).await;
    assert!(fixture.events.snapshot().is_empty());

    fixture.controller.shutdown().await.unwrap();
}

#[tokio::test]
async fn upstream_failure_closes_the_tunnel_and_is_audited() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let unavailable = listener.local_addr().unwrap();
    drop(listener);
    let fixture = ProxyFixture::start().await;
    let runtime = fixture.controller.runtime().clone();
    let request = connect_request(&runtime, unavailable, "connection-failed");

    assert_rejected(&runtime, &request).await;

    assert_eq!(
        fixture
            .events
            .snapshot()
            .iter()
            .map(|event| event.event_type)
            .collect::<Vec<_>>(),
        vec![
            AuditEventType::NetworkConnectAttempt,
            AuditEventType::NetworkConnectFailed,
        ]
    );

    fixture.controller.shutdown().await.unwrap();
}

#[tokio::test]
async fn connection_limit_rejects_excess_tunnels() {
    let destination = echo_server().await;
    let config = NetworkConfig {
        max_connections: 1,
        ..NetworkConfig::default()
    };
    let fixture = ProxyFixture::start_with_config(config).await;
    let runtime = fixture.controller.runtime().clone();
    let first_request = connect_request(&runtime, destination, "connection-first");
    let mut first = open_tunnel(&runtime, &first_request, b"one").await;
    let mut echoed = [0_u8; 3];
    first.read_exact(&mut echoed).await.unwrap();
    fixture.events.wait_for_len(2).await;

    let second_request = connect_request(&runtime, destination, "connection-second");
    assert_rejected(&runtime, &second_request).await;

    assert_eq!(&echoed, b"one");
    drop(first);
    fixture.controller.shutdown().await.unwrap();
}
