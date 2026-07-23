mod support;

use agora_sandbox::audit::{AuditEventType, DomainSource};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use support::{
    PROTOCOL_VERSION, ProxyFixture, TestConnectRequest, echo_server, open_tunnel, send_coverage_gap,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[tokio::test]
async fn connect_request_relays_bytes_and_emits_ordered_audit_events() {
    let destination = echo_server().await;
    let fixture = ProxyFixture::start().await;
    let runtime = fixture.controller.runtime();
    let request = TestConnectRequest::new(runtime, destination, "connection-1");
    let (mut client, response) = open_tunnel(runtime, &request).await;
    let source = client.local_addr().unwrap();

    assert_eq!(response.status, 200);
    client.write_all(b"hello").await.unwrap();
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
    assert_eq!(network.source_ip, Some(source.ip()));
    assert_eq!(network.source_port, Some(source.port()));

    fixture.controller.shutdown().await.unwrap();
}

#[tokio::test]
async fn server_first_bytes_follow_the_connect_response() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let destination = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        stream.write_all(b"banner").await.unwrap();
    });
    let fixture = ProxyFixture::start().await;
    let runtime = fixture.controller.runtime();
    let request = TestConnectRequest::new(runtime, destination, "connection-banner");

    let (mut client, response) = open_tunnel(runtime, &request).await;
    let mut banner = [0_u8; 6];
    client.read_exact(&mut banner).await.unwrap();

    assert_eq!(response.status, 200);
    assert_eq!(&banner, b"banner");
    drop(client);
    fixture.controller.shutdown().await.unwrap();
}

#[tokio::test]
async fn http_host_is_audited_from_relayed_payload() {
    let destination = echo_server().await;
    let fixture = ProxyFixture::start().await;
    let runtime = fixture.controller.runtime();
    let connect = TestConnectRequest::new(runtime, destination, "connection-http");
    let (mut client, response) = open_tunnel(runtime, &connect).await;
    assert_eq!(response.status, 200);

    let request = b"GET / HTTP/1.1\r\nHost: Audit.Example:8080\r\n\r\n";
    client.write_all(request).await.unwrap();
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
async fn invalid_credentials_version_and_run_are_rejected_without_audit_events() {
    let fixture = ProxyFixture::start().await;
    let runtime = fixture.controller.runtime();
    let destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9);

    let mut request = TestConnectRequest::new(runtime, destination, "connection-auth");
    request.token = "wrong-token".to_string();
    assert_eq!(open_tunnel(runtime, &request).await.1.status, 407);

    request.token = runtime.token().to_string();
    request.protocol_version += 1;
    assert_eq!(open_tunnel(runtime, &request).await.1.status, 505);

    request.protocol_version = PROTOCOL_VERSION;
    request.run_id = "another-run".to_string();
    assert_eq!(open_tunnel(runtime, &request).await.1.status, 403);
    assert!(fixture.events.snapshot().is_empty());

    fixture.controller.shutdown().await.unwrap();
}

#[tokio::test]
async fn upstream_failure_is_rejected_and_audited() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let unavailable = listener.local_addr().unwrap();
    drop(listener);
    let fixture = ProxyFixture::start().await;
    let runtime = fixture.controller.runtime();
    let request = TestConnectRequest::new(runtime, unavailable, "connection-failed");

    let (_, response) = open_tunnel(runtime, &request).await;

    assert_eq!(response.status, 502);
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
async fn coverage_gap_is_delivered_over_the_proxy_listener() {
    let fixture = ProxyFixture::start().await;
    let destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 20)), 80);

    let response = send_coverage_gap(fixture.controller.runtime(), destination).await;

    assert_eq!(response.status, 204);
    let events = fixture.events.snapshot();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_type, AuditEventType::NetworkCoverageGap);
    assert_eq!(
        events[0].result.error_code.as_deref(),
        Some("interception_coverage_gap"),
    );

    fixture.controller.shutdown().await.unwrap();
}
