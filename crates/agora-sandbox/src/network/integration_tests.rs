use super::{NetworkConfig, NetworkController, NetworkRunContext};
use crate::audit::{AuditEvent, AuditEventType, DomainSource};
use crate::protocol::{
    ControlRequest, ControlResponse, CoverageFallback, CoverageGap, HookOperation,
    PROTOCOL_VERSION, ProcessIdentity, RouteOutcome, RouteRegistration,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, UnixStream};

async fn echo_server() -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut bytes = [0_u8; 64];
        loop {
            let read = stream.read(&mut bytes).await.unwrap();
            if read == 0 {
                break;
            }
            stream.write_all(&bytes[..read]).await.unwrap();
        }
    });
    address
}

async fn send_control(socket: &std::path::Path, request: &ControlRequest) -> ControlResponse {
    let mut stream = UnixStream::connect(socket).await.unwrap();
    let payload = serde_json::to_vec(request).unwrap();
    stream
        .write_all(&(payload.len() as u32).to_be_bytes())
        .await
        .unwrap();
    stream.write_all(&payload).await.unwrap();

    let mut length = [0_u8; 4];
    stream.read_exact(&mut length).await.unwrap();
    let mut payload = vec![0_u8; u32::from_be_bytes(length) as usize];
    stream.read_exact(&mut payload).await.unwrap();
    serde_json::from_slice(&payload).unwrap()
}

#[tokio::test]
async fn registered_tcp_route_relays_bytes_and_emits_ordered_audit_events() {
    let destination = echo_server().await;
    let events = Arc::new(Mutex::new(Vec::<AuditEvent>::new()));
    let callback = {
        let events = Arc::clone(&events);
        move |event| events.lock().unwrap().push(event)
    };
    let controller = NetworkController::start(
        NetworkConfig::default(),
        NetworkRunContext::new("sandbox-1", "run-1"),
        callback,
    )
    .await
    .unwrap();
    let runtime = controller.runtime();
    let socket = TcpSocket::new_v4().unwrap();
    socket
        .bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .unwrap();
    let source = socket.local_addr().unwrap();
    let registration = RouteRegistration {
        protocol_version: PROTOCOL_VERSION,
        token: runtime.token().to_string(),
        sandbox_id: "sandbox-1".to_string(),
        run_id: "run-1".to_string(),
        connection_id: "connection-1".to_string(),
        source,
        destination,
        process: ProcessIdentity {
            pid: std::process::id(),
            ppid: 1,
            executable: "/tmp/test-client".to_string(),
        },
        operation: HookOperation::Connect,
    };

    let response = send_control(
        runtime.control_socket(),
        &ControlRequest::RegisterRoute(registration),
    )
    .await;
    assert!(matches!(
        response,
        ControlResponse::Route {
            outcome: RouteOutcome::Accepted,
            ..
        }
    ));

    let mut client = socket.connect(runtime.proxy_ipv4()).await.unwrap();
    client.write_all(b"hello").await.unwrap();
    let mut echoed = [0_u8; 5];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"hello");
    client.shutdown().await.unwrap();

    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            if events.lock().unwrap().len() >= 3 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    let event_types = events
        .lock()
        .unwrap()
        .iter()
        .map(|event| event.event_type)
        .collect::<Vec<_>>();
    assert_eq!(
        event_types,
        vec![
            AuditEventType::NetworkConnectAttempt,
            AuditEventType::NetworkConnectEstablished,
            AuditEventType::NetworkConnectionClosed,
        ]
    );

    controller.shutdown().await.unwrap();
}

#[tokio::test]
async fn http_host_is_audited_from_relayed_payload() {
    let destination = echo_server().await;
    let events = Arc::new(Mutex::new(Vec::<AuditEvent>::new()));
    let callback = {
        let events = Arc::clone(&events);
        move |event| events.lock().unwrap().push(event)
    };
    let controller = NetworkController::start(
        NetworkConfig::default(),
        NetworkRunContext::new("sandbox-1", "run-1"),
        callback,
    )
    .await
    .unwrap();
    let runtime = controller.runtime();
    let socket = TcpSocket::new_v4().unwrap();
    socket
        .bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .unwrap();
    let source = socket.local_addr().unwrap();
    let response = send_control(
        runtime.control_socket(),
        &ControlRequest::RegisterRoute(RouteRegistration {
            protocol_version: PROTOCOL_VERSION,
            token: runtime.token().to_string(),
            sandbox_id: "sandbox-1".to_string(),
            run_id: "run-1".to_string(),
            connection_id: "connection-http".to_string(),
            source,
            destination,
            process: ProcessIdentity {
                pid: std::process::id(),
                ppid: 1,
                executable: "/tmp/test-client".to_string(),
            },
            operation: HookOperation::Connect,
        }),
    )
    .await;
    assert!(matches!(
        response,
        ControlResponse::Route {
            outcome: RouteOutcome::Accepted,
            ..
        }
    ));

    let request = b"GET / HTTP/1.1\r\nHost: Audit.Example:8080\r\n\r\n";
    let mut client = socket.connect(runtime.proxy_ipv4()).await.unwrap();
    client.write_all(request).await.unwrap();
    let mut echoed = vec![0_u8; request.len()];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(echoed, request);
    client.shutdown().await.unwrap();

    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            let complete = {
                let events = events.lock().unwrap();
                let domain_observed = events
                    .iter()
                    .any(|event| event.event_type == AuditEventType::NetworkDomainObserved);
                let connection_closed = events
                    .iter()
                    .any(|event| event.event_type == AuditEventType::NetworkConnectionClosed);
                domain_observed && connection_closed
            };
            if complete {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    {
        let events = events.lock().unwrap();
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
    }

    controller.shutdown().await.unwrap();
}

#[tokio::test]
async fn invalid_control_token_is_rejected_without_audit_events() {
    let events = Arc::new(Mutex::new(Vec::<AuditEvent>::new()));
    let callback = {
        let events = Arc::clone(&events);
        move |event| events.lock().unwrap().push(event)
    };
    let controller = NetworkController::start(
        NetworkConfig::default(),
        NetworkRunContext::new("sandbox-1", "run-1"),
        callback,
    )
    .await
    .unwrap();
    let runtime = controller.runtime();
    let mut registration = RouteRegistration {
        protocol_version: PROTOCOL_VERSION,
        token: "wrong-token".to_string(),
        sandbox_id: "sandbox-1".to_string(),
        run_id: "run-1".to_string(),
        connection_id: "connection-1".to_string(),
        source: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 49152),
        destination: echo_server().await,
        process: ProcessIdentity {
            pid: std::process::id(),
            ppid: 1,
            executable: "/tmp/test-client".to_string(),
        },
        operation: HookOperation::Connect,
    };

    let response = send_control(
        runtime.control_socket(),
        &ControlRequest::RegisterRoute(registration.clone()),
    )
    .await;
    assert!(matches!(response, ControlResponse::ProtocolRejected { .. }));
    assert!(events.lock().unwrap().is_empty());

    registration.protocol_version += 1;
    registration.token = runtime.token().to_string();
    let response = send_control(
        runtime.control_socket(),
        &ControlRequest::RegisterRoute(registration),
    )
    .await;
    assert!(matches!(response, ControlResponse::ProtocolRejected { .. }));
    assert!(events.lock().unwrap().is_empty());

    controller.shutdown().await.unwrap();
}

#[tokio::test]
async fn upstream_failure_is_rejected_and_audited() {
    let unavailable = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap()
        .local_addr()
        .unwrap();
    let events = Arc::new(Mutex::new(Vec::<AuditEvent>::new()));
    let callback = {
        let events = Arc::clone(&events);
        move |event| events.lock().unwrap().push(event)
    };
    let controller = NetworkController::start(
        NetworkConfig::default(),
        NetworkRunContext::new("sandbox-1", "run-1"),
        callback,
    )
    .await
    .unwrap();
    let runtime = controller.runtime();
    let response = send_control(
        runtime.control_socket(),
        &ControlRequest::RegisterRoute(RouteRegistration {
            protocol_version: PROTOCOL_VERSION,
            token: runtime.token().to_string(),
            sandbox_id: "sandbox-1".to_string(),
            run_id: "run-1".to_string(),
            connection_id: "connection-failed".to_string(),
            source: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 49155),
            destination: unavailable,
            process: ProcessIdentity {
                pid: std::process::id(),
                ppid: 1,
                executable: "/tmp/test-client".to_string(),
            },
            operation: HookOperation::Connect,
        }),
    )
    .await;

    assert!(matches!(
        response,
        ControlResponse::Route {
            outcome: RouteOutcome::Rejected,
            ..
        }
    ));
    assert_eq!(
        events
            .lock()
            .unwrap()
            .iter()
            .map(|event| event.event_type)
            .collect::<Vec<_>>(),
        vec![
            AuditEventType::NetworkConnectAttempt,
            AuditEventType::NetworkConnectFailed,
        ]
    );

    controller.shutdown().await.unwrap();
}

#[tokio::test]
async fn coverage_gap_is_delivered_to_the_callback() {
    let events = Arc::new(Mutex::new(Vec::<AuditEvent>::new()));
    let callback = {
        let events = Arc::clone(&events);
        move |event| events.lock().unwrap().push(event)
    };
    let controller = NetworkController::start(
        NetworkConfig::default(),
        NetworkRunContext::new("sandbox-1", "run-1"),
        callback,
    )
    .await
    .unwrap();
    let runtime = controller.runtime();
    let response = send_control(
        runtime.control_socket(),
        &ControlRequest::CoverageGap(CoverageGap {
            protocol_version: PROTOCOL_VERSION,
            token: runtime.token().to_string(),
            sandbox_id: "sandbox-1".to_string(),
            run_id: "run-1".to_string(),
            connection_id: Some("connection-gap".to_string()),
            destination: Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 20)),
                80,
            )),
            process: ProcessIdentity {
                pid: std::process::id(),
                ppid: 1,
                executable: "/tmp/test-client".to_string(),
            },
            operation: HookOperation::Connect,
            reason: "unsupported pre-bound socket".to_string(),
            fallback: CoverageFallback::FailOpen,
        }),
    )
    .await;

    assert_eq!(response, ControlResponse::CoverageGapRecorded);
    {
        let events = events.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, AuditEventType::NetworkCoverageGap);
        assert_eq!(
            events[0].result.error_code.as_deref(),
            Some("interception_coverage_gap")
        );
    }

    let socket_path = runtime.control_socket().to_path_buf();
    controller.shutdown().await.unwrap();
    assert!(!socket_path.exists());
}
