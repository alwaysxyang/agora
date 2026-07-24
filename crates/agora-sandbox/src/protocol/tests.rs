use super::{
    ConnectRequest, HookOperation, PROTOCOL_VERSION, ProcessIdentity, encode_connect_request,
    parse_connect_request_prefix,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

fn connect_request() -> ConnectRequest {
    ConnectRequest {
        protocol_version: PROTOCOL_VERSION,
        token: "token-1".to_string(),
        connection_id: "connection-1".to_string(),
        destination: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), 443),
        process: ProcessIdentity {
            pid: 101,
            ppid: 100,
            executable: "/usr/bin/curl".to_string(),
        },
        operation: HookOperation::Connect,
    }
}

#[test]
fn connect_request_prefix_preserves_trailing_tunnel_bytes() {
    let request = connect_request();
    let mut encoded = encode_connect_request(&request).unwrap();
    encoded.extend_from_slice(b"hello");

    let (parsed, consumed) = parse_connect_request_prefix(&encoded).unwrap().unwrap();

    assert_eq!(parsed, request);
    assert_eq!(&encoded[consumed..], b"hello");
}

fn split_request(message: &[u8]) -> (&[u8], &[u8]) {
    let boundary = message
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
        .unwrap();
    message.split_at(boundary)
}

#[test]
fn connect_request_round_trips_through_http_headers() {
    let request = connect_request();
    let encoded = encode_connect_request(&request).unwrap();
    let (head, body) = split_request(&encoded);

    assert!(head.starts_with(b"CONNECT 203.0.113.10:443 HTTP/1.1\r\n"));
    assert!(
        !head
            .windows(b"Agora-Mode".len())
            .any(|window| window == b"Agora-Mode")
    );
    assert!(
        !head
            .windows(b"Agora-Run-Id".len())
            .any(|window| window == b"Agora-Run-Id")
    );
    assert!(
        !head
            .windows(b"Agora-Sandbox-Id".len())
            .any(|window| window == b"Agora-Sandbox-Id")
    );
    assert!(
        head.windows(b"Proxy-Authorization: Bearer token-1".len())
            .any(|window| window == b"Proxy-Authorization: Bearer token-1")
    );
    assert!(body.is_empty());
    let (parsed, consumed) = parse_connect_request_prefix(head).unwrap().unwrap();
    assert_eq!(consumed, head.len());
    assert_eq!(parsed, request);
}

#[test]
fn basic_authorization_is_rejected() {
    let request = encode_connect_request(&connect_request()).unwrap();
    let request = String::from_utf8(request)
        .unwrap()
        .replace("Bearer token-1", "Basic token-1");
    let (head, body) = split_request(request.as_bytes());

    assert!(body.is_empty());
    let error = parse_connect_request_prefix(head).unwrap_err();

    assert!(error.to_string().contains("Proxy-Authorization"));
}

#[test]
fn connect_host_must_match_the_target() {
    let request = encode_connect_request(&connect_request()).unwrap();
    let request = String::from_utf8(request)
        .unwrap()
        .replace("Host: 203.0.113.10:443", "Host: 203.0.113.11:443");
    let (head, body) = split_request(request.as_bytes());

    assert!(body.is_empty());
    let error = parse_connect_request_prefix(head).unwrap_err();

    assert!(error.to_string().contains("Host does not match"));
}
