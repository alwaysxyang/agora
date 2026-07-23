use super::{
    ConnectRequest, CoverageFallback, CoverageGap, HookOperation, PROTOCOL_VERSION,
    ProcessIdentity, ProxyRequest, encode_connect_request, encode_coverage_gap_request,
    encode_proxy_response, parse_proxy_request, parse_proxy_response, request_body_length,
};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

fn connect_request() -> ConnectRequest {
    ConnectRequest {
        protocol_version: PROTOCOL_VERSION,
        token: "token-1".to_string(),
        sandbox_id: "sandbox-1".to_string(),
        run_id: "run-1".to_string(),
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

fn coverage_gap() -> CoverageGap {
    let request = connect_request();
    CoverageGap {
        protocol_version: request.protocol_version,
        token: request.token,
        sandbox_id: request.sandbox_id,
        run_id: request.run_id,
        connection_id: Some(request.connection_id),
        destination: Some(request.destination),
        process: request.process,
        operation: request.operation,
        reason: "interception setup failed".to_string(),
        fallback: CoverageFallback::FailOpen,
    }
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
        head.windows(b"Proxy-Authorization: Bearer token-1".len())
            .any(|window| window == b"Proxy-Authorization: Bearer token-1")
    );
    assert_eq!(
        parse_proxy_request(head, body).unwrap(),
        ProxyRequest::Connect(request)
    );
}

#[test]
fn coverage_gap_round_trips_through_http_json_request() {
    let gap = coverage_gap();
    let encoded = encode_coverage_gap_request(&gap).unwrap();
    let (head, body) = split_request(&encoded);

    assert!(head.starts_with(b"POST /_agora/coverage-gap HTTP/1.1\r\n"));
    assert_eq!(request_body_length(head).unwrap(), body.len());
    assert_eq!(
        parse_proxy_request(head, body).unwrap(),
        ProxyRequest::CoverageGap(gap),
    );
}

#[test]
fn proxy_response_preserves_status_and_errno() {
    let accepted = encode_proxy_response(200, None);
    let rejected = encode_proxy_response(502, Some(61));

    assert_eq!(parse_proxy_response(&accepted).unwrap().status, 200);
    let rejected = parse_proxy_response(&rejected).unwrap();
    assert_eq!(rejected.status, 502);
    assert_eq!(rejected.errno, Some(61));
}

#[test]
fn basic_authorization_is_rejected() {
    let request = encode_connect_request(&connect_request()).unwrap();
    let request = String::from_utf8(request)
        .unwrap()
        .replace("Bearer token-1", "Basic token-1");
    let (head, body) = split_request(request.as_bytes());

    let error = parse_proxy_request(head, body).unwrap_err();

    assert_eq!(error.status(), 407);
}

#[test]
fn connect_host_must_match_the_target() {
    let request = encode_connect_request(&connect_request()).unwrap();
    let request = String::from_utf8(request)
        .unwrap()
        .replace("Host: 203.0.113.10:443", "Host: 203.0.113.11:443");
    let (head, body) = split_request(request.as_bytes());

    let error = parse_proxy_request(head, body).unwrap_err();

    assert_eq!(error.status(), 400);
}

#[test]
fn oversized_coverage_gap_is_rejected_before_writing() {
    let mut gap = coverage_gap();
    gap.reason = "x".repeat(20_000);

    let error = encode_coverage_gap_request(&gap).unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
}

#[test]
fn malformed_coverage_gap_json_is_rejected() {
    let encoded = encode_coverage_gap_request(&coverage_gap()).unwrap();
    let (head, _) = split_request(&encoded);
    let body = b"not-json";
    let head = String::from_utf8(head.to_vec()).unwrap().replace(
        &format!("Content-Length: {}", request_body_length(head).unwrap()),
        &format!("Content-Length: {}", body.len()),
    );

    let error = parse_proxy_request(head.as_bytes(), body).unwrap_err();

    assert_eq!(error.status(), 400);
}
