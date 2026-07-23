use super::{
    ControlRequest, ControlResponse, CoverageFallback, CoverageGap, HookOperation,
    PROTOCOL_VERSION, ProcessIdentity, RouteOutcome, RouteRegistration, read_message,
    write_message,
};
use std::io::{self, Cursor};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

fn registration() -> RouteRegistration {
    RouteRegistration {
        protocol_version: PROTOCOL_VERSION,
        token: "token-1".to_string(),
        sandbox_id: "sandbox-1".to_string(),
        run_id: "run-1".to_string(),
        connection_id: "connection-1".to_string(),
        source: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 49152),
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
fn route_registration_round_trips_through_a_framed_stream() {
    let request = ControlRequest::RegisterRoute(registration());
    let mut bytes = Vec::new();
    write_message(&mut bytes, &request).unwrap();

    let decoded: ControlRequest = read_message(&mut Cursor::new(bytes)).unwrap();

    assert_eq!(decoded, request);
}

#[test]
fn coverage_gap_round_trips_with_explicit_fallback() {
    let request = ControlRequest::CoverageGap(CoverageGap {
        protocol_version: PROTOCOL_VERSION,
        token: "token-1".to_string(),
        sandbox_id: "sandbox-1".to_string(),
        run_id: "run-1".to_string(),
        connection_id: Some("connection-1".to_string()),
        destination: Some(registration().destination),
        process: registration().process,
        operation: HookOperation::Connect,
        reason: "socket was pre-bound to a non-loopback interface".to_string(),
        fallback: CoverageFallback::FailOpen,
    });
    let mut bytes = Vec::new();
    write_message(&mut bytes, &request).unwrap();

    let decoded: ControlRequest = read_message(&mut Cursor::new(bytes)).unwrap();

    assert_eq!(decoded, request);
}

#[test]
fn route_rejection_preserves_errno_and_message() {
    let response = ControlResponse::Route {
        connection_id: "connection-1".to_string(),
        outcome: RouteOutcome::Rejected,
        errno: Some(61),
        message: Some("connection refused".to_string()),
    };
    let mut bytes = Vec::new();
    write_message(&mut bytes, &response).unwrap();

    let decoded: ControlResponse = read_message(&mut Cursor::new(bytes)).unwrap();

    assert_eq!(decoded, response);
}

#[test]
fn oversized_messages_are_rejected_before_writing() {
    let request = ControlRequest::CoverageGap(CoverageGap {
        protocol_version: PROTOCOL_VERSION,
        token: "token-1".to_string(),
        sandbox_id: "sandbox-1".to_string(),
        run_id: "run-1".to_string(),
        connection_id: None,
        destination: None,
        process: registration().process,
        operation: HookOperation::Connect,
        reason: "x".repeat(20_000),
        fallback: CoverageFallback::FailOpen,
    });
    let mut bytes = Vec::new();

    let error = write_message(&mut bytes, &request).unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert!(bytes.is_empty());
}

#[test]
fn malformed_json_is_rejected_as_invalid_data() {
    let payload = b"not-json";
    let mut frame = Vec::from((payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);

    let error = read_message::<_, ControlRequest>(&mut Cursor::new(frame)).unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
}

#[test]
fn oversized_declared_frames_are_rejected_without_reading_a_body() {
    let frame = Vec::from((20_000_u32).to_be_bytes());

    let error = read_message::<_, ControlRequest>(&mut Cursor::new(frame)).unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
}
