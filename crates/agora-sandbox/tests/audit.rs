use agora_sandbox::audit::{
    AUDIT_SCHEMA_VERSION, AuditCallback, AuditDecision, AuditEvent, AuditEventType, AuditMetrics,
    AuditResult, AuditResultStatus, AuditSubsystem, DomainSource, NetworkAudit, NetworkProtocol,
    NoopAuditCallback, ProcessAudit,
};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};

fn network_event() -> AuditEvent {
    AuditEvent {
        schema_version: AUDIT_SCHEMA_VERSION,
        event_id: "event-1".to_string(),
        occurred_at: "2026-07-23T12:34:56.789Z".to_string(),
        subsystem: AuditSubsystem::Network,
        event_type: AuditEventType::NetworkDomainObserved,
        sandbox_id: "sandbox-1".to_string(),
        run_id: "run-1".to_string(),
        connection_id: Some("connection-1".to_string()),
        sequence: Some(0),
        process: ProcessAudit {
            pid: 101,
            ppid: 100,
            executable: "/usr/bin/curl".to_string(),
        },
        network: Some(NetworkAudit {
            protocol: NetworkProtocol::Tcp,
            source_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            source_port: Some(49152),
            destination_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
            destination_port: 443,
            http_host: Some("example.com".to_string()),
            tls_sni: None,
            domain: Some("example.com".to_string()),
            domain_source: Some(DomainSource::HttpHost),
        }),
        tls: None,
        decision: AuditDecision::Observed,
        result: AuditResult {
            status: AuditResultStatus::Started,
            error_code: None,
            error_message: None,
        },
        metrics: Some(AuditMetrics {
            bytes_sent: 0,
            bytes_received: 0,
            duration_ms: 0,
        }),
    }
}

#[test]
fn audit_event_uses_stable_versioned_json_fields() {
    let value = serde_json::to_value(network_event()).unwrap();

    assert_eq!(value["schema_version"], 2);
    assert_eq!(value["subsystem"], "network");
    assert_eq!(value["event_type"], "network.domain.observed");
    assert_eq!(value["network"]["protocol"], "tcp");
    assert_eq!(value["network"]["destination_ip"], "203.0.113.10");
    assert_eq!(value["network"]["domain_source"], "http_host");
    assert_eq!(value["decision"], "observed");
    assert_eq!(value["result"]["status"], "started");
}

#[test]
fn closure_callback_receives_an_owned_event() {
    let received = Arc::new(Mutex::new(Vec::new()));
    let callback = {
        let received = Arc::clone(&received);
        move |event: AuditEvent| received.lock().unwrap().push(event)
    };

    callback.on_event(network_event());

    let events = received.lock().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_id, "event-1");
}

#[test]
fn noop_callback_accepts_events_without_side_effects() {
    NoopAuditCallback.on_event(network_event());
}
