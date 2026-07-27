use agora_sandbox::callback::{
    BasicAuth, Callback, Decision, DomainSource, EVENT_SCHEMA_VERSION, EventMetrics, EventResult,
    EventStatus, EventType, HttpProxy, NetworkContext, NetworkEvent, NetworkProtocol, NoopCallback,
    ProcessContext, Proxy, Redact, Subsystem,
};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};

fn network_event() -> NetworkEvent {
    NetworkEvent {
        schema_version: EVENT_SCHEMA_VERSION,
        event_id: "event-1".to_string(),
        occurred_at: "2026-07-23T12:34:56.789Z".to_string(),
        subsystem: Subsystem::Network,
        event_type: EventType::NetworkConnectAttempt,
        sandbox_id: "sandbox-1".to_string(),
        run_id: "run-1".to_string(),
        connection_id: Some("connection-1".to_string()),
        sequence: Some(0),
        process: ProcessContext {
            pid: 101,
            ppid: 100,
            executable: "/usr/bin/curl".to_string(),
        },
        network: Some(NetworkContext {
            protocol: NetworkProtocol::Tcp,
            destination_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
            destination_port: 443,
            http_host: Some("example.com".to_string()),
            tls_sni: None,
            domain: Some("example.com".to_string()),
            domain_source: Some(DomainSource::HttpHost),
        }),
        tls: None,
        decision: None,
        result: EventResult {
            status: EventStatus::Started,
            error_code: None,
            error_message: None,
        },
        metrics: Some(EventMetrics {
            bytes_sent: 0,
            bytes_received: 0,
            duration_ms: 0,
        }),
    }
}

#[test]
fn callback_event_uses_stable_versioned_json_fields() {
    let event = network_event();
    let value = serde_json::to_value(event.redacted()).unwrap();

    assert_eq!(value["schema_version"], 5);
    assert_eq!(value["subsystem"], "network");
    assert_eq!(value["event_type"], "network.connect.attempt");
    assert_eq!(value["network"]["protocol"], "tcp");
    assert_eq!(value["network"]["destination_ip"], "203.0.113.10");
    assert!(value["network"].get("source_ip").is_none());
    assert!(value["network"].get("source_port").is_none());
    assert_eq!(value["network"]["domain_source"], "http_host");
    assert!(value["decision"].is_null());
    assert_eq!(value["result"]["status"], "started");
}

#[test]
fn proxy_decision_is_redacted_before_serialization_and_debug_output() {
    let mut event = network_event();
    event.decision = Some(Decision::Proxy {
        proxy: Proxy::Http(HttpProxy {
            address: "proxy.example:8080".to_string(),
            basic_auth: Some(BasicAuth {
                username: "alice".to_string(),
                password: "secret-password".to_string(),
            }),
        }),
    });

    let json = serde_json::to_string(&event.redacted()).unwrap();
    assert!(json.contains("proxy.example:8080"));
    assert!(json.contains("alice"));
    assert!(json.contains("[redacted]"));
    assert!(!json.contains("secret-password"));

    let debug = format!("{:?}", event.decision.as_ref().unwrap());
    assert!(debug.contains("[redacted]"));
    assert!(!debug.contains("secret-password"));
}

#[tokio::test]
async fn closure_callback_receives_an_owned_event() {
    let received = Arc::new(Mutex::new(Vec::new()));
    let callback = {
        let received = Arc::clone(&received);
        move |event: NetworkEvent| {
            received.lock().unwrap().push(event);
            std::future::ready(Decision::Allow)
        }
    };

    assert_eq!(callback.on_event(network_event()).await, Decision::Allow);

    let events = received.lock().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_id, "event-1");
}

#[tokio::test]
async fn noop_callback_allows_events_without_side_effects() {
    assert_eq!(
        NoopCallback.on_event(network_event()).await,
        Decision::Allow
    );
}
