use super::{
    Arguments, AuditState, async_main, default_hook_library, exit_status_code, parse_command,
    signal_exit_code,
};
use agora_sandbox::callback::{
    EVENT_SCHEMA_VERSION, EventResult, EventStatus, EventType, NetworkContext, NetworkEvent,
    NetworkProtocol, ProcessContext, Subsystem,
};
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::process::Command;
use uuid::Uuid;

fn event(event_type: EventType, connection_id: Option<&str>, network: bool) -> NetworkEvent {
    NetworkEvent {
        schema_version: EVENT_SCHEMA_VERSION,
        event_id: "event".to_string(),
        occurred_at: "2026-07-29T12:00:00Z".to_string(),
        subsystem: Subsystem::Network,
        event_type,
        sandbox_id: "sandbox".to_string(),
        run_id: "run".to_string(),
        connection_id: connection_id.map(ToString::to_string),
        sequence: Some(0),
        process: ProcessContext {
            pid: 42,
            ppid: 1,
            executable: "/usr/bin/curl".to_string(),
        },
        network: network.then_some(NetworkContext {
            protocol: NetworkProtocol::Tcp,
            destination_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
            destination_port: 443,
            http_host: None,
            tls_sni: None,
            domain: Some("example.com".to_string()),
            domain_source: None,
        }),
        tls: None,
        decision: None,
        result: EventResult {
            status: EventStatus::Started,
            error_code: None,
            error_message: None,
        },
        metrics: None,
    }
}

#[test]
fn command_parser_rejects_empty_input_and_preserves_quoted_arguments() {
    assert!(
        parse_command(" ")
            .unwrap_err()
            .to_string()
            .contains("contain a program")
    );
    let command = parse_command("/bin/echo 'hello world'").unwrap();
    let debug = format!("{command:?}");
    assert!(debug.contains("/bin/echo"));
    assert!(debug.contains("hello world"));
}

#[test]
fn audit_state_ignores_incomplete_events_and_writes_terminal_fallbacks() {
    let root = std::env::temp_dir().join(format!("agora-audit-test-{}", Uuid::new_v4()));
    let path = root.join("nested").join("audit.jsonl");
    let mut state = AuditState::new(Some(&path)).unwrap();

    state
        .on_event(&event(EventType::NetworkConnectAttempt, None, true))
        .unwrap();
    state
        .on_event(&event(
            EventType::NetworkConnectDenied,
            Some("connection"),
            false,
        ))
        .unwrap();
    state
        .on_event(&event(
            EventType::NetworkConnectFailed,
            Some("connection"),
            true,
        ))
        .unwrap();

    let output = std::fs::read_to_string(&path).unwrap();
    assert!(output.contains("example.com"));
    assert!(output.contains("203.0.113.10"));
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn default_paths_and_exit_codes_are_stable() {
    assert_eq!(
        default_hook_library().unwrap().file_name().unwrap(),
        "libagora_sandbox.dylib"
    );
    let status = Command::new("/bin/sh")
        .args(["-c", "exit 7"])
        .status()
        .unwrap();
    assert_eq!(exit_status_code(status), 7);
    assert_eq!(signal_exit_code(15), 143);
    assert_eq!(signal_exit_code(i32::MAX), u8::MAX);
}

#[tokio::test]
async fn async_main_reports_a_missing_hook_before_starting_a_child() {
    let arguments = Arguments {
        command: "/bin/true".to_string(),
        hook_library: Some(PathBuf::from("/missing/agora-hook.dylib")),
        audit_file: None,
    };

    assert!(
        async_main(arguments)
            .await
            .unwrap_err()
            .to_string()
            .contains("hook library does not exist")
    );
}
