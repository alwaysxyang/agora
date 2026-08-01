use super::{
    Arguments, AuditState, async_main, clean_executable_cache, default_hook_library,
    exit_status_code, parse_command, signal_exit_code,
};
use agora_sandbox::callback::{
    CommandContext, EVENT_SCHEMA_VERSION, Event, EventResult, EventStatus, EventType,
    NetworkContext, NetworkEvent, NetworkProtocol, ProcessContext, ProcessEvent, ProcessOperation,
    Subsystem,
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
        trace_id: "trace-root".to_string(),
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

fn process_event() -> ProcessEvent {
    ProcessEvent {
        schema_version: EVENT_SCHEMA_VERSION,
        event_id: "process-event".to_string(),
        occurred_at: "2026-07-29T12:00:01Z".to_string(),
        subsystem: Subsystem::Process,
        event_type: EventType::ProcessExecAttempt,
        sandbox_id: "sandbox".to_string(),
        run_id: "run".to_string(),
        trace_id: "trace-root, trace-child".to_string(),
        process: ProcessContext {
            pid: 43,
            ppid: 42,
            executable: "/bin/bash".to_string(),
        },
        command: CommandContext {
            executable: "/usr/bin/curl".to_string(),
            arguments: vec!["curl".to_string(), "https://example.com".to_string()],
            current_dir: "/tmp".to_string(),
            operation: ProcessOperation::PosixSpawn,
        },
        result: EventResult {
            status: EventStatus::Started,
            error_code: None,
            error_message: None,
        },
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
fn audit_state_writes_attempts_immediately_without_terminal_duplicates() {
    let root = std::env::temp_dir().join(format!("agora-audit-test-{}", Uuid::new_v4()));
    let path = root.join("nested").join("audit.jsonl");
    let mut state = AuditState::new(Some(&path)).unwrap();

    state
        .on_event(&Event::Network(event(
            EventType::NetworkConnectAttempt,
            None,
            false,
        )))
        .unwrap();
    state
        .on_event(&Event::Network(event(
            EventType::NetworkConnectDenied,
            Some("connection"),
            true,
        )))
        .unwrap();
    state
        .on_event(&Event::Network(event(
            EventType::NetworkConnectAttempt,
            Some("connection"),
            true,
        )))
        .unwrap();
    state
        .on_event(&Event::Network(event(
            EventType::NetworkConnectFailed,
            Some("connection"),
            true,
        )))
        .unwrap();

    let output = std::fs::read_to_string(&path).unwrap();
    assert_eq!(output.lines().count(), 1);
    assert!(output.contains("example.com"));
    assert!(output.contains("203.0.113.10"));
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn audit_state_writes_process_and_network_records_to_the_same_stream() {
    let root = std::env::temp_dir().join(format!("agora-audit-events-{}", Uuid::new_v4()));
    let path = root.join("audit.jsonl");
    let mut state = AuditState::new(Some(&path)).unwrap();

    state.on_event(&Event::Process(process_event())).unwrap();
    state
        .on_event(&Event::Network(event(
            EventType::NetworkConnectAttempt,
            Some("connection"),
            true,
        )))
        .unwrap();

    let records = std::fs::read_to_string(&path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(records[0]["type"], "process");
    assert_eq!(records[0]["executable"], "/usr/bin/curl");
    assert_eq!(records[0]["arguments"][0], "curl");
    assert_eq!(records[0]["arguments"][1], "https://example.com");
    assert_eq!(records[0]["trace_id"], "trace-root, trace-child");
    assert_eq!(records[1]["type"], "network");
    assert_eq!(records[1]["trace_id"], "trace-root");
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

#[test]
fn clean_reports_when_the_executable_cache_is_not_a_directory() {
    let workdir = std::env::temp_dir().join(format!("agora-clean-test-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&workdir).unwrap();
    std::fs::write(workdir.join("fs"), b"not a directory").unwrap();

    let error = clean_executable_cache(Some(&workdir)).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("failed to clean sandbox executable cache")
    );

    std::fs::remove_dir_all(workdir).unwrap();
}

#[tokio::test]
async fn async_main_reports_a_missing_hook_before_starting_a_child() {
    let arguments = Arguments {
        command: Some("/bin/true".to_string()),
        subcommand: None,
        hook_library: Some(PathBuf::from("/missing/agora-hook.dylib")),
        audit_file: None,
        workdir: None,
        tls_trust_anchor: None,
        tls: super::TlsArgument::Off,
        tls_ca_cert: None,
        tls_ca_key: None,
    };

    assert!(
        async_main(arguments)
            .await
            .unwrap_err()
            .to_string()
            .contains("hook library does not exist")
    );
}
