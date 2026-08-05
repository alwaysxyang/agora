use super::{
    Arguments, AuditOutput, AuditState, FilesystemArgument, JsonCallback, TlsArgument, async_main,
    exit_status_code, parse_command, shutdown_signals, signal_exit_code,
};
use agora_core::lifecycle::shutdown::ShutdownGuard;
use agora_sandbox::callback::{
    Callback, CommandContext, Decision, EVENT_SCHEMA_VERSION, Event, EventResult, EventStatus,
    EventType, FileAccessMode, FileContext, FileEvent, FileOpenMode, NetworkContext, NetworkEvent,
    NetworkProtocol, ProcessContext, ProcessEvent, ProcessOperation, Subsystem,
};
use agora_sandbox::network::TlsMode;
use agora_sandbox::runner::FilesystemMode;
use std::net::{IpAddr, Ipv4Addr};
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

#[test]
fn filesystem_arguments_map_to_their_runtime_modes() {
    assert!(matches!(
        FilesystemArgument::default(),
        FilesystemArgument::Plain
    ));
    assert_eq!(
        FilesystemMode::from(FilesystemArgument::Encrypted),
        FilesystemMode::Encrypted
    );
    assert_eq!(
        FilesystemMode::from(FilesystemArgument::Plain),
        FilesystemMode::Plain
    );
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

fn file_event(event_type: EventType) -> FileEvent {
    FileEvent {
        schema_version: EVENT_SCHEMA_VERSION,
        event_id: "file-event".to_string(),
        occurred_at: "2026-07-29T12:00:02Z".to_string(),
        subsystem: Subsystem::Filesystem,
        event_type,
        sandbox_id: "sandbox".to_string(),
        run_id: "run".to_string(),
        trace_id: "trace-root, trace-child".to_string(),
        process: ProcessContext {
            pid: 43,
            ppid: 42,
            executable: "/bin/bash".to_string(),
        },
        file: FileContext {
            path: "/Users/example/project/input.txt".to_string(),
            mode: FileOpenMode {
                access: FileAccessMode::ReadWrite,
                create: true,
                truncate: false,
                append: true,
                exclusive: false,
            },
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
fn audit_state_writes_process_network_and_filesystem_records_to_the_same_stream() {
    let root = std::env::temp_dir().join(format!("agora-audit-events-{}", Uuid::new_v4()));
    let path = root.join("audit.jsonl");
    let mut state = AuditState::new(Some(&path)).unwrap();

    state.on_event(&Event::Process(process_event())).unwrap();
    state
        .on_event(&Event::File(file_event(EventType::FilesystemOpen)))
        .unwrap();
    state
        .on_event(&Event::File(file_event(EventType::FilesystemClose)))
        .unwrap();
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
    assert_eq!(records[1]["type"], "filesystem");
    assert_eq!(records[1]["operation"], "open");
    assert_eq!(records[1]["path"], "/Users/example/project/input.txt");
    assert_eq!(records[1]["mode"]["access"], "read_write");
    assert_eq!(records[1]["mode"]["create"], true);
    assert_eq!(records[1]["mode"]["append"], true);
    assert_eq!(records[1]["trace_id"], "trace-root, trace-child");
    assert_eq!(records[2]["type"], "filesystem");
    assert_eq!(records[2]["operation"], "close");
    assert_eq!(records[3]["type"], "network");
    assert_eq!(records[3]["trace_id"], "trace-root");
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn audit_state_reports_an_unusable_output_directory() {
    let root = std::env::temp_dir().join(format!("agora-audit-error-{}", Uuid::new_v4()));
    let blocked_parent = root.join("blocked");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(&blocked_parent, b"not a directory").unwrap();

    let error = AuditState::new(Some(&blocked_parent.join("audit.jsonl")))
        .err()
        .expect("a file cannot be used as an audit directory");
    assert!(
        error
            .to_string()
            .contains("failed to create audit directory")
    );

    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn exit_codes_and_tls_arguments_are_stable() {
    let status = Command::new("/bin/sh")
        .args(["-c", "exit 7"])
        .status()
        .unwrap();
    assert_eq!(exit_status_code(status), 7);
    assert_eq!(signal_exit_code(15), 143);
    assert_eq!(signal_exit_code(i32::MAX), u8::MAX);
    assert!(matches!(TlsMode::from(TlsArgument::Off), TlsMode::Off));
    assert!(matches!(TlsMode::from(TlsArgument::Auto), TlsMode::Auto));
    shutdown_signals(&ShutdownGuard::get()).unwrap();
}

#[tokio::test]
async fn json_callback_allows_events_after_recording_them() {
    let root = std::env::temp_dir().join(format!("agora-json-callback-{}", Uuid::new_v4()));
    let path = root.join("audit.jsonl");
    let callback = JsonCallback::new(Some(&path)).unwrap();

    assert!(matches!(
        callback.on_event(Event::Process(process_event())).await,
        Decision::Allow
    ));
    let record = std::fs::read_to_string(path).unwrap();
    assert!(record.contains("\"type\":\"process\""));
    assert!(record.contains("\"executable\":\"/usr/bin/curl\""));

    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn json_callback_allows_events_when_audit_output_fails() {
    let root = std::env::temp_dir().join(format!("agora-json-callback-error-{}", Uuid::new_v4()));
    let path = root.join("audit.jsonl");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(&path, b"").unwrap();
    let callback = JsonCallback {
        state: std::sync::Mutex::new(AuditState {
            output: AuditOutput::File(std::fs::File::open(&path).unwrap()),
        }),
    };

    assert!(matches!(
        callback.on_event(Event::Process(process_event())).await,
        Decision::Allow
    ));

    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn async_main_rejects_an_empty_encrypted_workspace_key() {
    let root = std::env::temp_dir().join(format!("agora-empty-key-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    let arguments = Arguments {
        command: Some("/bin/true".to_string()),
        subcommand: None,
        audit_file: None,
        workdir: Some(root.clone()),
        filesystem_key: Some(String::new()),
        filesystem: FilesystemArgument::Encrypted,
        tls: super::TlsArgument::Off,
        tls_ca_cert: None,
        tls_ca_key: None,
    };

    let error = async_main(arguments).await.unwrap_err();
    assert!(error.to_string().contains("key is empty"));

    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn async_main_requires_a_key_for_explicit_encrypted_mode() {
    let root = std::env::temp_dir().join(format!("agora-missing-key-{}", Uuid::new_v4()));
    let arguments = Arguments {
        command: Some("/bin/true".to_string()),
        subcommand: None,
        audit_file: None,
        workdir: Some(root.clone()),
        filesystem_key: None,
        filesystem: FilesystemArgument::Encrypted,
        tls: super::TlsArgument::Off,
        tls_ca_cert: None,
        tls_ca_key: None,
    };

    let error = async_main(arguments).await.unwrap_err();
    assert!(
        error
            .to_string()
            .contains("--filesystem-key is required with encrypted filesystem mode")
    );
    assert!(!root.join("runtime/hook").exists());
}
