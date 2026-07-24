use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::OnceLock;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn hook_library() -> PathBuf {
    static HOOK: OnceLock<PathBuf> = OnceLock::new();
    HOOK.get_or_init(|| {
        let workspace = workspace_root();
        let status = Command::new(env!("CARGO"))
            .args(["build", "-p", "agora-sandbox", "--lib"])
            .current_dir(&workspace)
            .status()
            .unwrap();
        assert!(status.success());
        let target = std::env::var_os("CARGO_TARGET_DIR")
            .map(PathBuf::from)
            .map(|path| {
                if path.is_absolute() {
                    path
                } else {
                    workspace.join(path)
                }
            })
            .unwrap_or_else(|| workspace.join("target"));
        let library = target.join("debug/libagora_sandbox.dylib");
        assert!(library.is_file(), "missing {}", library.display());
        library
    })
    .clone()
}

#[test]
fn sandbox_cli_documents_only_available_options() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_agora-sandbox"))
        .arg("--help")
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("-c, --command <COMMAND>"));
    assert!(stdout.contains("--hook-library <HOOK_LIBRARY>"));
    assert!(stdout.contains("--audit-file <AUDIT_FILE>"));
    assert!(!stdout.contains("--network-enforcement"));
    assert!(!stdout.contains("--tls"));
}

#[test]
fn sandbox_cli_requires_a_command() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_agora-sandbox"))
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("--command <COMMAND>"));
}

#[test]
fn intercepted_cli_child() {
    if std::env::var_os("AGORA_SANDBOX_TEST_CLI_CHILD").is_none() {
        return;
    }

    let destination = std::env::var("AGORA_SANDBOX_TEST_DESTINATION").unwrap();
    let mut stream = TcpStream::connect(destination).unwrap();
    let request = b"GET / HTTP/1.1\r\nHost: audit.example\r\nConnection: close\r\n\r\n";
    stream.write_all(request).unwrap();
    stream.shutdown(Shutdown::Write).unwrap();
    let mut echoed = Vec::new();
    stream.read_to_end(&mut echoed).unwrap();
    assert_eq!(echoed, request);
}

#[test]
fn sandbox_cli_writes_compact_audit_to_stdout_by_default() {
    let (output, destination) = run_audited_cli(None);

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let records = audit_records(&output.stdout);
    assert_eq!(
        records.len(),
        1,
        "stdout={}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert_audit_record(&records[0], destination);
    assert!(!String::from_utf8_lossy(&output.stderr).contains("network.connect.attempt"));
}

#[test]
fn sandbox_cli_appends_compact_audit_to_the_configured_file() {
    let temp = std::env::temp_dir().join(format!("agora-sandbox-audit-{}", uuid::Uuid::new_v4()));
    let audit_file = temp.join("nested/network.jsonl");

    let (first, first_destination) = run_audited_cli(Some(&audit_file));
    let (second, second_destination) = run_audited_cli(Some(&audit_file));

    assert!(
        first.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(
        second.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&second.stderr)
    );
    assert!(audit_records(&first.stdout).is_empty());
    assert!(audit_records(&second.stdout).is_empty());
    let records = audit_records(&std::fs::read(&audit_file).unwrap());
    assert_eq!(records.len(), 2);
    assert_audit_record(&records[0], first_destination);
    assert_audit_record(&records[1], second_destination);
    std::fs::remove_dir_all(temp).unwrap();
}

fn run_audited_cli(audit_file: Option<&Path>) -> (Output, SocketAddr) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let destination = listener.local_addr().unwrap();
    let echo = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).unwrap();
        stream.write_all(&bytes).unwrap();
    });
    let test_binary = std::env::current_exe().unwrap();
    let command = format!(
        "'{}' intercepted_cli_child --exact --nocapture",
        test_binary.display()
    );
    let mut process = Command::new(env!("CARGO_BIN_EXE_agora-sandbox"));
    process
        .arg("--hook-library")
        .arg(hook_library())
        .arg("-c")
        .arg(command)
        .env("AGORA_SANDBOX_TEST_CLI_CHILD", "1")
        .env("AGORA_SANDBOX_TEST_DESTINATION", destination.to_string());
    if let Some(audit_file) = audit_file {
        process.arg("--audit-file").arg(audit_file);
    }
    let output = process.output().unwrap();

    if !output.status.success() {
        drop(TcpStream::connect(destination));
    }
    echo.join().unwrap();
    (output, destination)
}

fn audit_records(output: &[u8]) -> Vec<serde_json::Value> {
    String::from_utf8_lossy(output)
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect()
}

fn assert_audit_record(record: &serde_json::Value, destination: SocketAddr) {
    let object = record.as_object().unwrap();
    assert_eq!(object.len(), 5);
    assert!(record["access_time"].as_str().is_some());
    assert!(record["pid"].as_u64().is_some_and(|pid| pid > 0));
    assert_eq!(record["destination_ip"], destination.ip().to_string());
    assert_eq!(record["destination_port"], destination.port());
    assert_eq!(record["domain"], "audit.example");
}
