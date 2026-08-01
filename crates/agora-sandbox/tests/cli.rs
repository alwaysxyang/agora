#[cfg(target_os = "macos")]
use base64::Engine;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
#[cfg(target_os = "macos")]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

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

fn cli_workdir() -> PathBuf {
    workspace_root().join("target/agora-sandbox-test-cache/cli")
}

fn write_checksum_manifest(directory: &Path, files: &[(&str, &str)]) {
    let files = files
        .iter()
        .map(|(path, checksum)| ((*path).to_string(), (*checksum).to_string()))
        .collect::<std::collections::BTreeMap<_, _>>();
    let manifest = serde_json::json!({
        "version": 1,
        "files": files,
    });
    std::fs::write(
        directory.join("checksums.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
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
    assert!(stdout.contains("--workdir <WORKDIR>"));
    assert!(stdout.contains("--tls-trust-anchor <TLS_TRUST_ANCHOR>"));
    assert!(stdout.contains("--tls <TLS>"));
    assert!(stdout.contains("[possible values: off, auto]"));
    assert!(!stdout.contains("off, auto, require"));
    assert!(stdout.contains("--tls-ca-cert <TLS_CA_CERT>"));
    assert!(stdout.contains("--tls-ca-key <TLS_CA_KEY>"));
    assert!(stdout.contains("<workdir>/ca/ca.crt"));
    assert!(stdout.contains("<workdir>/ca/ca.key"));
    assert!(!stdout.contains("--network-enforcement"));
    assert!(stdout.contains("clean"));
    let removed = std::process::Command::new(env!("CARGO_BIN_EXE_agora-sandbox"))
        .args(["tls", "generate"])
        .output()
        .unwrap();
    assert!(!removed.status.success());
}

#[test]
fn sandbox_cli_clean_removes_only_the_selected_executable_cache() {
    let workdir = std::env::temp_dir().join(format!(
        "agora-sandbox-cli-clean-test-{}",
        uuid::Uuid::new_v4()
    ));
    let cache = workdir.join("fs");
    std::fs::create_dir_all(cache.join("usr/bin")).unwrap();
    std::fs::write(cache.join("usr/bin/curl"), b"prepared executable").unwrap();
    std::fs::write(cache.join("usr/bin/user-file"), b"overlay content").unwrap();
    write_checksum_manifest(&cache.join("usr/bin"), &[("/usr/bin/curl", "source-md5")]);
    std::fs::create_dir_all(cache.join("Users/bytedance/project")).unwrap();
    std::fs::write(
        cache.join("Users/bytedance/project/output.txt"),
        b"overlay output",
    )
    .unwrap();
    std::fs::create_dir_all(workdir.join("root")).unwrap();
    std::fs::write(workdir.join("root/legacy"), b"legacy executable").unwrap();
    std::fs::create_dir_all(workdir.join("ca")).unwrap();
    std::fs::write(workdir.join("ca/ca.crt"), b"certificate").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_agora-sandbox"))
        .arg("clean")
        .arg("--workdir")
        .arg(&workdir)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(cache.is_dir());
    assert!(!cache.join("usr/bin/curl").exists());
    assert!(!cache.join("usr/bin/checksums.json").exists());
    assert!(cache.join("usr/bin/user-file").is_file());
    assert!(cache.join("Users/bytedance/project/output.txt").is_file());
    assert!(workdir.join("root/legacy").is_file());
    assert!(workdir.join("ca/ca.crt").is_file());
    std::fs::remove_dir_all(workdir).unwrap();
}

#[test]
fn sandbox_cli_clean_uses_the_default_cache_and_is_idempotent() {
    let home = std::env::temp_dir().join(format!(
        "agora-sandbox-cli-clean-home-test-{}",
        uuid::Uuid::new_v4()
    ));
    let workdir = home.join(".agora-sandbox");
    let cache = workdir.join("fs");
    std::fs::create_dir_all(cache.join("bin")).unwrap();
    std::fs::write(cache.join("bin/tool"), b"prepared executable").unwrap();
    write_checksum_manifest(&cache.join("bin"), &[("/bin/tool", "tool-md5")]);
    std::fs::create_dir_all(cache.join("usr/bin")).unwrap();
    std::fs::write(cache.join("usr/bin/curl"), b"prepared curl").unwrap();
    write_checksum_manifest(&cache.join("usr/bin"), &[("/usr/bin/curl", "curl-md5")]);
    std::fs::create_dir_all(workdir.join("ca")).unwrap();
    std::fs::write(workdir.join("ca/ca.crt"), b"certificate").unwrap();

    for _ in 0..2 {
        let output = Command::new(env!("CARGO_BIN_EXE_agora-sandbox"))
            .arg("clean")
            .env("HOME", &home)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "stdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    assert!(cache.is_dir());
    assert!(!cache.join("bin").exists());
    assert!(!cache.join("usr").exists());
    assert!(workdir.join("ca/ca.crt").is_file());
    std::fs::remove_dir_all(home).unwrap();
}

#[test]
fn sandbox_cli_clean_rejects_manifest_entries_from_another_directory() {
    let workdir = std::env::temp_dir().join(format!(
        "agora-sandbox-cli-clean-invalid-test-{}",
        uuid::Uuid::new_v4()
    ));
    let cache = workdir.join("fs");
    std::fs::create_dir_all(cache.join("usr/bin")).unwrap();
    std::fs::create_dir_all(cache.join("bin")).unwrap();
    std::fs::write(cache.join("bin/tool"), b"must remain").unwrap();
    write_checksum_manifest(&cache.join("bin"), &[("/bin/tool", "valid-entry")]);
    write_checksum_manifest(
        &cache.join("usr/bin"),
        &[("/bin/tool", "unexpected-directory")],
    );

    let output = Command::new(env!("CARGO_BIN_EXE_agora-sandbox"))
        .arg("clean")
        .arg("--workdir")
        .arg(&workdir)
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(cache.join("bin/tool").is_file());
    assert!(cache.join("bin/checksums.json").is_file());
    assert!(cache.join("usr/bin/checksums.json").is_file());
    std::fs::remove_dir_all(workdir).unwrap();
}

#[cfg(target_os = "macos")]
#[test]
fn sandbox_cli_auto_generates_reuses_and_replaces_a_configured_tls_ca() {
    let directory = std::env::temp_dir().join(format!(
        "agora-sandbox-cli-auto-ca-test-{}",
        uuid::Uuid::new_v4()
    ));
    let certificate = directory.join("nested/ca.pem");
    let private_key = directory.join("nested/ca-key.pem");
    let workdir = directory.join("workdir");

    let run = || {
        Command::new(env!("CARGO_BIN_EXE_agora-sandbox"))
            .arg("--hook-library")
            .arg(hook_library())
            .arg("--workdir")
            .arg(&workdir)
            .args(["--tls", "auto", "--tls-ca-cert"])
            .arg(&certificate)
            .arg("--tls-ca-key")
            .arg(&private_key)
            .args(["-c", "/usr/bin/true"])
            .output()
            .unwrap()
    };

    let generated = run();
    assert!(
        generated.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&generated.stdout),
        String::from_utf8_lossy(&generated.stderr)
    );
    let certificate_pem = std::fs::read_to_string(&certificate).unwrap();
    let private_key_pem = std::fs::read_to_string(&private_key).unwrap();
    assert!(certificate_pem.starts_with("-----BEGIN CERTIFICATE-----"));
    assert!(private_key_pem.starts_with("-----BEGIN PRIVATE KEY-----"));
    assert_eq!(
        certificate.metadata().unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        private_key.metadata().unwrap().permissions().mode() & 0o777,
        0o600
    );

    let reused = run();
    assert!(
        reused.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&reused.stdout),
        String::from_utf8_lossy(&reused.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(&certificate).unwrap(),
        certificate_pem
    );
    assert_eq!(
        std::fs::read_to_string(&private_key).unwrap(),
        private_key_pem
    );

    std::fs::remove_file(&private_key).unwrap();
    let regenerated = run();
    assert!(
        regenerated.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&regenerated.stdout),
        String::from_utf8_lossy(&regenerated.stderr)
    );
    assert_ne!(
        std::fs::read_to_string(&certificate).unwrap(),
        certificate_pem
    );
    assert_ne!(
        std::fs::read_to_string(&private_key).unwrap(),
        private_key_pem
    );
    std::fs::remove_dir_all(directory).unwrap();
}

#[cfg(target_os = "macos")]
#[test]
fn sandbox_cli_runs_an_interactive_bash_in_a_terminal() {
    let mut process = Command::new("/usr/bin/script");
    process
        .arg("-q")
        .arg("/dev/null")
        .arg(env!("CARGO_BIN_EXE_agora-sandbox"))
        .arg("--hook-library")
        .arg(hook_library())
        .arg("--workdir")
        .arg(cli_workdir())
        .arg("-c")
        .arg("/bin/bash")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = process.spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"echo AGORA_INTERACTIVE_BASH_OK\nexit\n")
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            panic!("interactive sandbox Bash did not exit before the deadline");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let output = child.wait_with_output().unwrap();

    assert!(
        status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("AGORA_INTERACTIVE_BASH_OK"),
        "stdout={}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn sandbox_cli_requires_both_tls_ca_files() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_agora-sandbox"))
        .args([
            "--tls",
            "auto",
            "--tls-ca-cert",
            "/tmp/ca.pem",
            "-c",
            "/bin/true",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--tls-ca-key"));
}

#[test]
fn sandbox_cli_requires_a_command() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_agora-sandbox"))
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("--command <COMMAND>"));
}

#[cfg(target_os = "macos")]
#[test]
fn sandbox_cli_injects_the_configured_tls_trust_anchor() {
    let directory = std::env::temp_dir().join(format!(
        "agora-sandbox-cli-trust-anchor-test-{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let anchor = directory.join("ca.der");
    let leaf = directory.join("leaf.der");
    std::fs::write(
        &anchor,
        base64::engine::general_purpose::STANDARD
            .decode(include_str!("fixtures/test-ca.der.b64").trim())
            .unwrap(),
    )
    .unwrap();
    std::fs::write(
        &leaf,
        base64::engine::general_purpose::STANDARD
            .decode(include_str!("fixtures/test-leaf.der.b64").trim())
            .unwrap(),
    )
    .unwrap();

    let command = format!(
        "/usr/bin/security verify-cert -c {} -p ssl -d 2026-08-01-00:00:00 -s example.test",
        leaf.display()
    );
    let output = Command::new(env!("CARGO_BIN_EXE_agora-sandbox"))
        .arg("--hook-library")
        .arg(hook_library())
        .arg("--workdir")
        .arg(cli_workdir())
        .arg("--tls-trust-anchor")
        .arg(&anchor)
        .arg("-c")
        .arg(command)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    std::fs::remove_dir_all(directory).unwrap();
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
        .arg("--workdir")
        .arg(cli_workdir())
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
        .filter_map(|line| {
            let record = line.get(line.find('{')?..)?;
            serde_json::from_str(record).ok()
        })
        .collect()
}

fn assert_audit_record(record: &serde_json::Value, destination: SocketAddr) {
    let object = record.as_object().unwrap();
    assert_eq!(object.len(), 7);
    assert_eq!(record["type"], "network");
    assert!(record["access_time"].as_str().is_some());
    assert!(
        record["trace_id"]
            .as_str()
            .is_some_and(|value| !value.is_empty())
    );
    assert!(record["pid"].as_u64().is_some_and(|pid| pid > 0));
    assert_eq!(record["destination_ip"], destination.ip().to_string());
    assert_eq!(record["destination_port"], destination.port());
    assert_eq!(record["domain"], "audit.example");
}
