#[cfg(target_os = "macos")]
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
#[cfg(target_os = "macos")]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

fn cli_workdir() -> PathBuf {
    std::env::temp_dir().join(format!(
        "agora-sandbox-cli-workdir-{}",
        uuid::Uuid::new_v4()
    ))
}

#[cfg(target_os = "macos")]
fn write_cli_config(
    directory: &Path,
    workdir: &Path,
    tls: &str,
    encryption: &str,
    key: Option<&str>,
    audit_file: Option<&Path>,
) -> PathBuf {
    std::fs::create_dir_all(directory).unwrap();
    let mut local = serde_json::json!({ "encrypt": encryption });
    if let Some(key) = key {
        local["key"] = serde_json::Value::String(key.to_string());
    }
    let audit = audit_file
        .map(|path| serde_json::json!({ "file": path }))
        .unwrap_or_else(|| serde_json::json!({}));
    let config = serde_json::json!({
        "workdir": workdir,
        "tls": tls,
        "filesystem": {
            "local": local,
            "nfs": []
        },
        "audit": audit
    });
    let path = directory.join("sandbox.json");
    std::fs::write(&path, serde_json::to_vec_pretty(&config).unwrap()).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    path
}

fn configured_command(config: &Path, executable: impl AsRef<std::ffi::OsStr>) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_agora-sandbox"));
    command
        .arg("run")
        .arg("-c")
        .arg(config)
        .arg("-e")
        .arg(executable);
    command
}

#[test]
fn sandbox_cli_documents_only_available_options() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_agora-sandbox"))
        .arg("--help")
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("run"));
    assert!(stdout.contains("migrate-key"));
    assert!(!stdout.contains("--smb-config"));
    assert!(!stdout.contains("--filesystem-key"));

    let run = std::process::Command::new(env!("CARGO_BIN_EXE_agora-sandbox"))
        .args(["run", "--help"])
        .output()
        .unwrap();
    assert!(run.status.success());
    let run = String::from_utf8_lossy(&run.stdout);
    assert!(run.contains("-c, --config <CONFIG>"));
    assert!(run.contains("-e, --executable <EXECUTABLE>"));
    assert!(!run.contains("--workdir"));
    assert!(!run.contains("--tls"));
    assert!(!run.contains("--audit-file"));

    let removed = std::process::Command::new(env!("CARGO_BIN_EXE_agora-sandbox"))
        .args(["tls", "generate"])
        .output()
        .unwrap();
    assert!(!removed.status.success());
}

#[cfg(target_os = "macos")]
#[test]
fn sandbox_cli_runs_from_one_strict_config_file() {
    let root = tempfile::tempdir().unwrap();
    let config = root.path().join("sandbox.json");
    std::fs::write(
        &config,
        r#"{
          "workdir": "workdir",
          "tls": "off",
          "filesystem": {
            "local": { "encrypt": "plain" },
            "nfs": []
          },
          "audit": {}
        }"#,
    )
    .unwrap();
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_agora-sandbox"))
        .arg("run")
        .arg("-c")
        .arg("sandbox.json")
        .args(["-e", "/usr/bin/true"])
        .current_dir(root.path())
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(root.path().join("workdir/fs").is_dir());
}

#[test]
fn sandbox_cli_documents_interactive_key_migration() {
    let output = Command::new(env!("CARGO_BIN_EXE_agora-sandbox"))
        .args(["migrate-key", "--help"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--workdir <WORKDIR>"));
    assert!(stdout.contains("Interactively"));
    assert!(!stdout.contains("--filesystem-key"));
    assert!(!stdout.contains("--new-filesystem-key"));
}

#[cfg(target_os = "macos")]
#[test]
fn sandbox_cli_runs_with_a_plain_local_filesystem() {
    let root = tempfile::tempdir().unwrap();
    let workdir = root.path().join("workdir");
    let config = write_cli_config(root.path(), &workdir, "off", "plain", None, None);
    let output = configured_command(&config, "/usr/bin/true")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(workdir.join("fs").is_dir());
}

#[cfg(target_os = "macos")]
#[test]
fn copied_cli_materializes_its_hook_without_a_sidecar() {
    let root = tempfile::tempdir().unwrap();
    let bin = root.path().join("bin");
    let workdir = root.path().join("workdir");
    std::fs::create_dir(&bin).unwrap();
    let executable = bin.join("agora-sandbox");
    std::fs::copy(env!("CARGO_BIN_EXE_agora-sandbox"), &executable).unwrap();
    assert!(!bin.join("libagora_sandbox.dylib").exists());
    let config = write_cli_config(root.path(), &workdir, "off", "plain", None, None);

    let output = Command::new(&executable)
        .arg("run")
        .arg("-c")
        .arg(&config)
        .args(["-e", "/usr/bin/true"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let versions = std::fs::read_dir(workdir.join("runtime/hook"))
        .unwrap()
        .map(|entry| entry.unwrap())
        .filter(|entry| entry.path().is_dir())
        .collect::<Vec<_>>();
    assert_eq!(versions.len(), 1);
    let checksum = versions[0].file_name();
    let checksum = checksum.to_str().unwrap();
    assert_eq!(checksum.len(), 32);
    assert!(
        checksum
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
    assert!(versions[0].path().join("libagora_sandbox.dylib").is_file());
}

#[test]
fn sandbox_cli_rejects_a_key_in_plain_filesystem_mode() {
    let root = tempfile::tempdir().unwrap();
    let config = write_cli_config(
        root.path(),
        &root.path().join("workdir"),
        "off",
        "plain",
        Some("unused"),
        None,
    );
    let output = configured_command(&config, "/usr/bin/true")
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("filesystem.local.key is not allowed when encrypt is plain")
    );
}

#[cfg(target_os = "macos")]
#[test]
fn sandbox_cli_migrates_the_encrypted_filesystem_key_in_place() {
    let root = tempfile::tempdir().unwrap();
    let workdir = root.path().join("workdir");
    let run = |key: &str| {
        let config = write_cli_config(root.path(), &workdir, "off", "encrypted", Some(key), None);
        configured_command(&config, "/usr/bin/true")
            .output()
            .unwrap()
    };

    let initialized = run("old-filesystem-key");
    assert!(
        initialized.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&initialized.stdout),
        String::from_utf8_lossy(&initialized.stderr)
    );

    let mut migrated = Command::new(env!("CARGO_BIN_EXE_agora-sandbox"));
    migrated
        .arg("migrate-key")
        .arg("--workdir")
        .arg(&workdir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut migrated = migrated.spawn().unwrap();
    migrated
        .stdin
        .take()
        .unwrap()
        .write_all(b"old-filesystem-key\nnew-filesystem-key\n")
        .unwrap();
    let migrated = migrated.wait_with_output().unwrap();
    assert!(
        migrated.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&migrated.stdout),
        String::from_utf8_lossy(&migrated.stderr)
    );
    let stdout = String::from_utf8_lossy(&migrated.stdout);
    assert!(stdout.contains("Current filesystem key"), "{stdout}");
    assert!(stdout.contains("New filesystem key"), "{stdout}");
    assert!(stdout.contains("100%"), "{stdout}");

    let old_key = run("old-filesystem-key");
    assert!(!old_key.status.success());
    assert!(String::from_utf8_lossy(&old_key.stderr).contains("key is incorrect"));

    let new_key = run("new-filesystem-key");
    assert!(
        new_key.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&new_key.stdout),
        String::from_utf8_lossy(&new_key.stderr)
    );
}

#[cfg(target_os = "macos")]
#[test]
fn sandbox_cli_prompts_for_migration_keys_in_a_terminal() {
    let workdir = cli_workdir();
    let mut process = Command::new("/usr/bin/script");
    process
        .arg("-q")
        .arg("/dev/null")
        .arg(env!("CARGO_BIN_EXE_agora-sandbox"))
        .arg("migrate-key")
        .arg("--workdir")
        .arg(&workdir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = process.spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"old-filesystem-key\nnew-filesystem-key\n")
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            panic!("interactive key migration did not exit before the deadline");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let output = child.wait_with_output().unwrap();

    assert!(!status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Current filesystem key"), "{stdout}");
    assert!(stdout.contains("New filesystem key"), "{stdout}");
    assert!(stdout.contains("Migration progress"), "{stdout}");
    assert!(stdout.contains("5%"), "{stdout}");
}

#[cfg(target_os = "macos")]
#[test]
fn sandbox_cli_auto_generates_reuses_and_replaces_its_workdir_tls_ca() {
    let directory = tempfile::tempdir().unwrap();
    let workdir = directory.path().join("workdir");
    let certificate = workdir.join("ca/ca.crt");
    let private_key = workdir.join("ca/ca.key");
    let config = write_cli_config(directory.path(), &workdir, "auto", "plain", None, None);

    let run = || {
        configured_command(&config, "/usr/bin/true")
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
}

#[cfg(target_os = "macos")]
#[test]
fn sandbox_cli_encrypted_ls_lists_upper_file() {
    let root = tempfile::tempdir().unwrap();
    let workdir = root.path().join("workdir");
    let config = write_cli_config(
        root.path(),
        &workdir,
        "off",
        "encrypted",
        Some("interactive-filesystem-key"),
        None,
    );
    let directory = root.path().to_string_lossy();
    let directory = shell_words::quote(&directory);
    let create_script = format!("cd {directory} && printf AGORA_UPPER_ONLY > interactive.txt");
    let create = format!("/bin/bash -c {}", shell_words::quote(&create_script));
    let created = configured_command(&config, create).output().unwrap();
    assert!(
        created.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&created.stdout),
        String::from_utf8_lossy(&created.stderr)
    );

    let list = format!("/bin/ls -1 {directory}");
    let output = configured_command(&config, list).output().unwrap();
    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .any(|line| line.trim_end_matches('\r') == "interactive.txt"),
        "stdout={}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[cfg(target_os = "macos")]
#[test]
fn sandbox_cli_external_command_writes_to_encrypted_redirection() {
    let root = tempfile::tempdir().unwrap();
    let workdir = root.path().join("workdir");
    let audit = root.path().join("audit.jsonl");
    let config = write_cli_config(
        root.path(),
        &workdir,
        "off",
        "encrypted",
        Some("redirection-filesystem-key"),
        Some(&audit),
    );
    let directory = root.path().to_string_lossy();
    let directory = shell_words::quote(&directory);
    let script = format!(
        "cd {directory} && /bin/echo inherited-output > redirected.txt && /bin/cat redirected.txt"
    );
    let command = format!("/bin/bash -c {}", shell_words::quote(&script));
    let output = configured_command(&config, command).output().unwrap();

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}\naudit={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
        std::fs::read_to_string(&audit).unwrap_or_default(),
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "inherited-output\n"
    );
}

#[test]
fn sandbox_cli_rejects_unknown_config_fields() {
    let root = tempfile::tempdir().unwrap();
    let config = root.path().join("sandbox.json");
    std::fs::write(
        &config,
        r#"{
          "workdir": "workdir",
          "tls": "off",
          "filesystem": { "local": { "encrypt": "plain" } },
          "tls_ca_cert": "/tmp/ca.pem"
        }"#,
    )
    .unwrap();
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
    let output = configured_command(&config, "/bin/true").output().unwrap();

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unknown field `tls_ca_cert`"));
}

#[test]
fn sandbox_cli_requires_a_command() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_agora-sandbox"))
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("Usage: agora-sandbox <COMMAND>"));
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
fn sandbox_cli_writes_structured_audit_logs_to_stderr_by_default() {
    let (output, destination) = run_audited_cli(None);

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(audit_records(&output.stdout).is_empty());
    let records = audit_records(&output.stderr);
    let network_records = records
        .iter()
        .filter(|record| record["audit"]["type"] == "network")
        .collect::<Vec<_>>();
    assert_eq!(
        network_records.len(),
        1,
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_audit_record(network_records[0], destination);
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
    let network_records = records
        .iter()
        .filter(|record| record["audit"]["type"] == "network")
        .collect::<Vec<_>>();
    assert_eq!(network_records.len(), 2);
    assert_audit_record(network_records[0], first_destination);
    assert_audit_record(network_records[1], second_destination);
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
    let root = tempfile::tempdir().unwrap();
    let workdir = root.path().join("workdir");
    let config = write_cli_config(root.path(), &workdir, "off", "plain", None, audit_file);
    let mut process = configured_command(&config, command);
    process
        .env("AGORA_SANDBOX_TEST_CLI_CHILD", "1")
        .env("AGORA_SANDBOX_TEST_DESTINATION", destination.to_string());
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
    assert_eq!(record["message"], "sandbox audit event");
    assert_eq!(record["level"], "INFO");
    assert!(record["time"].as_str().is_some());
    let record = &record["audit"];
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
