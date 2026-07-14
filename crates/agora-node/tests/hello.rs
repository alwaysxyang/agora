#[test]
fn node_has_library_and_binary_and_requires_config() {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    assert!(manifest_dir.join("src/lib.rs").exists());
    assert!(manifest_dir.join("src/main.rs").exists());

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_agora-node"))
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--config"));
}

#[test]
fn node_rejects_removed_manual_task_flags() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_agora-node"))
        .arg("--task")
        .arg("hello")
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unexpected argument"));
}

#[test]
fn node_accepts_empty_config_without_starting_channel() {
    let temp = tempfile::tempdir().unwrap();
    let config_path = temp.path().join("agents.json");
    std::fs::write(&config_path, r#"{"channels":[],"agents":[]}"#).unwrap();

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_agora-node"))
        .arg("--config")
        .arg(config_path)
        .env("HOME", temp.path())
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"message\":\"loaded 0 channels and 0 agents\""));
    assert!(
        temp.path()
            .join(".agora")
            .join("db")
            .join("store.db")
            .exists()
    );
}

#[test]
fn node_help_describes_the_config_fields() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_agora-node"))
        .arg("--help")
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    for expected in [
        "CONFIGURATION FILE",
        "channels",
        "app_id",
        "secret",
        "agents",
        "isolate",
        "workspace",
        "~/.agora/workspace",
        "model",
        "effort",
        "agent_sandbox",
        "subscribe",
        "filter",
    ] {
        assert!(stdout.contains(expected), "help is missing {expected:?}");
    }
    assert!(!stdout.contains("Agent card fields"));
}
