#[test]
fn node_is_binary_only_and_logs_hello() {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    assert!(!manifest_dir.join("src/lib.rs").exists());

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_agora-node"))
        .output()
        .unwrap();
    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"level\":\"INFO\""));
    assert!(stdout.contains("\"message\":\"hello from agora-node\""));
    assert!(stdout.contains("\"level\":\"DEBUG\""));
    assert!(stdout.contains("\"message\":\"node logger initialized\""));
}
