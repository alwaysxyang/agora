use super::{
    SandboxCommand, SandboxConfig, process_group_exists, signal_process_group,
    wait_for_child_or_service,
};
use crate::callback::NoopCallback;
use crate::execution::ExecutionController;
use crate::network::{NetworkConfig, NetworkController, NetworkRunContext, TlsMode};
use base64::Engine;
use std::ffi::OsStr;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::time::Duration;

fn sleeping_child() -> tokio::process::Child {
    let mut command = tokio::process::Command::new("/bin/sleep");
    command.arg("30").kill_on_drop(true);
    command.as_std_mut().process_group(0);
    command.spawn().unwrap()
}

#[test]
fn sandbox_config_and_command_builders_preserve_runtime_inputs() {
    let missing_hook = std::env::temp_dir().join("agora-missing-hook.dylib");
    let config = SandboxConfig::new(&missing_hook);
    assert_eq!(config.hook_library(), missing_hook);
    assert_eq!(config.tls_trust_anchor(), None);
    assert_eq!(config.tls_ca(), None);
    assert!(
        config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("hook library does not exist")
    );

    let command = SandboxCommand::new("sh")
        .arg("-c")
        .args(["printf", "ok"])
        .env("KEY", "value")
        .current_dir("/tmp");
    assert_eq!(command.program, "sh");
    assert_eq!(command.arguments, ["-c", "printf", "ok"]);
    assert_eq!(command.environment.get(OsStr::new("KEY")).unwrap(), "value");
    assert_eq!(command.current_dir.as_deref(), Some(Path::new("/tmp")));
    assert_eq!(
        command.clone().into_command().as_std().get_current_dir(),
        Some(Path::new("/tmp"))
    );
    assert_eq!(
        SandboxCommand::from(OsStr::new("/bin/sh")).program,
        "/bin/sh"
    );
}

#[test]
fn sandbox_config_requires_a_tls_ca_for_interception() {
    let root = std::env::temp_dir().join(format!("agora-missing-ca-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    let hook = root.join("hook.dylib");
    std::fs::write(&hook, b"hook").unwrap();
    let mut config = SandboxConfig::new(&hook);
    config.network.tls = TlsMode::Auto;

    let error = config.validate().unwrap_err();

    assert!(
        error
            .to_string()
            .contains("requires a CA certificate and private key")
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn sandbox_config_rejects_missing_tls_ca_files() {
    let root =
        std::env::temp_dir().join(format!("agora-missing-ca-files-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    let hook = root.join("hook.dylib");
    let certificate = root.join("ca.pem");
    let private_key = root.join("ca-key.pem");
    std::fs::write(&hook, b"hook").unwrap();
    std::fs::write(&private_key, b"private key").unwrap();
    let mut config = SandboxConfig::new(&hook).with_tls_ca(&certificate, &private_key);
    config.network.tls = TlsMode::Auto;

    assert!(
        config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("TLS CA certificate does not exist")
    );

    std::fs::write(&certificate, b"certificate").unwrap();
    std::fs::remove_file(&private_key).unwrap();
    assert!(
        config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("TLS CA private key does not exist")
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn sandbox_config_preserves_tls_ca_paths() {
    let root = std::env::temp_dir().join(format!("agora-tls-ca-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    let hook = root.join("hook.dylib");
    let certificate = root.join("ca.pem");
    let private_key = root.join("ca-key.pem");
    std::fs::write(&hook, b"hook").unwrap();
    std::fs::write(&certificate, b"certificate").unwrap();
    std::fs::write(&private_key, b"private key").unwrap();
    let mut config = SandboxConfig::new(&hook).with_tls_ca(&certificate, &private_key);
    config.network.tls = TlsMode::Auto;

    assert_eq!(
        config.tls_ca(),
        Some((certificate.as_path(), private_key.as_path()))
    );
    assert!(config.validate().is_ok());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn sandbox_config_accepts_a_der_tls_trust_anchor() {
    let root = std::env::temp_dir().join(format!("agora-trust-anchor-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    let hook = root.join("hook.dylib");
    let anchor = root.join("ca.der");
    std::fs::write(&hook, b"hook").unwrap();
    std::fs::write(
        &anchor,
        base64::engine::general_purpose::STANDARD
            .decode(include_str!("../../tests/fixtures/test-ca.der.b64").trim())
            .unwrap(),
    )
    .unwrap();

    let config = SandboxConfig::new(&hook).with_tls_trust_anchor(&anchor);

    assert_eq!(config.tls_trust_anchor(), Some(anchor.as_path()));
    assert!(config.validate().is_ok());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn sandbox_config_rejects_a_malformed_tls_trust_anchor() {
    let root = std::env::temp_dir().join(format!("agora-bad-anchor-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    let hook = root.join("hook.dylib");
    let anchor = root.join("ca.der");
    std::fs::write(&hook, b"hook").unwrap();
    std::fs::write(&anchor, b"not a certificate").unwrap();

    let error = SandboxConfig::new(&hook)
        .with_tls_trust_anchor(&anchor)
        .validate()
        .unwrap_err();

    assert!(error.to_string().contains("valid DER certificate"));
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn sandbox_config_rejects_a_missing_tls_trust_anchor() {
    let root = std::env::temp_dir().join(format!("agora-missing-anchor-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    let hook = root.join("hook.dylib");
    let anchor = root.join("missing-ca.der");
    std::fs::write(&hook, b"hook").unwrap();

    let error = SandboxConfig::new(&hook)
        .with_tls_trust_anchor(&anchor)
        .validate()
        .unwrap_err();

    assert!(error.to_string().contains("trust anchor does not exist"));
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn process_group_helpers_treat_a_missing_group_as_already_stopped() {
    let missing = libc::pid_t::MAX;
    assert!(!process_group_exists(missing).unwrap());
    signal_process_group(missing, libc::SIGTERM).unwrap();
    assert!(process_group_exists(0).unwrap());
    assert!(signal_process_group(0, libc::c_int::MAX).is_err());
    assert!(process_group_exists(-1).unwrap());
}

#[tokio::test]
async fn proxy_failure_terminates_the_child_process() {
    let mut controller = NetworkController::start(
        NetworkConfig::default(),
        NetworkRunContext::new("sandbox", "run"),
        NoopCallback,
    )
    .await
    .unwrap();
    let mut child = sleeping_child();
    let mut execution = ExecutionController::start("proxy-failure-test")
        .await
        .unwrap();
    controller.abort_listener_for_test();
    let process_group = child.id().unwrap() as libc::pid_t;

    let result = tokio::time::timeout(
        Duration::from_secs(1),
        wait_for_child_or_service(&mut child, process_group, &mut controller, &mut execution),
    )
    .await
    .unwrap();

    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("sandbox network proxy failed")
    );
    assert!(child.try_wait().unwrap().is_some());
    controller.shutdown().await.unwrap();
    execution.shutdown().await.unwrap();
}

#[tokio::test]
async fn execution_controller_failure_terminates_the_child_process() {
    let mut controller = NetworkController::start(
        NetworkConfig::default(),
        NetworkRunContext::new("sandbox", "run"),
        NoopCallback,
    )
    .await
    .unwrap();
    let mut child = sleeping_child();
    let mut execution = ExecutionController::start("execution-failure-test")
        .await
        .unwrap();
    execution.abort_server_for_test();
    let process_group = child.id().unwrap() as libc::pid_t;

    let result = tokio::time::timeout(
        Duration::from_secs(1),
        wait_for_child_or_service(&mut child, process_group, &mut controller, &mut execution),
    )
    .await
    .unwrap();

    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("sandbox execution controller failed")
    );
    assert!(child.try_wait().unwrap().is_some());
    controller.shutdown().await.unwrap();
    assert!(execution.shutdown().await.is_ok());
}
