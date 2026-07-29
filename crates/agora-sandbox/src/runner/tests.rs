use super::{
    SandboxCommand, SandboxConfig, process_group_exists, signal_process_group,
    wait_for_child_or_service,
};
use crate::callback::NoopCallback;
use crate::execution::ExecutionController;
use crate::network::{NetworkConfig, NetworkController, NetworkRunContext};
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
