use super::wait_for_child_or_proxy;
use crate::audit::NoopAuditCallback;
use crate::network::{NetworkConfig, NetworkController, NetworkRunContext};
use std::time::Duration;

#[tokio::test]
async fn proxy_failure_terminates_the_child_process() {
    let mut controller = NetworkController::start(
        NetworkConfig::default(),
        NetworkRunContext::new("sandbox", "run"),
        NoopAuditCallback,
    )
    .await
    .unwrap();
    let mut child = tokio::process::Command::new("/bin/sleep")
        .arg("30")
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    controller.abort_listener_for_test();

    let result = tokio::time::timeout(
        Duration::from_secs(1),
        wait_for_child_or_proxy(&mut child, &mut controller),
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
}
