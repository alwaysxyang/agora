use super::*;

#[tokio::test]
async fn agent_run_control_keeps_the_first_cancellation_reason() {
    let control = AgentRunControl::new();

    assert!(control.stop());
    assert!(!control.interrupt());
    assert_eq!(control.cancelled().await, AgentRunCancellation::Stopped);
}
