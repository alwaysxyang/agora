use super::*;

#[cfg(unix)]
struct StartSignalOutput {
    started: Option<tokio::sync::oneshot::Sender<()>>,
}

#[cfg(unix)]
impl AgentOutput for StartSignalOutput {
    async fn write(&mut self, _event: OutputEvent) -> Result<()> {
        if let Some(started) = self.started.take() {
            let _ = started.send(());
        }
        Ok(())
    }
}

#[cfg(unix)]
#[tokio::test]
async fn configured_agent_run_owns_its_cancellation() {
    use std::os::unix::fs::PermissionsExt;

    const TEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

    let temp = tempfile::tempdir().unwrap();
    let script = temp.path().join("slow-agent");
    std::fs::write(&script, "#!/bin/sh\nprintf 'started\\n'\nexec sleep 30\n").unwrap();
    let mut permissions = std::fs::metadata(&script).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&script, permissions).unwrap();

    let agent =
        ConfiguredAgent::from_config(agent(AgentType::Custom, &script, temp.path())).unwrap();
    let control = AgentRunControl::new();
    let stop = control.clone();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let mut run = tokio::spawn(async move {
        let mut output = StartSignalOutput {
            started: Some(started_tx),
        };
        agent
            .run(AgentTask::new("long task"), None, control, &mut output)
            .await
    });

    tokio::select! {
        started = tokio::time::timeout(TEST_TIMEOUT, started_rx) => {
            started
                .expect("agent command did not produce startup output before the timeout")
                .expect("agent command stopped before producing startup output");
        }
        result = &mut run => {
            panic!("agent run finished before startup output: {result:?}");
        }
    }
    assert!(stop.stop());

    assert_eq!(
        tokio::time::timeout(TEST_TIMEOUT, run)
            .await
            .expect("agent run did not stop before the timeout")
            .expect("agent run task failed")
            .expect("agent run returned an error"),
        AgentRunOutcome::Cancelled(AgentRunCancellation::Stopped)
    );
}

#[tokio::test]
async fn agent_run_control_keeps_the_first_cancellation_reason() {
    let control = AgentRunControl::new();

    assert!(control.stop());
    assert!(!control.interrupt());
    assert_eq!(control.cancelled().await, AgentRunCancellation::Stopped);
}
