use agora_node::agent::{AgentOutput, AgentSessionUpdate, AgentTask, ConfiguredAgent};
use agora_node::config::{AgentCard, AgentConfig, AgentType, IsolateMode};
use anyhow::Result;

#[derive(Default)]
struct VecAgentOutput {
    chunks: Vec<String>,
}

impl AgentOutput for VecAgentOutput {
    async fn write(&mut self, chunk: String) -> Result<()> {
        self.chunks.push(chunk);
        Ok(())
    }
}

#[cfg(unix)]
#[tokio::test]
async fn codex_agent_uses_the_session_supplied_by_its_caller() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().unwrap();
    let script = temp.path().join("codex");
    std::fs::write(
        &script,
        concat!(
            "#!/bin/sh\n",
            "printf '%s\\n' \"$*\" >> invocations\n",
            "cat >/dev/null\n",
            "printf '%s\\n' ",
            "'{\"type\":\"thread.started\",\"thread_id\":\"thread-123\"}'\n",
            "printf '%s\\n' ",
            "'{\"type\":\"item.completed\",\"item\":{\"type\":\"agent_message\",\"text\":\"hello from codex\"}}'\n",
        ),
    )
    .unwrap();
    let mut permissions = std::fs::metadata(&script).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&script, permissions).unwrap();

    let mut config = agent(AgentType::Codex, &script, temp.path());
    config.model = Some("gpt-5.4".to_string());
    config.effort = Some("xhigh".to_string());
    let agent = ConfiguredAgent::from_config(config).unwrap();
    let mut first_output = VecAgentOutput::default();
    let mut second_output = VecAgentOutput::default();

    let first_outcome = agent
        .run(
            AgentTask::new("task-1", "session-1", "first"),
            None,
            &mut first_output,
        )
        .await
        .unwrap();
    assert_eq!(
        first_outcome.session_update(),
        &AgentSessionUpdate::Set("thread-123".to_string())
    );

    let second_outcome = agent
        .run(
            AgentTask::new("task-2", "session-2", "second"),
            Some("thread-123".to_string()),
            &mut second_output,
        )
        .await
        .unwrap();
    assert_eq!(
        second_outcome.session_update(),
        &AgentSessionUpdate::Set("thread-123".to_string())
    );

    let invocations = std::fs::read_to_string(temp.path().join("invocations")).unwrap();
    assert_eq!(
        invocations.lines().collect::<Vec<_>>(),
        vec![
            "exec --json --color never --model gpt-5.4 --config model_reasoning_effort=xhigh -",
            "exec resume --json --model gpt-5.4 --config model_reasoning_effort=xhigh thread-123 -",
        ]
    );
    assert!(
        first_output
            .chunks
            .iter()
            .any(|chunk| chunk.contains("hello from codex"))
    );
    assert!(
        first_output
            .chunks
            .iter()
            .all(|chunk| !chunk.contains("thread.started"))
    );
}

#[cfg(unix)]
#[tokio::test]
async fn codex_agent_reports_a_missing_session_without_persisting_it() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().unwrap();
    let script = temp.path().join("codex");
    std::fs::write(
        &script,
        concat!(
            "#!/bin/sh\n",
            "cat >/dev/null\n",
            "printf '%s\\n' ",
            "'Error: thread/resume failed: no rollout found for thread id missing' >&2\n",
            "exit 1\n",
        ),
    )
    .unwrap();
    let mut permissions = std::fs::metadata(&script).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&script, permissions).unwrap();

    let agent =
        ConfiguredAgent::from_config(agent(AgentType::Codex, &script, temp.path())).unwrap();
    let mut output = VecAgentOutput::default();

    let outcome = agent
        .run(
            AgentTask::new("task-1", "session-1", "hello"),
            Some("missing".to_string()),
            &mut output,
        )
        .await
        .unwrap();

    assert_eq!(outcome.session_update(), &AgentSessionUpdate::NotFound);
    assert!(output.chunks.is_empty());
}

#[cfg(unix)]
#[tokio::test]
async fn codex_agent_does_not_publish_backend_stderr() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().unwrap();
    let script = temp.path().join("codex");
    std::fs::write(
        &script,
        concat!(
            "#!/bin/sh\n",
            "cat >/dev/null\n",
            "printf '%s\\n' ",
            "'{\"type\":\"thread.started\",\"thread_id\":\"thread-123\"}'\n",
            "printf '%s\\n' ",
            "'{\"type\":\"item.completed\",\"item\":{\"type\":\"agent_message\",\"text\":\"visible response\"}}'\n",
            "printf '%s\\n' ",
            "'ERROR codex_core::tools::router: internal diagnostic' >&2\n",
        ),
    )
    .unwrap();
    let mut permissions = std::fs::metadata(&script).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&script, permissions).unwrap();

    let agent =
        ConfiguredAgent::from_config(agent(AgentType::Codex, &script, temp.path())).unwrap();
    let mut output = VecAgentOutput::default();

    agent
        .run(
            AgentTask::new("task-1", "session-1", "hello"),
            None,
            &mut output,
        )
        .await
        .unwrap();

    let output = output.chunks.concat();
    assert!(output.contains("visible response"));
    assert!(!output.contains("codex_core::tools::router"));
}

#[tokio::test]
async fn custom_agent_streams_raw_command_output() {
    let temp = tempfile::tempdir().unwrap();
    let agent =
        ConfiguredAgent::from_config(agent(AgentType::Custom, "/bin/cat", temp.path())).unwrap();
    let mut output = VecAgentOutput::default();

    let outcome = agent
        .run(
            AgentTask::new("task-1", "session-1", "hello from custom"),
            None,
            &mut output,
        )
        .await
        .unwrap();

    assert_eq!(outcome.exit_code(), 0);
    assert_eq!(outcome.session_update(), &AgentSessionUpdate::Unchanged);
    assert_eq!(output.chunks.concat(), "hello from custom");
    assert!(temp.path().exists());
}

fn agent(
    agent_type: AgentType,
    path: impl AsRef<std::path::Path>,
    workspace: impl AsRef<std::path::Path>,
) -> AgentConfig {
    AgentConfig {
        name: "codex-dev".to_string(),
        isolate: IsolateMode::None,
        workspace: workspace.as_ref().to_string_lossy().into_owned(),
        agent_type,
        path: path.as_ref().to_string_lossy().into_owned(),
        model: None,
        effort: None,
        card: AgentCard::default(),
        subscribe: Vec::new(),
    }
}
