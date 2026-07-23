use super::*;

#[cfg(unix)]
#[tokio::test]
async fn configured_agent_run_owns_its_cancellation() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().unwrap();
    let script = temp.path().join("slow-agent");
    let started = temp.path().join("started");
    std::fs::write(
        &script,
        format!("#!/bin/sh\ntouch '{}'\nexec sleep 30\n", started.display()),
    )
    .unwrap();
    let mut permissions = std::fs::metadata(&script).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&script, permissions).unwrap();

    let agent =
        ConfiguredAgent::from_config(agent(AgentType::Custom, &script, temp.path())).unwrap();
    let control = AgentRunControl::new();
    let stop = control.clone();
    let run = tokio::spawn(async move {
        let mut output = VecAgentOutput::default();
        agent
            .run(AgentTask::new("long task"), None, control, &mut output)
            .await
            .unwrap()
    });

    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while !started.exists() {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert!(stop.stop());

    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(2), run)
            .await
            .unwrap()
            .unwrap(),
        AgentRunOutcome::Cancelled(AgentRunCancellation::Stopped)
    );
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
            "printf '%s' \"$AGORA_AGENT_ENV\" > configured-env\n",
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
    config.agent_sandbox = Some(AgentSandbox::DangerFullAccess);
    config
        .env
        .insert("AGORA_AGENT_ENV".to_string(), "configured".to_string());
    let agent = ConfiguredAgent::from_config(config).unwrap();
    let mut first_output = VecAgentOutput::default();
    let mut second_output = VecAgentOutput::default();

    let first_outcome = completed(
        agent
            .run(
                AgentTask::new("first"),
                None,
                AgentRunControl::new(),
                &mut first_output,
            )
            .await
            .unwrap(),
    );
    assert_eq!(
        first_outcome.session_update(),
        &AgentSessionUpdate::Set("thread-123".to_string())
    );

    let second_outcome = completed(
        agent
            .run(
                AgentTask::new("second"),
                Some("thread-123".to_string()),
                AgentRunControl::new(),
                &mut second_output,
            )
            .await
            .unwrap(),
    );
    assert_eq!(
        second_outcome.session_update(),
        &AgentSessionUpdate::Set("thread-123".to_string())
    );

    let invocations = std::fs::read_to_string(temp.path().join("invocations")).unwrap();
    assert_eq!(
        invocations.lines().collect::<Vec<_>>(),
        vec![
            "exec --json --color never --model gpt-5.4 --config model_reasoning_effort=xhigh --config sandbox_mode=\"danger-full-access\" --config approval_policy=\"never\" --config model_reasoning_summary=concise -",
            "exec resume --json --model gpt-5.4 --config model_reasoning_effort=xhigh --config sandbox_mode=\"danger-full-access\" --config approval_policy=\"never\" --config model_reasoning_summary=concise thread-123 -",
        ]
    );
    assert_eq!(
        std::fs::read_to_string(temp.path().join("configured-env")).unwrap(),
        "configured"
    );
    assert!(first_output.events.iter().any(
        |event| matches!(event, OutputEvent::Answer { text } if text.contains("hello from codex"))
    ));
    assert!(
        first_output
            .events
            .iter()
            .all(|event| !format!("{event:?}").contains("thread.started"))
    );
}

#[cfg(unix)]
#[tokio::test]
async fn codex_agent_classifies_thinking_progress_and_final_answer() {
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
            "'{\"type\":\"item.completed\",\"item\":{\"id\":\"msg-0\",\"type\":\"agent_message\",\"text\":\"I will inspect the channel path\"}}'\n",
            "printf '%s\\n' ",
            "'{\"type\":\"item.completed\",\"item\":{\"id\":\"reason-1\",\"type\":\"reasoning\",\"text\":\"Inspecting the channel path\"}}'\n",
            "printf '%s\\n' ",
            "'{\"type\":\"item.started\",\"item\":{\"id\":\"cmd-1\",\"type\":\"command_execution\",\"command\":\"cargo test\",\"aggregated_output\":\"\",\"exit_code\":null,\"status\":\"in_progress\"}}'\n",
            "printf '%s\\n' ",
            "'{\"type\":\"item.completed\",\"item\":{\"id\":\"cmd-1\",\"type\":\"command_execution\",\"command\":\"cargo test\",\"aggregated_output\":\"ok\",\"exit_code\":0,\"status\":\"completed\"}}'\n",
            "printf '%s\\n' ",
            "'{\"type\":\"item.completed\",\"item\":{\"id\":\"msg-1\",\"type\":\"agent_message\",\"text\":\"All checks passed\"}}'\n",
            "printf '%s\\n' ",
            "'{\"type\":\"turn.completed\",\"usage\":{\"input_tokens\":1,\"cached_input_tokens\":0,\"output_tokens\":1,\"reasoning_output_tokens\":1}}'\n",
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
            AgentTask::new("hello"),
            None,
            AgentRunControl::new(),
            &mut output,
        )
        .await
        .unwrap();

    assert_eq!(
        output.events,
        vec![
            OutputEvent::Progress {
                id: "msg-0".to_string(),
                text: "I will inspect the channel path".to_string(),
                status: ProgressStatus::Completed,
            },
            OutputEvent::Thinking {
                text: "Inspecting the channel path".to_string(),
            },
            OutputEvent::Progress {
                id: "cmd-1".to_string(),
                text: "Run `cargo test`".to_string(),
                status: ProgressStatus::Running,
            },
            OutputEvent::Progress {
                id: "cmd-1".to_string(),
                text: "Run `cargo test`".to_string(),
                status: ProgressStatus::Completed,
            },
            OutputEvent::Answer {
                text: "All checks passed".to_string(),
            },
            OutputEvent::Usage(TokenUsage {
                input_tokens: 1,
                cached_input_tokens: 0,
                output_tokens: 1,
                reasoning_output_tokens: 1,
            }),
        ]
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

    let outcome = completed(
        agent
            .run(
                AgentTask::new("hello"),
                Some("missing".to_string()),
                AgentRunControl::new(),
                &mut output,
            )
            .await
            .unwrap(),
    );

    assert_eq!(outcome.session_update(), &AgentSessionUpdate::NotFound);
    assert!(output.events.is_empty());
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
            AgentTask::new("hello"),
            None,
            AgentRunControl::new(),
            &mut output,
        )
        .await
        .unwrap();

    let output = output.answer_text();
    assert!(output.contains("visible response"));
    assert!(!output.contains("codex_core::tools::router"));
}

#[cfg(unix)]
#[tokio::test]
async fn codex_agent_passes_image_attachments_to_a_resumed_turn() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().unwrap();
    let script = temp.path().join("codex");
    std::fs::write(
        &script,
        concat!(
            "#!/bin/sh\n",
            "printf '%s\\n' \"$@\" > invocation-args\n",
            "while [ \"$#\" -gt 0 ]; do\n",
            "  if [ \"$1\" = \"--image\" ]; then\n",
            "    shift\n",
            "    cp \"$1\" received-image\n",
            "  fi\n",
            "  shift\n",
            "done\n",
            "cat > received-prompt\n",
            "printf '%s\\n' ",
            "'{\"type\":\"thread.started\",\"thread_id\":\"thread-123\"}'\n",
            "printf '%s\\n' ",
            "'{\"type\":\"item.completed\",\"item\":{\"type\":\"agent_message\",\"text\":\"image received\"}}'\n",
        ),
    )
    .unwrap();
    let mut permissions = std::fs::metadata(&script).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&script, permissions).unwrap();

    let agent =
        ConfiguredAgent::from_config(agent(AgentType::Codex, &script, temp.path())).unwrap();
    let content = TaskContent::new("analyze this image").with_attachment(TaskAttachment::image(
        "trace.png",
        "image/png",
        b"image-bytes".to_vec(),
    ));
    let mut output = VecAgentOutput::default();

    agent
        .run(
            AgentTask::new(content),
            Some("thread-123".to_string()),
            AgentRunControl::new(),
            &mut output,
        )
        .await
        .unwrap();

    let args = std::fs::read_to_string(temp.path().join("invocation-args")).unwrap();
    let args = args.lines().collect::<Vec<_>>();
    assert_eq!(&args[..3], ["exec", "resume", "--json"]);
    let image = args.iter().position(|arg| *arg == "--image").unwrap();
    let session = args.iter().position(|arg| *arg == "thread-123").unwrap();
    assert!(image < session);
    assert_eq!(args.last(), Some(&"-"));
    assert_eq!(
        std::fs::read(temp.path().join("received-image")).unwrap(),
        b"image-bytes"
    );
    assert_eq!(
        std::fs::read_to_string(temp.path().join("received-prompt")).unwrap(),
        "analyze this image"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn codex_agent_deletes_its_backend_session() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().unwrap();
    let script = temp.path().join("codex");
    std::fs::write(
        &script,
        concat!(
            "#!/bin/sh\n",
            "printf '%s\\n' \"$*\" > \"$DELETE_INVOCATION\"\n",
            "printf '%s' \"$AGORA_AGENT_ENV\" > \"$DELETE_ENV\"\n",
        ),
    )
    .unwrap();
    let mut permissions = std::fs::metadata(&script).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&script, permissions).unwrap();

    let mut config = agent(AgentType::Codex, &script, temp.path());
    config
        .env
        .insert("AGORA_AGENT_ENV".to_string(), "configured".to_string());
    config.env.insert(
        "DELETE_INVOCATION".to_string(),
        temp.path()
            .join("delete-invocation")
            .to_string_lossy()
            .into_owned(),
    );
    config.env.insert(
        "DELETE_ENV".to_string(),
        temp.path()
            .join("delete-env")
            .to_string_lossy()
            .into_owned(),
    );
    let agent = ConfiguredAgent::from_config(config).unwrap();

    assert_eq!(
        agent
            .delete_session("019f5eb1-cf97-7c71-bf16-b7cff731724a")
            .await
            .unwrap(),
        DeleteSessionOutcome::Deleted
    );
    assert_eq!(
        std::fs::read_to_string(temp.path().join("delete-invocation")).unwrap(),
        "delete --force 019f5eb1-cf97-7c71-bf16-b7cff731724a\n"
    );
    assert_eq!(
        std::fs::read_to_string(temp.path().join("delete-env")).unwrap(),
        "configured"
    );
}
