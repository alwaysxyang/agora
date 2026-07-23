use super::*;

#[tokio::test]
async fn custom_agent_streams_raw_command_output() {
    let temp = tempfile::tempdir().unwrap();
    let agent =
        ConfiguredAgent::from_config(agent(AgentType::Custom, "/bin/cat", temp.path())).unwrap();
    let mut output = VecAgentOutput::default();

    let outcome = completed(
        agent
            .run(
                AgentTask::new("hello from custom"),
                None,
                AgentRunControl::new(),
                &mut output,
            )
            .await
            .unwrap(),
    );

    assert_eq!(outcome.exit_code(), 0);
    assert_eq!(outcome.session_update(), &AgentSessionUpdate::Unchanged);
    assert_eq!(output.answer_text(), "hello from custom");
    assert!(temp.path().exists());
}

#[tokio::test]
async fn custom_agent_rejects_attachments_without_a_backend_contract() {
    let temp = tempfile::tempdir().unwrap();
    let agent =
        ConfiguredAgent::from_config(agent(AgentType::Custom, "/bin/cat", temp.path())).unwrap();
    let content = TaskContent::new("analyze this image").with_attachment(TaskAttachment::image(
        "trace.png",
        "image/png",
        b"image-bytes".to_vec(),
    ));
    let mut output = VecAgentOutput::default();

    let error = agent
        .run(
            AgentTask::new(content),
            None,
            AgentRunControl::new(),
            &mut output,
        )
        .await
        .unwrap_err();

    assert_eq!(
        error.to_string(),
        "custom agent does not support task attachments"
    );
}

#[tokio::test]
async fn custom_agent_reports_backend_session_deletion_as_unsupported() {
    let temp = tempfile::tempdir().unwrap();
    let agent =
        ConfiguredAgent::from_config(agent(AgentType::Custom, "/bin/cat", temp.path())).unwrap();

    assert_eq!(
        agent.delete_session("custom-session").await.unwrap(),
        DeleteSessionOutcome::Unsupported
    );
}
