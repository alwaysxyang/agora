use super::*;
use crate::agent::AgentOutput;
use std::os::unix::fs::PermissionsExt;

#[test]
fn selects_all_agents_subscribed_to_channel() {
    let config = NodeConfig {
        proxy: None,
        channels: Vec::new(),
        agents: vec![
            agent("codex-dev", "lark1"),
            agent("review-bot", "lark1"),
            agent("tg-only", "telegram1"),
        ],
    };

    let agents = AgentRegistry::from_configs(config.agents)
        .unwrap()
        .subscribed_to("lark1");

    assert_eq!(agents.len(), 2);
    assert_eq!(agents[0].name(), "codex-dev");
    assert_eq!(agents[1].name(), "review-bot");
}

#[test]
fn wraps_configured_channel_behind_channel_trait() {
    let channel = ConfiguredChannel::from_config(ChannelConfig::Lark(LarkChannelConfig {
        name: "lark1".to_string(),
        app_id: "cli_xxx".to_string(),
        secret: "sec_xxx".to_string(),
        permission: Default::default(),
        proxy: None,
    }))
    .unwrap()
    .unwrap();

    assert_eq!(channel.name(), "lark1");
}

#[tokio::test]
async fn opens_one_channel_run_for_each_agent() {
    let temp = tempfile::tempdir().unwrap();
    let contexts = Arc::new(Mutex::new(Vec::new()));
    let channel = RecordingChannel {
        contexts: Arc::clone(&contexts),
        events: Arc::new(Mutex::new(Vec::new())),
    };
    let dispatcher =
        AgentDispatcher::new(SessionStore::open(temp.path().join("store.db")).unwrap());

    dispatcher
        .dispatch_channel_task(
            &channel,
            vec![
                ConfiguredAgent::from_config(custom_agent("codex-dev")).unwrap(),
                ConfiguredAgent::from_config(custom_agent("review-bot")).unwrap(),
            ],
            TestTask,
        )
        .await
        .unwrap();

    let contexts = contexts.lock().unwrap();
    assert_eq!(contexts.len(), 2);
    assert_eq!(contexts[0].agent.name, "codex-dev");
    assert_eq!(contexts[1].agent.name, "review-bot");
}

#[tokio::test]
async fn forwards_structured_agent_output_to_the_channel_run() {
    let temp = tempfile::tempdir().unwrap();
    let events = Arc::new(Mutex::new(Vec::new()));
    let channel = RecordingChannel {
        contexts: Arc::new(Mutex::new(Vec::new())),
        events: Arc::clone(&events),
    };
    let dispatcher =
        AgentDispatcher::new(SessionStore::open(temp.path().join("store.db")).unwrap());

    dispatcher
        .dispatch_channel_task(
            &channel,
            vec![ConfiguredAgent::from_config(custom_agent("custom")).unwrap()],
            TestTask,
        )
        .await
        .unwrap();

    assert!(
        events
            .lock()
            .unwrap()
            .contains(&RunEvent::Output(OutputEvent::Answer {
                text: "hello".to_string(),
            }))
    );
}

#[cfg(unix)]
#[tokio::test]
async fn forwards_custom_agent_stderr_to_the_channel_run() {
    let temp = tempfile::tempdir().unwrap();
    let script = temp.path().join("stderr-agent");
    std::fs::write(
        &script,
        "#!/bin/sh\ncat >/dev/null\nprintf 'diagnostic' >&2\n",
    )
    .unwrap();
    let mut permissions = std::fs::metadata(&script).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&script, permissions).unwrap();

    let events = Arc::new(Mutex::new(Vec::new()));
    let channel = RecordingChannel {
        contexts: Arc::new(Mutex::new(Vec::new())),
        events: Arc::clone(&events),
    };
    let dispatcher =
        AgentDispatcher::new(SessionStore::open(temp.path().join("store.db")).unwrap());
    let mut config = custom_agent("custom");
    config.path = script.to_string_lossy().into_owned();

    dispatcher
        .dispatch_channel_task(
            &channel,
            vec![ConfiguredAgent::from_config(config).unwrap()],
            TestTask,
        )
        .await
        .unwrap();

    assert!(
        events
            .lock()
            .unwrap()
            .contains(&RunEvent::Output(OutputEvent::Answer {
                text: "diagnostic".to_string(),
            }))
    );
}

#[tokio::test]
async fn daemon_skips_unsupported_and_unsubscribed_channels() {
    let temp = tempfile::tempdir().unwrap();
    let store = SessionStore::open(temp.path().join("store.db")).unwrap();
    let scheduler = super::super::ExecutionScheduler::default();
    let config = NodeConfig {
        proxy: None,
        channels: vec![
            ChannelConfig::Local(NamedChannelConfig {
                name: "local".to_string(),
                permission: Default::default(),
                proxy: None,
            }),
            ChannelConfig::Lark(LarkChannelConfig {
                name: "lark".to_string(),
                app_id: "app".to_string(),
                secret: "secret".to_string(),
                permission: Default::default(),
                proxy: None,
            }),
        ],
        agents: Vec::new(),
    };
    let daemon = Daemon {
        config,
        dispatcher: AgentDispatcher::from_parts(store.clone(), scheduler.clone()),
        commands: Arc::new(CommandRuntime::new(store, scheduler).unwrap()),
    };

    daemon.run().await.unwrap();
}

#[tokio::test]
async fn replies_when_no_agent_is_enabled_and_rejects_command_input() {
    let temp = tempfile::tempdir().unwrap();
    let store = SessionStore::open(temp.path().join("store.db")).unwrap();
    let dispatcher = AgentDispatcher::new(store);
    let replies = Arc::new(Mutex::new(Vec::new()));
    let channel = ReplyChannel {
        replies: Arc::clone(&replies),
    };

    dispatcher
        .dispatch_channel_task(
            &channel,
            Vec::new(),
            ReplyTask {
                input: ChannelTaskInput::Message(TaskContent::new("hello")),
            },
        )
        .await
        .unwrap();
    assert_eq!(
        replies.lock().unwrap().as_slice(),
        [ChannelReply::new(crate::i18n::NO_ENABLED_AGENTS)]
    );

    let error = dispatcher
        .dispatch_channel_task(
            &channel,
            vec![ConfiguredAgent::from_config(custom_agent("custom")).unwrap()],
            ReplyTask {
                input: ChannelTaskInput::Command(crate::task::CommandRequest::new(["stop"])),
            },
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("command input cannot start"));
}

#[tokio::test]
async fn agent_run_output_publishes_every_terminal_state() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut output = AgentRunOutput::new(RecordingRun {
        events: Arc::clone(&events),
    });

    output.queued(2).await.unwrap();
    output.started().await.unwrap();
    output
        .write(OutputEvent::Thinking {
            text: "checking".to_string(),
        })
        .await
        .unwrap();
    output.completed(7).await.unwrap();
    output.failed("failed".to_string()).await.unwrap();
    output
        .cancelled(crate::agent::AgentRunCancellation::Stopped)
        .await
        .unwrap();
    output
        .cancelled(crate::agent::AgentRunCancellation::Interrupted)
        .await
        .unwrap();

    assert_eq!(
        events.lock().unwrap().as_slice(),
        [
            RunEvent::Queued { ahead: 2 },
            RunEvent::Started {
                run_id: "local-run".to_string(),
            },
            RunEvent::Output(OutputEvent::Thinking {
                text: "checking".to_string(),
            }),
            RunEvent::Completed { exit_code: 7 },
            RunEvent::Failed {
                message: "failed".to_string(),
            },
            RunEvent::Stopped,
            RunEvent::Interrupted,
        ]
    );

    let failing = AgentRunOutput::new(FailingRun);
    assert!(failing.interrupted().await.is_err());
}

#[tokio::test]
async fn shutdown_interrupts_active_execution_and_join_errors_are_handled() {
    let scheduler = super::super::ExecutionScheduler::default();
    let execution = scheduler.enqueue(super::super::ExecutionScope::new(
        "lark",
        "chat",
        SessionKey::new("agent", IsolationScope::Shared),
    ));
    let shutdown = DaemonShutdown {
        scheduler: scheduler.clone(),
    };

    let waiting = tokio::spawn(async move {
        let cancellation = execution.control().cancelled().await;
        drop(execution);
        cancellation
    });
    shutdown.interrupt().await;
    assert_eq!(
        waiting.await.unwrap(),
        crate::agent::AgentRunCancellation::Interrupted
    );
    shutdown.interrupt().await;

    AgentDispatcher::log_run_result(Ok(Err(anyhow::anyhow!("run failed"))));
    let task = tokio::spawn(std::future::pending::<()>());
    task.abort();
    let join_error = task.await;
    AgentDispatcher::log_run_result(join_error.map(|_| Ok(())));
}
