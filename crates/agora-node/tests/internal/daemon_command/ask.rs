use super::*;

#[tokio::test]
async fn ask_commands_persist_and_report_agent_status_for_the_current_session() {
    let temp = tempfile::tempdir().unwrap();
    let agents = vec![
        command_test_agent("codex-dev", temp.path()),
        command_test_agent("reviewer", temp.path()),
    ];
    let store = SessionStore::open(temp.path().join("store.db")).unwrap();
    let dispatcher = AgentDispatcher::new(store.clone());
    let replies = Arc::new(Mutex::new(Vec::new()));
    let channel = CommandTestChannel::new(Arc::clone(&replies));
    let mut runs = tokio::task::JoinSet::new();

    Daemon::route_channel_task(
        &channel,
        &agents,
        &dispatcher,
        &command_runtime(&dispatcher),
        CommandTestTask::new("disable", "chat-1", "/ask disable codex-dev"),
        &mut runs,
    )
    .await
    .unwrap();
    assert_eq!(
        replies.lock().unwrap().as_slice(),
        [ChannelReply::agent_status(ChannelAgentStatus::new(
            "codex-dev",
            false,
        ))]
    );

    replies.lock().unwrap().clear();
    Daemon::route_channel_task(
        &channel,
        &agents,
        &dispatcher,
        &command_runtime(&dispatcher),
        CommandTestTask::new("list", "chat-1", "/ask list"),
        &mut runs,
    )
    .await
    .unwrap();
    assert_eq!(
        replies.lock().unwrap().as_slice(),
        [ChannelReply::agent_list(vec![
            agent_status_with_button("codex-dev", false),
            agent_status_with_button("reviewer", true),
        ])]
    );

    replies.lock().unwrap().clear();
    Daemon::route_channel_task(
        &channel,
        &agents,
        &dispatcher,
        &command_runtime(&dispatcher),
        CommandTestTask::new("status", "chat-1", "/ask status reviewer"),
        &mut runs,
    )
    .await
    .unwrap();
    assert_eq!(
        replies.lock().unwrap().as_slice(),
        [ChannelReply::agent_status(ChannelAgentStatus::new(
            "reviewer", true,
        ))]
    );

    let session = crate::store::ChannelSessionKey::new("lark", "chat-1");
    assert!(!store.is_agent_enabled(&session, "codex-dev").unwrap());
    assert!(store.is_agent_enabled(&session, "reviewer").unwrap());
}

#[tokio::test]
async fn ask_button_action_updates_status_and_returns_the_full_agent_list() {
    let temp = tempfile::tempdir().unwrap();
    let agents = vec![
        command_test_agent("codex-dev", temp.path()),
        command_test_agent("reviewer", temp.path()),
    ];
    let store = SessionStore::open(temp.path().join("store.db")).unwrap();
    let dispatcher = AgentDispatcher::new(store.clone());
    let replies = Arc::new(Mutex::new(Vec::new()));
    let channel = CommandTestChannel::new(Arc::clone(&replies));
    let mut runs = tokio::task::JoinSet::new();

    Daemon::route_channel_task(
        &channel,
        &agents,
        &dispatcher,
        &command_runtime(&dispatcher),
        CommandTestTask::agent_enabled_action("action", "chat-1", "reviewer", false),
        &mut runs,
    )
    .await
    .unwrap();

    assert_eq!(
        replies.lock().unwrap().as_slice(),
        [ChannelReply::agent_list(vec![
            agent_status_with_button("codex-dev", true),
            agent_status_with_button("reviewer", false),
        ])]
    );
    let session = crate::store::ChannelSessionKey::new("lark", "chat-1");
    assert!(!store.is_agent_enabled(&session, "reviewer").unwrap());
}

#[tokio::test]
async fn disabled_agents_do_not_receive_new_tasks_or_open_run_cards() {
    let temp = tempfile::tempdir().unwrap();
    let agents = vec![
        command_test_agent("codex-dev", temp.path()),
        command_test_agent("reviewer", temp.path()),
    ];
    let store = SessionStore::open(temp.path().join("store.db")).unwrap();
    let session = crate::store::ChannelSessionKey::new("lark", "chat-1");
    store.disable_agent(&session, "codex-dev").unwrap();
    let dispatcher = AgentDispatcher::new(store);
    let contexts = Arc::new(Mutex::new(Vec::new()));
    let channel = CommandTestChannel {
        tasks: VecDeque::new(),
        events: Arc::new(Mutex::new(Vec::new())),
        contexts: Arc::clone(&contexts),
        interrupts: Arc::new(Mutex::new(Vec::new())),
        replies: Arc::new(Mutex::new(Vec::new())),
    };
    let mut runs = tokio::task::JoinSet::new();

    Daemon::route_channel_task(
        &channel,
        &agents,
        &dispatcher,
        &command_runtime(&dispatcher),
        CommandTestTask::new("task", "chat-1", "review this project"),
        &mut runs,
    )
    .await
    .unwrap();

    assert_eq!(contexts.lock().unwrap().as_slice(), ["reviewer"]);
}

#[tokio::test]
async fn targeted_ask_runs_only_the_named_agent_even_when_it_is_disabled() {
    let temp = tempfile::tempdir().unwrap();
    let agents = vec![
        command_test_agent("codex-dev", temp.path()),
        command_test_agent("reviewer", temp.path()),
    ];
    let store = SessionStore::open(temp.path().join("store.db")).unwrap();
    let session = crate::store::ChannelSessionKey::new("lark", "chat-1");
    store.disable_agent(&session, "codex-dev").unwrap();
    let dispatcher = AgentDispatcher::new(store.clone());
    let events = Arc::new(Mutex::new(Vec::new()));
    let contexts = Arc::new(Mutex::new(Vec::new()));
    let replies = Arc::new(Mutex::new(Vec::new()));
    let channel = CommandTestChannel {
        tasks: VecDeque::new(),
        events: Arc::clone(&events),
        contexts: Arc::clone(&contexts),
        interrupts: Arc::new(Mutex::new(Vec::new())),
        replies: Arc::clone(&replies),
    };
    let mut runs = tokio::task::JoinSet::new();

    Daemon::route_channel_task(
        &channel,
        &agents,
        &dispatcher,
        &command_runtime(&dispatcher),
        CommandTestTask::new(
            "targeted-ask",
            "chat-1",
            "/ask codex-dev review this project",
        ),
        &mut runs,
    )
    .await
    .unwrap();
    while let Some(result) = runs.join_next().await {
        result.unwrap().unwrap();
    }

    assert_eq!(contexts.lock().unwrap().as_slice(), ["codex-dev"]);
    assert!(replies.lock().unwrap().is_empty());
    assert!(!store.is_agent_enabled(&session, "codex-dev").unwrap());
    assert!(events.lock().unwrap().iter().any(|event| {
        matches!(
            event,
            RunEvent::Output(OutputEvent::Answer { text }) if text == "review this project"
        )
    }));
}

#[tokio::test]
async fn targeted_ask_rejects_an_agent_that_is_not_subscribed() {
    let temp = tempfile::tempdir().unwrap();
    let agents = vec![command_test_agent("codex-dev", temp.path())];
    let dispatcher =
        AgentDispatcher::new(SessionStore::open(temp.path().join("store.db")).unwrap());
    let contexts = Arc::new(Mutex::new(Vec::new()));
    let replies = Arc::new(Mutex::new(Vec::new()));
    let channel = CommandTestChannel {
        tasks: VecDeque::new(),
        events: Arc::new(Mutex::new(Vec::new())),
        contexts: Arc::clone(&contexts),
        interrupts: Arc::new(Mutex::new(Vec::new())),
        replies: Arc::clone(&replies),
    };
    let mut runs = tokio::task::JoinSet::new();

    Daemon::route_channel_task(
        &channel,
        &agents,
        &dispatcher,
        &command_runtime(&dispatcher),
        CommandTestTask::new(
            "targeted-ask",
            "chat-1",
            "/ask reviewer review this project",
        ),
        &mut runs,
    )
    .await
    .unwrap();

    assert!(runs.is_empty());
    assert!(contexts.lock().unwrap().is_empty());
    assert_eq!(
        replies.lock().unwrap().as_slice(),
        [ChannelReply::new("当前对话中不存在 Agent：reviewer。")]
    );
}

#[tokio::test]
async fn agent_input_gets_a_reply_when_every_agent_is_disabled() {
    let temp = tempfile::tempdir().unwrap();
    let agents = vec![command_test_agent("codex-dev", temp.path())];
    let store = SessionStore::open(temp.path().join("store.db")).unwrap();
    let session = crate::store::ChannelSessionKey::new("lark", "chat-1");
    store.disable_agent(&session, "codex-dev").unwrap();
    let dispatcher = AgentDispatcher::new(store);
    let replies = Arc::new(Mutex::new(Vec::new()));
    let channel = CommandTestChannel::new(Arc::clone(&replies));
    let mut runs = tokio::task::JoinSet::new();

    Daemon::route_channel_task(
        &channel,
        &agents,
        &dispatcher,
        &command_runtime(&dispatcher),
        CommandTestTask::new("task", "chat-1", "review this project"),
        &mut runs,
    )
    .await
    .unwrap();

    assert_eq!(
        replies.lock().unwrap().as_slice(),
        [ChannelReply::new("当前对话没有启用的 Agent。")]
    );
}
