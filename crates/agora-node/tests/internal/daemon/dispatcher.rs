use super::*;

#[test]
fn selects_all_agents_subscribed_to_channel() {
    let config = NodeConfig {
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
