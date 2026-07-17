use agora_node::config::{AgentConfig, AgentSandbox, AgentType, IsolateMode, NodeConfig};

#[test]
fn parses_channels_and_agents_config() {
    let content = r#"{
        "channels": [
            {
                "type": "lark",
                "name": "lark1",
                "app_id": "cli_xxx",
                "secret": "sec_xxx"
            }
        ],
        "agents": [
            {
                "name": "codex-dev",
                "isolate": "session",
                "workspace": "/tmp/agora-agent",
                "type": "codex",
                "path": "/opt/homebrew/bin/codex",
                "model": "gpt-5.4",
                "effort": "high",
                "agent_sandbox": "danger-full-access",
                "env": {
                    "AGORA_AGENT_ENV": "configured"
                },
                "subscribe": [
                    {
                        "channel": "lark1",
                        "filter": {}
                    }
                ]
            }
        ]
    }"#;

    let config: NodeConfig = serde_json::from_str(content).unwrap();

    assert_eq!(config.channels.len(), 1);
    assert_eq!(config.channels[0].name(), "lark1");
    assert_eq!(config.agents.len(), 1);
    assert_eq!(config.agents[0].name, "codex-dev");
    assert_eq!(config.agents[0].agent_type, AgentType::Codex);
    assert_eq!(config.agents[0].path, "/opt/homebrew/bin/codex");
    assert_eq!(config.agents[0].model.as_deref(), Some("gpt-5.4"));
    assert_eq!(config.agents[0].effort.as_deref(), Some("high"));
    assert_eq!(
        config.agents[0].agent_sandbox,
        Some(AgentSandbox::DangerFullAccess)
    );
    assert_eq!(
        config.agents[0]
            .env
            .get("AGORA_AGENT_ENV")
            .map(String::as_str),
        Some("configured")
    );
    assert_eq!(config.agents[0].subscribe.len(), 1);
    assert_eq!(config.agents[0].subscribe[0].channel, "lark1");
    assert_eq!(
        config.agents[0].subscribe[0].filter,
        Some(serde_json::json!({}))
    );
}

#[test]
fn isolation_mode_does_not_change_workdir() {
    let mut config = example_config();
    config.workspace = "/tmp/agora-agent".to_string();

    config.isolate = IsolateMode::None;
    let isolation_scope = config.isolation_scope("lark1", "session-a");
    assert_eq!(
        isolation_scope,
        config.isolation_scope("telegram1", "session-b")
    );
    assert_eq!(
        config.workdir(),
        std::path::PathBuf::from("/tmp/agora-agent")
    );

    config.isolate = IsolateMode::Session;
    let isolation_scope = config.isolation_scope("lark1", "session-a");
    assert_ne!(
        isolation_scope,
        config.isolation_scope("telegram1", "session-b")
    );
    assert_eq!(
        config.workdir(),
        std::path::PathBuf::from("/tmp/agora-agent")
    );
}

#[test]
fn rejects_removed_task_isolation_mode() {
    let content = r#"{
        "channels": [],
        "agents": [{
            "name": "agent-1",
            "isolate": "task",
            "type": "codex",
            "path": "/opt/homebrew/bin/codex",
            "subscribe": []
        }]
    }"#;

    assert!(serde_json::from_str::<NodeConfig>(content).is_err());
}

#[test]
fn defaults_workspace_to_agora_directory_under_home() {
    let content = r#"{
        "channels": [],
        "agents": [
            {
                "name": "agent-1",
                "isolate": "none",
                "type": "codex",
                "path": "/opt/homebrew/bin/codex",
                "subscribe": []
            }
        ]
    }"#;

    let config: NodeConfig = serde_json::from_str(content).unwrap();
    let home = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let expected = home.join(".agora").join("workspace");

    assert_eq!(
        std::path::PathBuf::from(&config.agents[0].workspace),
        expected
    );
    assert_eq!(config.agents[0].model, None);
    assert_eq!(config.agents[0].effort, None);
    assert_eq!(config.agents[0].agent_sandbox, None);
    assert!(config.agents[0].env.is_empty());
}

fn example_config() -> AgentConfig {
    AgentConfig {
        name: "agent-1".to_string(),
        isolate: IsolateMode::None,
        workspace: "/tmp/agora-agent".to_string(),
        agent_type: AgentType::Codex,
        path: "/opt/homebrew/bin/codex".to_string(),
        model: None,
        effort: None,
        agent_sandbox: None,
        env: Default::default(),
        subscribe: vec![agora_node::config::AgentSubscription {
            channel: "lark1".to_string(),
            filter: None,
        }],
    }
}
