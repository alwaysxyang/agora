use agora_node::config::{AgentCard, AgentConfig, AgentType, IsolateMode, NodeConfig};

#[test]
fn parses_channels_and_agents_config() {
    let content = r#"{
        "channels": [
            {
                "type": "lark",
                "name": "lark1",
                "appid": "cli_xxx",
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
                "card": {
                    "name": "Codex Dev Agent",
                    "description": "Local coding agent",
                    "supportedInterfaces": [
                        {
                            "url": "https://agora.local/a2a/codex-dev",
                            "protocolBinding": "HTTP+JSON",
                            "protocolVersion": "1.0"
                        }
                    ],
                    "version": "0.1.0",
                    "capabilities": {
                        "streaming": true
                    },
                    "defaultInputModes": ["text/plain"],
                    "defaultOutputModes": ["text/plain"],
                    "skills": [
                        {
                            "id": "workspace-coding",
                            "name": "Workspace coding",
                            "description": "Read and modify source code in the configured workspace",
                            "tags": ["coding", "workspace"]
                        }
                    ]
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
    assert_eq!(config.agents[0].subscribe.len(), 1);
    assert_eq!(config.agents[0].subscribe[0].channel, "lark1");
    assert_eq!(
        config.agents[0].subscribe[0].filter,
        Some(serde_json::json!({}))
    );
    assert_eq!(config.agents[0].card.version, "0.1.0");
    assert_eq!(config.agents[0].card.supported_interfaces.len(), 1);
    assert_eq!(
        config.agents[0].card.supported_interfaces[0].protocol_binding,
        "HTTP+JSON"
    );
    assert_eq!(config.agents[0].card.capabilities.streaming, Some(true));
    assert_eq!(
        config.agents[0].card.default_input_modes,
        vec!["text/plain".to_string()]
    );
    assert_eq!(
        config.agents[0].card.default_output_modes,
        vec!["text/plain".to_string()]
    );
    assert_eq!(config.agents[0].card.skills.len(), 1);
    assert_eq!(
        config.agents[0].card.skills[0].id,
        "workspace-coding".to_string()
    );
}

#[test]
fn derives_workdir_from_isolation_mode() {
    let mut config = example_config();
    config.workspace = "/tmp/agora-agent".to_string();

    config.isolate = IsolateMode::None;
    assert_eq!(
        config.workdir("task-1", "session-a"),
        std::path::PathBuf::from("/tmp/agora-agent")
    );

    config.isolate = IsolateMode::Session;
    assert_eq!(
        config.workdir("task-1", "session-a"),
        std::path::PathBuf::from("/tmp/agora-agent/agent-1/session-a")
    );

    config.isolate = IsolateMode::Task;
    assert_eq!(
        config.workdir("task-1", "session-a"),
        std::path::PathBuf::from("/tmp/agora-agent/agent-1/task-1")
    );
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
                "card": {
                    "name": "Agent",
                    "description": "Local coding agent",
                    "supportedInterfaces": [],
                    "version": "0.1.0",
                    "capabilities": {},
                    "defaultInputModes": ["text/plain"],
                    "defaultOutputModes": ["text/plain"],
                    "skills": []
                },
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
        card: AgentCard {
            name: "Agent".to_string(),
            description: "Local coding agent".to_string(),
            supported_interfaces: Vec::new(),
            version: "0.1.0".to_string(),
            capabilities: Default::default(),
            default_input_modes: vec!["text/plain".to_string()],
            default_output_modes: vec!["text/plain".to_string()],
            skills: Vec::new(),
            ..AgentCard::default()
        },
        subscribe: vec![agora_node::config::AgentSubscription {
            channel: "lark1".to_string(),
            filter: None,
        }],
    }
}
