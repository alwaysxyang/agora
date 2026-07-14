use agora_node::agent::{AgentRegistry, ConfiguredAgent};
use agora_node::channel::{
    Channel, ChannelRun, ChannelRunContext, ChannelTask, ConfiguredChannel, RunEvent,
};
use agora_node::config::{
    AgentConfig, AgentSubscription, AgentType, ChannelConfig, IsolateMode, LarkChannelConfig,
    NodeConfig,
};
use agora_node::daemon::AgentDispatcher;
use agora_node::store::{SessionKey, SessionStore};
use agora_node::task::{OutputEvent, TaskContent};
use anyhow::Result;
use std::sync::{Arc, Mutex};

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

#[cfg(unix)]
#[tokio::test]
async fn persists_and_serializes_session_by_channel_and_agent() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().unwrap();
    let script = temp.path().join("codex");
    std::fs::write(
        &script,
        concat!(
            "#!/bin/sh\n",
            "printf '%s\\n' \"$*\" >> invocations\n",
            "cat >/dev/null\n",
            "sleep 0.1\n",
            "printf '%s\\n' ",
            "'{\"type\":\"thread.started\",\"thread_id\":\"thread-123\"}'\n",
            "printf '%s\\n' ",
            "'{\"type\":\"item.completed\",\"item\":{\"type\":\"agent_message\",\"text\":\"ok\"}}'\n",
        ),
    )
    .unwrap();
    let mut permissions = std::fs::metadata(&script).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&script, permissions).unwrap();

    let channel = RecordingChannel {
        contexts: Arc::new(Mutex::new(Vec::new())),
        events: Arc::new(Mutex::new(Vec::new())),
    };
    let store = SessionStore::open(temp.path().join("store.db")).unwrap();
    let dispatcher = AgentDispatcher::new(store.clone());
    let agent = AgentConfig {
        name: "codex-dev".to_string(),
        isolate: IsolateMode::None,
        workspace: temp.path().to_string_lossy().into_owned(),
        agent_type: AgentType::Codex,
        path: script.to_string_lossy().into_owned(),
        model: None,
        effort: None,
        agent_sandbox: None,
        subscribe: Vec::new(),
    };
    let agent = ConfiguredAgent::from_config(agent).unwrap();

    let first = dispatcher.dispatch_channel_task(&channel, vec![agent.clone()], TestTask);
    let second = dispatcher.dispatch_channel_task(&channel, vec![agent], TestTask);
    let (first, second) = tokio::join!(first, second);
    first.unwrap();
    second.unwrap();

    let invocations = std::fs::read_to_string(temp.path().join("invocations")).unwrap();
    assert_eq!(
        invocations.lines().collect::<Vec<_>>(),
        vec![
            "exec --json --color never --config model_reasoning_summary=concise -",
            "exec resume --json --config model_reasoning_summary=concise thread-123 -",
        ]
    );
    assert_eq!(
        store
            .get(&SessionKey::new("test", "session-1", "codex-dev"))
            .unwrap()
            .as_deref(),
        Some("thread-123")
    );
}

#[cfg(unix)]
#[tokio::test]
async fn replaces_a_missing_agent_session_with_a_new_session() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().unwrap();
    let script = temp.path().join("codex");
    std::fs::write(
        &script,
        concat!(
            "#!/bin/sh\n",
            "printf '%s\\n' \"$*\" >> invocations\n",
            "cat >/dev/null\n",
            "case \"$*\" in\n",
            "  *\" missing \"*)\n",
            "    printf '%s\\n' ",
            "'Error: thread/resume failed: no rollout found for thread id missing' >&2\n",
            "    exit 1\n",
            "    ;;\n",
            "esac\n",
            "printf '%s\\n' ",
            "'{\"type\":\"thread.started\",\"thread_id\":\"thread-new\"}'\n",
            "printf '%s\\n' ",
            "'{\"type\":\"item.completed\",\"item\":{\"type\":\"agent_message\",\"text\":\"ok\"}}'\n",
        ),
    )
    .unwrap();
    let mut permissions = std::fs::metadata(&script).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&script, permissions).unwrap();

    let key = SessionKey::new("test", "session-1", "codex-dev");
    let store = SessionStore::open(temp.path().join("store.db")).unwrap();
    store.save(&key, "missing").unwrap();
    let dispatcher = AgentDispatcher::new(store.clone());
    let channel = RecordingChannel {
        contexts: Arc::new(Mutex::new(Vec::new())),
        events: Arc::new(Mutex::new(Vec::new())),
    };
    let agent = ConfiguredAgent::from_config(AgentConfig {
        name: "codex-dev".to_string(),
        isolate: IsolateMode::None,
        workspace: temp.path().to_string_lossy().into_owned(),
        agent_type: AgentType::Codex,
        path: script.to_string_lossy().into_owned(),
        model: None,
        effort: None,
        agent_sandbox: None,
        subscribe: Vec::new(),
    })
    .unwrap();

    dispatcher
        .dispatch_channel_task(&channel, vec![agent], TestTask)
        .await
        .unwrap();

    let invocations = std::fs::read_to_string(temp.path().join("invocations")).unwrap();
    assert_eq!(
        invocations.lines().collect::<Vec<_>>(),
        vec![
            "exec resume --json --config model_reasoning_summary=concise missing -",
            "exec --json --color never --config model_reasoning_summary=concise -",
        ]
    );
    assert_eq!(store.get(&key).unwrap().as_deref(), Some("thread-new"));
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

fn agent(name: &str, channel: &str) -> AgentConfig {
    AgentConfig {
        name: name.to_string(),
        isolate: IsolateMode::None,
        workspace: "/tmp/agora-agent".to_string(),
        agent_type: AgentType::Codex,
        path: "/bin/cat".to_string(),
        model: None,
        effort: None,
        agent_sandbox: None,
        subscribe: vec![AgentSubscription {
            channel: channel.to_string(),
            filter: None,
        }],
    }
}

fn custom_agent(name: &str) -> AgentConfig {
    AgentConfig {
        name: name.to_string(),
        isolate: IsolateMode::None,
        workspace: "/tmp/agora-agent".to_string(),
        agent_type: AgentType::Custom,
        path: "/bin/cat".to_string(),
        model: None,
        effort: None,
        agent_sandbox: None,
        subscribe: Vec::new(),
    }
}

#[derive(Clone)]
struct TestTask;

impl ChannelTask for TestTask {
    fn task_id(&self) -> &str {
        "task-1"
    }

    fn session_id(&self) -> &str {
        "session-1"
    }

    fn content(&self) -> &TaskContent {
        static CONTENT: std::sync::OnceLock<TaskContent> = std::sync::OnceLock::new();
        CONTENT.get_or_init(|| TaskContent::new("hello"))
    }
}

#[derive(Clone)]
struct RecordingRun {
    events: Arc<Mutex<Vec<RunEvent>>>,
}

impl ChannelRun for RecordingRun {
    async fn publish(&self, event: RunEvent) -> Result<()> {
        self.events.lock().unwrap().push(event);
        Ok(())
    }
}

struct RecordingChannel {
    contexts: Arc<Mutex<Vec<ChannelRunContext>>>,
    events: Arc<Mutex<Vec<RunEvent>>>,
}

impl Channel for RecordingChannel {
    type Task = TestTask;
    type Run = RecordingRun;

    fn name(&self) -> &str {
        "test"
    }

    async fn recv(&mut self) -> Result<Option<Self::Task>> {
        Ok(None)
    }

    async fn open_run(&self, _task: &Self::Task, context: ChannelRunContext) -> Result<Self::Run> {
        self.contexts.lock().unwrap().push(context);
        Ok(RecordingRun {
            events: Arc::clone(&self.events),
        })
    }
}
