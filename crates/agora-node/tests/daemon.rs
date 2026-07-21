use agora_node::agent::{AgentRegistry, ConfiguredAgent};
use agora_node::channel::{
    Channel, ChannelReply, ChannelRun, ChannelRunContext, ChannelTask, ConfiguredChannel, RunEvent,
};
use agora_node::config::{
    AgentConfig, AgentSubscription, AgentType, ChannelConfig, IsolateMode, IsolationScope,
    LarkChannelConfig, NodeConfig,
};
use agora_node::daemon::AgentDispatcher;
use agora_node::store::{SessionKey, SessionStore};
use agora_node::task::{ChannelTaskInput, OutputEvent, TaskContent};
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
        env: Default::default(),
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
            .get(&SessionKey::new("codex-dev", IsolationScope::Shared))
            .unwrap()
            .as_deref(),
        Some("thread-123")
    );
}

#[cfg(unix)]
#[tokio::test]
async fn none_isolation_queues_and_resumes_across_channels() {
    use std::os::unix::fs::PermissionsExt;
    use tokio::time::{Duration, timeout};

    let temp = tempfile::tempdir().unwrap();
    let script = temp.path().join("codex");
    std::fs::write(
        &script,
        concat!(
            "#!/bin/sh\n",
            "printf '%s\\n' \"$*\" >> invocations\n",
            "cat >/dev/null\n",
            "sleep 0.2\n",
            "printf '%s\\n' ",
            "'{\"type\":\"thread.started\",\"thread_id\":\"thread-shared\"}'\n",
            "printf '%s\\n' ",
            "'{\"type\":\"item.completed\",\"item\":{\"type\":\"agent_message\",\"text\":\"ok\"}}'\n",
        ),
    )
    .unwrap();
    let mut permissions = std::fs::metadata(&script).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&script, permissions).unwrap();

    let store = SessionStore::open(temp.path().join("store.db")).unwrap();
    let dispatcher = AgentDispatcher::new(store.clone());
    let agent = ConfiguredAgent::from_config(AgentConfig {
        name: "codex-dev".to_string(),
        isolate: IsolateMode::None,
        workspace: temp.path().to_string_lossy().into_owned(),
        agent_type: AgentType::Codex,
        path: script.to_string_lossy().into_owned(),
        model: None,
        effort: None,
        agent_sandbox: None,
        env: Default::default(),
        subscribe: Vec::new(),
    })
    .unwrap();
    let second_events = Arc::new(Mutex::new(Vec::new()));

    let first = tokio::spawn({
        let dispatcher = dispatcher.clone();
        let agent = agent.clone();
        async move {
            dispatcher
                .dispatch_channel_task(
                    &ScopedChannel::new("lark1"),
                    vec![agent],
                    ScopedTask::new("task-1", "chat-1"),
                )
                .await
        }
    });
    timeout(Duration::from_secs(2), async {
        loop {
            if std::fs::read_to_string(temp.path().join("invocations"))
                .map(|content| content.lines().count() == 1)
                .unwrap_or(false)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();

    let second = tokio::spawn({
        let dispatcher = dispatcher.clone();
        let events = Arc::clone(&second_events);
        async move {
            dispatcher
                .dispatch_channel_task(
                    &ScopedChannel::with_events("telegram1", events),
                    vec![agent],
                    ScopedTask::new("task-2", "chat-2"),
                )
                .await
        }
    });

    first.await.unwrap().unwrap();
    second.await.unwrap().unwrap();

    let invocations = std::fs::read_to_string(temp.path().join("invocations")).unwrap();
    assert_eq!(
        invocations.lines().collect::<Vec<_>>(),
        vec![
            "exec --json --color never --config model_reasoning_summary=concise -",
            "exec resume --json --config model_reasoning_summary=concise thread-shared -",
        ]
    );
    assert!(
        second_events
            .lock()
            .unwrap()
            .contains(&RunEvent::Queued { ahead: 1 })
    );
    assert_eq!(
        store
            .get(&SessionKey::new("codex-dev", IsolationScope::Shared))
            .unwrap()
            .as_deref(),
        Some("thread-shared")
    );
}

#[cfg(unix)]
#[tokio::test]
async fn session_isolation_separates_backend_sessions_and_reuses_workspace() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().unwrap();
    let script = temp.path().join("codex");
    std::fs::write(
        &script,
        concat!(
            "#!/bin/sh\n",
            "printf '%s\\n' \"$*\" >> \"$INVOCATIONS\"\n",
            "pwd >> \"$WORKDIRS\"\n",
            "count=$(wc -l < \"$INVOCATIONS\" | tr -d ' ')\n",
            "cat >/dev/null\n",
            "printf '{\"type\":\"thread.started\",\"thread_id\":\"thread-%s\"}\\n' \"$count\"\n",
            "printf '%s\\n' ",
            "'{\"type\":\"item.completed\",\"item\":{\"type\":\"agent_message\",\"text\":\"ok\"}}'\n",
        ),
    )
    .unwrap();
    let mut permissions = std::fs::metadata(&script).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&script, permissions).unwrap();

    let invocations = temp.path().join("invocations");
    let workdirs = temp.path().join("workdirs");
    let store = SessionStore::open(temp.path().join("store.db")).unwrap();
    let dispatcher = AgentDispatcher::new(store.clone());
    let mut env = std::collections::HashMap::new();
    env.insert(
        "INVOCATIONS".to_string(),
        invocations.to_string_lossy().into_owned(),
    );
    env.insert(
        "WORKDIRS".to_string(),
        workdirs.to_string_lossy().into_owned(),
    );
    let agent = ConfiguredAgent::from_config(AgentConfig {
        name: "codex-dev".to_string(),
        isolate: IsolateMode::Session,
        workspace: temp.path().to_string_lossy().into_owned(),
        agent_type: AgentType::Codex,
        path: script.to_string_lossy().into_owned(),
        model: None,
        effort: None,
        agent_sandbox: None,
        env,
        subscribe: Vec::new(),
    })
    .unwrap();
    let channel = ScopedChannel::new("lark1");

    dispatcher
        .dispatch_channel_task(
            &channel,
            vec![agent.clone()],
            ScopedTask::new("task-1", "chat-1"),
        )
        .await
        .unwrap();
    dispatcher
        .dispatch_channel_task(&channel, vec![agent], ScopedTask::new("task-2", "chat-2"))
        .await
        .unwrap();

    let invocations = std::fs::read_to_string(invocations).unwrap();
    assert_eq!(
        invocations.lines().collect::<Vec<_>>(),
        vec![
            "exec --json --color never --config model_reasoning_summary=concise -",
            "exec --json --color never --config model_reasoning_summary=concise -",
        ]
    );
    assert_eq!(
        store
            .get(&SessionKey::new(
                "codex-dev",
                IsolationScope::session("lark1", "chat-1"),
            ))
            .unwrap()
            .as_deref(),
        Some("thread-1")
    );
    assert_eq!(
        store
            .get(&SessionKey::new(
                "codex-dev",
                IsolationScope::session("lark1", "chat-2"),
            ))
            .unwrap()
            .as_deref(),
        Some("thread-2")
    );
    let workdirs = std::fs::read_to_string(workdirs).unwrap();
    let expected_workdir = std::fs::canonicalize(temp.path()).unwrap();
    let expected_workdir = expected_workdir.to_string_lossy();
    assert_eq!(
        workdirs.lines().collect::<Vec<_>>(),
        vec![expected_workdir.as_ref(), expected_workdir.as_ref()]
    );
}

#[cfg(unix)]
#[tokio::test]
async fn updates_queue_depth_before_starting_serialized_agent_runs() {
    use std::os::unix::fs::PermissionsExt;
    use tokio::time::{Duration, timeout};

    let temp = tempfile::tempdir().unwrap();
    let script = temp.path().join("codex");
    std::fs::write(
        &script,
        concat!(
            "#!/bin/sh\n",
            "printf 'started\\n' >> invocations\n",
            "cat >/dev/null\n",
            "sleep 0.2\n",
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

    let events = Arc::new(Mutex::new(Vec::new()));
    let contexts = Arc::new(Mutex::new(Vec::new()));
    let dispatcher =
        AgentDispatcher::new(SessionStore::open(temp.path().join("queued-store.db")).unwrap());
    let agent = ConfiguredAgent::from_config(AgentConfig {
        name: "codex-dev".to_string(),
        isolate: IsolateMode::None,
        workspace: temp.path().to_string_lossy().into_owned(),
        agent_type: AgentType::Codex,
        path: script.to_string_lossy().into_owned(),
        model: None,
        effort: None,
        agent_sandbox: None,
        env: Default::default(),
        subscribe: Vec::new(),
    })
    .unwrap();

    let first = tokio::spawn({
        let dispatcher = dispatcher.clone();
        let agent = agent.clone();
        let events = Arc::clone(&events);
        let contexts = Arc::clone(&contexts);
        async move {
            dispatcher
                .dispatch_channel_task(
                    &RecordingChannel { contexts, events },
                    vec![agent],
                    TestTask,
                )
                .await
        }
    });
    timeout(Duration::from_secs(2), async {
        loop {
            if std::fs::read_to_string(temp.path().join("invocations"))
                .map(|content| content.lines().count() == 1)
                .unwrap_or(false)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();

    let second = tokio::spawn({
        let dispatcher = dispatcher.clone();
        let agent = agent.clone();
        let events = Arc::clone(&events);
        let contexts = Arc::clone(&contexts);
        async move {
            dispatcher
                .dispatch_channel_task(
                    &RecordingChannel { contexts, events },
                    vec![agent],
                    TestTask,
                )
                .await
        }
    });
    timeout(Duration::from_secs(2), async {
        loop {
            if events
                .lock()
                .unwrap()
                .contains(&RunEvent::Queued { ahead: 1 })
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();

    let third = tokio::spawn({
        let dispatcher = dispatcher.clone();
        let events = Arc::clone(&events);
        let contexts = Arc::clone(&contexts);
        let agent = agent.clone();
        async move {
            dispatcher
                .dispatch_channel_task(
                    &RecordingChannel { contexts, events },
                    vec![agent],
                    TestTask,
                )
                .await
        }
    });
    timeout(Duration::from_secs(2), async {
        loop {
            if events
                .lock()
                .unwrap()
                .contains(&RunEvent::Queued { ahead: 2 })
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();

    first.await.unwrap().unwrap();
    second.await.unwrap().unwrap();
    third.await.unwrap().unwrap();

    let events = events.lock().unwrap();
    let queued_two = events
        .iter()
        .position(|event| event == &RunEvent::Queued { ahead: 2 })
        .unwrap();
    let queued_one = events
        .iter()
        .enumerate()
        .filter_map(|(index, event)| (event == &RunEvent::Queued { ahead: 1 }).then_some(index))
        .collect::<Vec<_>>();
    let started = events
        .iter()
        .enumerate()
        .filter_map(|(index, event)| matches!(event, RunEvent::Started { .. }).then_some(index))
        .collect::<Vec<_>>();
    assert_eq!(started.len(), 3);
    assert_eq!(queued_one.len(), 2);
    assert!(started[0] < queued_one[0]);
    assert!(queued_one[0] < queued_two);
    assert!(queued_two < queued_one[1]);
    assert!(queued_one[1] < started[2]);
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

    let key = SessionKey::new("codex-dev", IsolationScope::Shared);
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
        env: Default::default(),
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
        env: Default::default(),
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
        env: Default::default(),
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

    fn input(&self) -> &ChannelTaskInput {
        static INPUT: std::sync::OnceLock<ChannelTaskInput> = std::sync::OnceLock::new();
        INPUT.get_or_init(|| ChannelTaskInput::Message(TaskContent::new("hello")))
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

    async fn reply(&self, _task: &Self::Task, _reply: ChannelReply) -> Result<()> {
        Ok(())
    }
}

#[derive(Clone)]
struct ScopedTask {
    task_id: String,
    session_id: String,
    input: ChannelTaskInput,
}

impl ScopedTask {
    fn new(task_id: &str, session_id: &str) -> Self {
        Self {
            task_id: task_id.to_string(),
            session_id: session_id.to_string(),
            input: ChannelTaskInput::Message(TaskContent::new("hello")),
        }
    }
}

impl ChannelTask for ScopedTask {
    fn task_id(&self) -> &str {
        &self.task_id
    }

    fn session_id(&self) -> &str {
        &self.session_id
    }

    fn input(&self) -> &ChannelTaskInput {
        &self.input
    }
}

struct ScopedChannel {
    name: String,
    events: Arc<Mutex<Vec<RunEvent>>>,
}

impl ScopedChannel {
    fn new(name: &str) -> Self {
        Self::with_events(name, Arc::new(Mutex::new(Vec::new())))
    }

    fn with_events(name: &str, events: Arc<Mutex<Vec<RunEvent>>>) -> Self {
        Self {
            name: name.to_string(),
            events,
        }
    }
}

impl Channel for ScopedChannel {
    type Task = ScopedTask;
    type Run = RecordingRun;

    fn name(&self) -> &str {
        &self.name
    }

    async fn recv(&mut self) -> Result<Option<Self::Task>> {
        Ok(None)
    }

    async fn open_run(&self, _task: &Self::Task, _context: ChannelRunContext) -> Result<Self::Run> {
        Ok(RecordingRun {
            events: Arc::clone(&self.events),
        })
    }

    async fn reply(&self, _task: &Self::Task, _reply: ChannelReply) -> Result<()> {
        Ok(())
    }
}
