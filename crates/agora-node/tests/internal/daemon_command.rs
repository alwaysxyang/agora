use super::active_runs::{ActiveRunScope, ActiveRuns, RunCancellation};
use super::command::{CommandParser, CommandRoute, NodeCommand};
use super::{AgentDispatcher, Daemon};
use crate::agent::{AgentOutput, AgentTask, ConfiguredAgent};
use crate::channel::{Channel, ChannelReply, ChannelRun, ChannelRunContext, ChannelTask, RunEvent};
use crate::config::{AgentConfig, AgentType, IsolateMode, IsolationScope};
use crate::store::{SessionKey, SessionStore};
use crate::task::{OutputEvent, TaskContent};
use anyhow::Result;
use std::collections::VecDeque;
use std::future::pending;
use std::sync::{Arc, Mutex};
use tokio::time::{Duration, timeout};

fn active_scope(channel_name: &str, session_id: &str, agent_name: &str) -> ActiveRunScope {
    ActiveRunScope::new(
        channel_name,
        session_id,
        SessionKey::new(
            agent_name,
            IsolationScope::session(channel_name, session_id),
        ),
    )
}

#[test]
fn command_parser_keeps_agent_input_separate() {
    assert_eq!(
        CommandParser::parse("run cargo test"),
        CommandRoute::AgentInput
    );
}

#[test]
fn command_parser_parses_stop_targets() {
    assert_eq!(
        CommandParser::parse("/stop"),
        CommandRoute::Command(NodeCommand::Stop { agent_name: None })
    );
    assert_eq!(
        CommandParser::parse("  /stop codex-dev  "),
        CommandRoute::Command(NodeCommand::Stop {
            agent_name: Some("codex-dev".to_string()),
        })
    );
}

#[test]
fn command_parser_parses_reset_without_arguments() {
    assert_eq!(
        CommandParser::parse("  /reset  "),
        CommandRoute::Command(NodeCommand::Reset)
    );
}

#[test]
fn command_parser_rejects_unknown_or_invalid_commands() {
    assert_eq!(
        CommandParser::parse("/unknown"),
        CommandRoute::Invalid("Unknown command: /unknown".to_string())
    );
    assert_eq!(
        CommandParser::parse("/stop codex-dev reviewer"),
        CommandRoute::Invalid("Usage: /stop [agent_name]".to_string())
    );
    assert_eq!(
        CommandParser::parse("/reset codex-dev"),
        CommandRoute::Invalid("Usage: /reset".to_string())
    );
}

#[tokio::test]
async fn active_runs_stop_all_agents_only_in_the_current_session() {
    let runs = ActiveRuns::default();
    let mut codex = runs.register(active_scope("lark", "chat-1", "codex"));
    let mut reviewer = runs.register(active_scope("lark", "chat-1", "reviewer"));
    let mut other_session = runs.register(active_scope("lark", "chat-2", "codex"));

    assert_eq!(
        runs.stop("lark", "chat-1", None),
        vec!["codex".to_string(), "reviewer".to_string()]
    );
    timeout(Duration::from_millis(50), codex.cancelled())
        .await
        .unwrap();
    timeout(Duration::from_millis(50), reviewer.cancelled())
        .await
        .unwrap();
    assert!(
        timeout(Duration::from_millis(20), other_session.cancelled())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn active_runs_stop_only_the_named_agent() {
    let runs = ActiveRuns::default();
    let mut codex = runs.register(active_scope("lark", "chat-1", "codex"));
    let mut reviewer = runs.register(active_scope("lark", "chat-1", "reviewer"));

    assert_eq!(
        runs.stop("lark", "chat-1", Some("codex")),
        vec!["codex".to_string()]
    );
    timeout(Duration::from_millis(50), codex.cancelled())
        .await
        .unwrap();
    assert!(
        timeout(Duration::from_millis(20), reviewer.cancelled())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn active_runs_stop_every_run_using_a_reset_session_key() {
    let runs = ActiveRuns::default();
    let shared = SessionKey::new("codex", IsolationScope::Shared);
    let other = SessionKey::new("reviewer", IsolationScope::Shared);
    let mut lark = runs.register(ActiveRunScope::new("lark", "chat-1", shared.clone()));
    let mut telegram = runs.register(ActiveRunScope::new("telegram", "chat-2", shared.clone()));
    let mut reviewer = runs.register(ActiveRunScope::new("lark", "chat-1", other));

    assert_eq!(
        runs.stop_session_keys(std::slice::from_ref(&shared)),
        vec!["codex".to_string()]
    );
    assert_eq!(lark.cancelled().await, RunCancellation::Stopped);
    assert_eq!(telegram.cancelled().await, RunCancellation::Stopped);
    assert!(
        timeout(Duration::from_millis(20), reviewer.cancelled())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn active_runs_interrupt_every_run_during_process_shutdown() {
    let runs = ActiveRuns::default();
    let mut codex = runs.register(active_scope("lark", "chat-1", "codex"));
    let mut reviewer = runs.register(active_scope("lark", "chat-2", "reviewer"));

    assert_eq!(runs.interrupt_all(), 2);
    assert_eq!(codex.cancelled().await, RunCancellation::Interrupted);
    assert_eq!(reviewer.cancelled().await, RunCancellation::Interrupted);
}

#[cfg(unix)]
#[tokio::test]
async fn channel_loop_routes_stop_without_sending_it_to_the_agent() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().unwrap();
    let script = temp.path().join("slow-agent");
    std::fs::write(&script, "#!/bin/sh\ncat >/dev/null\nexec sleep 30\n").unwrap();
    let mut permissions = std::fs::metadata(&script).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&script, permissions).unwrap();

    let events = Arc::new(Mutex::new(Vec::new()));
    let contexts = Arc::new(Mutex::new(Vec::new()));
    let replies = Arc::new(Mutex::new(Vec::new()));
    let channel = CommandTestChannel {
        tasks: VecDeque::from([
            CommandTestTask::new("task-1", "chat-1", "long running task"),
            CommandTestTask::new("task-2", "chat-1", "/stop"),
        ]),
        events: Arc::clone(&events),
        contexts: Arc::clone(&contexts),
        replies: Arc::clone(&replies),
    };
    let agent = ConfiguredAgent::from_config(AgentConfig {
        name: "codex-dev".to_string(),
        isolate: IsolateMode::None,
        workspace: temp.path().to_string_lossy().into_owned(),
        agent_type: AgentType::Custom,
        path: script.to_string_lossy().into_owned(),
        model: None,
        effort: None,
        agent_sandbox: None,
        env: Default::default(),
        subscribe: Vec::new(),
    })
    .unwrap();
    let dispatcher =
        AgentDispatcher::new(SessionStore::open(temp.path().join("store.db")).unwrap());

    let daemon = tokio::spawn(Daemon::run_channel(channel, vec![agent], dispatcher));
    timeout(Duration::from_secs(2), async {
        loop {
            if events.lock().unwrap().contains(&RunEvent::Stopped) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();

    assert_eq!(contexts.lock().unwrap().as_slice(), ["codex-dev"]);
    assert_eq!(
        replies.lock().unwrap().as_slice(),
        [ChannelReply::new("Stopped 1 agent: codex-dev.")]
    );
    daemon.abort();
}

#[cfg(unix)]
#[tokio::test]
async fn reset_stops_the_scope_deletes_the_session_and_starts_fresh_next_time() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().unwrap();
    let script = temp.path().join("codex");
    let invocations = temp.path().join("invocations");
    std::fs::write(
        &script,
        concat!(
            "#!/bin/sh\n",
            "printf '%s\\n' \"$*\" >> \"$INVOCATIONS\"\n",
            "if [ \"$1\" = delete ]; then exit 0; fi\n",
            "cat >/dev/null\n",
            "printf '%s\\n' '{\"type\":\"thread.started\",\"thread_id\":\"new-session\"}'\n",
        ),
    )
    .unwrap();
    let mut permissions = std::fs::metadata(&script).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&script, permissions).unwrap();

    let mut env = std::collections::HashMap::new();
    env.insert(
        "INVOCATIONS".to_string(),
        invocations.to_string_lossy().into_owned(),
    );
    let agent = ConfiguredAgent::from_config(AgentConfig {
        name: "codex-dev".to_string(),
        isolate: IsolateMode::None,
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
    let store = SessionStore::open(temp.path().join("store.db")).unwrap();
    let dispatcher = AgentDispatcher::new(store.clone());
    let key = SessionKey::new(agent.name(), agent.isolation_scope("lark", "chat-1"));
    store.save(&key, "old-session").unwrap();

    let active_ticket = dispatcher.queues.enqueue(&key);
    let mut active_run =
        dispatcher
            .active_runs
            .register(ActiveRunScope::new("telegram", "chat-2", key.clone()));
    let active_run = tokio::spawn(async move {
        assert_eq!(active_run.cancelled().await, RunCancellation::Stopped);
        drop(active_ticket);
    });

    let replies = Arc::new(Mutex::new(Vec::new()));
    let channel = CommandTestChannel {
        tasks: VecDeque::new(),
        events: Arc::new(Mutex::new(Vec::new())),
        contexts: Arc::new(Mutex::new(Vec::new())),
        replies: Arc::clone(&replies),
    };
    let mut runs = tokio::task::JoinSet::new();
    Daemon::route_channel_task(
        &channel,
        std::slice::from_ref(&agent),
        &dispatcher,
        CommandTestTask::new("reset", "chat-1", "/reset"),
        &mut runs,
    )
    .await
    .unwrap();
    timeout(Duration::from_secs(1), active_run)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(store.get(&key).unwrap(), None);
    assert_eq!(
        replies.lock().unwrap().as_slice(),
        [ChannelReply::new("Reset successful.")]
    );

    let mut output = IgnoreAgentOutput;
    dispatcher
        .execute_agent(&key, &agent, AgentTask::new("next task"), &mut output)
        .await
        .unwrap();

    assert_eq!(store.get(&key).unwrap().as_deref(), Some("new-session"));
    let invocations = std::fs::read_to_string(invocations).unwrap();
    assert!(invocations.contains("delete --force old-session\n"));
    assert!(invocations.lines().any(|line| line.starts_with("exec ")));
    assert!(!invocations.lines().any(|line| line.contains(" resume ")));
}

#[cfg(unix)]
#[tokio::test]
async fn reset_preserves_the_mapping_when_backend_deletion_fails() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().unwrap();
    let script = temp.path().join("codex");
    std::fs::write(
        &script,
        "#!/bin/sh\nprintf 'backend refused deletion' >&2\nexit 7\n",
    )
    .unwrap();
    let mut permissions = std::fs::metadata(&script).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&script, permissions).unwrap();

    let agent = ConfiguredAgent::from_config(AgentConfig {
        name: "codex-dev".to_string(),
        isolate: IsolateMode::Session,
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
    let store = SessionStore::open(temp.path().join("store.db")).unwrap();
    let dispatcher = AgentDispatcher::new(store.clone());
    let key = SessionKey::new(agent.name(), agent.isolation_scope("lark", "chat-1"));
    store.save(&key, "old-session").unwrap();

    let replies = Arc::new(Mutex::new(Vec::new()));
    let channel = CommandTestChannel {
        tasks: VecDeque::new(),
        events: Arc::new(Mutex::new(Vec::new())),
        contexts: Arc::new(Mutex::new(Vec::new())),
        replies: Arc::clone(&replies),
    };
    let mut runs = tokio::task::JoinSet::new();
    Daemon::route_channel_task(
        &channel,
        std::slice::from_ref(&agent),
        &dispatcher,
        CommandTestTask::new("reset", "chat-1", "/reset"),
        &mut runs,
    )
    .await
    .unwrap();

    assert_eq!(store.get(&key).unwrap().as_deref(), Some("old-session"));
    assert_eq!(
        replies.lock().unwrap().as_slice(),
        [ChannelReply::new("Reset failed for agents: codex-dev.")]
    );
}

#[tokio::test]
async fn reset_removes_the_mapping_when_backend_deletion_is_unsupported() {
    let temp = tempfile::tempdir().unwrap();
    let agent = ConfiguredAgent::from_config(AgentConfig {
        name: "custom-dev".to_string(),
        isolate: IsolateMode::Session,
        workspace: temp.path().to_string_lossy().into_owned(),
        agent_type: AgentType::Custom,
        path: "/bin/cat".to_string(),
        model: None,
        effort: None,
        agent_sandbox: None,
        env: Default::default(),
        subscribe: Vec::new(),
    })
    .unwrap();
    let store = SessionStore::open(temp.path().join("store.db")).unwrap();
    let dispatcher = AgentDispatcher::new(store.clone());
    let key = SessionKey::new(agent.name(), agent.isolation_scope("lark", "chat-1"));
    store.save(&key, "custom-session").unwrap();

    assert!(
        dispatcher
            .reset_sessions("lark", "chat-1", &[agent])
            .await
            .is_empty()
    );
    assert_eq!(store.get(&key).unwrap(), None);
}

struct IgnoreAgentOutput;

impl AgentOutput for IgnoreAgentOutput {
    async fn write(&mut self, _event: OutputEvent) -> Result<()> {
        Ok(())
    }
}

#[derive(Clone)]
struct CommandTestTask {
    task_id: String,
    session_id: String,
    content: TaskContent,
}

impl CommandTestTask {
    fn new(task_id: &str, session_id: &str, content: &str) -> Self {
        Self {
            task_id: task_id.to_string(),
            session_id: session_id.to_string(),
            content: TaskContent::new(content),
        }
    }
}

impl ChannelTask for CommandTestTask {
    fn task_id(&self) -> &str {
        &self.task_id
    }

    fn session_id(&self) -> &str {
        &self.session_id
    }

    fn content(&self) -> &TaskContent {
        &self.content
    }
}

#[derive(Clone)]
struct CommandTestRun {
    events: Arc<Mutex<Vec<RunEvent>>>,
}

impl ChannelRun for CommandTestRun {
    async fn publish(&self, event: RunEvent) -> Result<()> {
        self.events.lock().unwrap().push(event);
        Ok(())
    }
}

struct CommandTestChannel {
    tasks: VecDeque<CommandTestTask>,
    events: Arc<Mutex<Vec<RunEvent>>>,
    contexts: Arc<Mutex<Vec<String>>>,
    replies: Arc<Mutex<Vec<ChannelReply>>>,
}

impl Channel for CommandTestChannel {
    type Task = CommandTestTask;
    type Run = CommandTestRun;

    fn name(&self) -> &str {
        "lark"
    }

    async fn recv(&mut self) -> Result<Option<Self::Task>> {
        if let Some(task) = self.tasks.pop_front() {
            Ok(Some(task))
        } else {
            pending().await
        }
    }

    async fn open_run(&self, _task: &Self::Task, context: ChannelRunContext) -> Result<Self::Run> {
        self.contexts.lock().unwrap().push(context.agent.name);
        Ok(CommandTestRun {
            events: Arc::clone(&self.events),
        })
    }

    async fn reply(&self, _task: &Self::Task, reply: ChannelReply) -> Result<()> {
        self.replies.lock().unwrap().push(reply);
        Ok(())
    }
}
