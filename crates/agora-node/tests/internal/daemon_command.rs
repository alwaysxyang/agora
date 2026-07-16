use super::active_runs::{ActiveRunScope, ActiveRuns, RunCancellation};
use super::command::{CommandParser, CommandRoute, NodeCommand};
use super::{AgentDispatcher, Daemon};
use crate::agent::ConfiguredAgent;
use crate::channel::{Channel, ChannelReply, ChannelRun, ChannelRunContext, ChannelTask, RunEvent};
use crate::config::{AgentConfig, AgentType, IsolateMode};
use crate::store::SessionStore;
use crate::task::TaskContent;
use anyhow::Result;
use std::collections::VecDeque;
use std::future::pending;
use std::sync::{Arc, Mutex};
use tokio::time::{Duration, timeout};

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
fn command_parser_rejects_unknown_or_invalid_commands() {
    assert_eq!(
        CommandParser::parse("/unknown"),
        CommandRoute::Invalid("Unknown command: /unknown".to_string())
    );
    assert_eq!(
        CommandParser::parse("/stop codex-dev reviewer"),
        CommandRoute::Invalid("Usage: /stop [agent_name]".to_string())
    );
}

#[tokio::test]
async fn active_runs_stop_all_agents_only_in_the_current_session() {
    let runs = ActiveRuns::default();
    let mut codex = runs.register(ActiveRunScope::new("lark", "chat-1", "codex"));
    let mut reviewer = runs.register(ActiveRunScope::new("lark", "chat-1", "reviewer"));
    let mut other_session = runs.register(ActiveRunScope::new("lark", "chat-2", "codex"));

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
    let mut codex = runs.register(ActiveRunScope::new("lark", "chat-1", "codex"));
    let mut reviewer = runs.register(ActiveRunScope::new("lark", "chat-1", "reviewer"));

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
async fn active_runs_interrupt_every_run_during_process_shutdown() {
    let runs = ActiveRuns::default();
    let mut codex = runs.register(ActiveRunScope::new("lark", "chat-1", "codex"));
    let mut reviewer = runs.register(ActiveRunScope::new("lark", "chat-2", "reviewer"));

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
