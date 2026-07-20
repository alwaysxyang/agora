use super::active_runs::{ActiveRunScope, ActiveRuns, RunCancellation};
use super::command::{
    Argument, CommandArguments, CommandContext, CommandExecutor, CommandFuture, CommandHandler,
    CommandNode, CommandRegistry, CommandResolution,
};
use super::{AgentDispatcher, Daemon};
use crate::agent::{AgentOutput, AgentTask, ConfiguredAgent};
use crate::channel::{
    Channel, ChannelAction, ChannelAgentStatus, ChannelReply, ChannelRun, ChannelRunContext,
    ChannelTask, RunEvent,
};
use crate::config::{AgentConfig, AgentType, IsolateMode, IsolationScope};
use crate::store::{SessionKey, SessionStore};
use crate::task::{OutputEvent, TaskContent};
use anyhow::Result;
use std::collections::VecDeque;
use std::future::pending;
use std::sync::{Arc, Mutex, OnceLock};
use tokio::time::{Duration, timeout};

fn active_scope(channel_name: &str, session_id: &str, agent_name: &str) -> ActiveRunScope {
    ActiveRunScope::new(
        channel_name,
        session_id,
        "task-1",
        SessionKey::new(
            agent_name,
            IsolationScope::session(channel_name, session_id),
        ),
    )
}

fn command_registry() -> &'static CommandRegistry<CommandHandler> {
    static REGISTRY: OnceLock<CommandRegistry<CommandHandler>> = OnceLock::new();
    REGISTRY.get_or_init(|| CommandRegistry::standard().unwrap())
}

#[test]
fn command_registry_routes_default_handlers_and_subcommands() {
    let registry = CommandRegistry::standard().unwrap();

    let CommandResolution::Invocation(stop) = registry.route("/stop codex-dev") else {
        panic!("expected stop invocation");
    };
    let (_, stop_arguments) = stop.into_parts();
    assert_eq!(stop_arguments.argument("agent_name"), Some("codex-dev"));

    let CommandResolution::Invocation(_reset) = registry.route("/reset") else {
        panic!("expected reset invocation");
    };

    let CommandResolution::Invocation(enable) = registry.route("/ask enable codex-dev") else {
        panic!("expected ask enable invocation");
    };
    let (_, enable_arguments) = enable.into_parts();
    assert_eq!(enable_arguments.argument("agent_name"), Some("codex-dev"));
}

#[test]
fn command_registry_generates_root_and_command_help() {
    let registry = CommandRegistry::standard().unwrap();

    assert_eq!(
        registry.route("/help"),
        CommandResolution::Reply(
            "Agora commands:\n\
/stop - Stop running or queued agent tasks in the current conversation.\n\
/reset - Stop tasks and reset backend agent sessions.\n\
/ask - Control which agents receive messages in the current conversation.\n\
/help - Show all commands.\n\n\
Use /{command} help for details."
                .to_string()
        )
    );
    assert_eq!(
        registry.route("/stop help"),
        CommandResolution::Reply(
            "/stop - Stop running or queued agent tasks in the current conversation.\n\n\
Usage:\n\
/stop [{agent_name}]\n\
\nArguments:\n\
agent_name (optional) - Configured agent name. Omit it to stop every agent."
                .to_string()
        )
    );
    assert_eq!(
        registry.route("/reset help"),
        CommandResolution::Reply(
            "/reset - Stop tasks and reset backend agent sessions.\n\n\
Usage:\n\
/reset"
                .to_string()
        )
    );
}

#[test]
fn command_registry_generates_subcommand_and_argument_help() {
    let registry = CommandRegistry::standard().unwrap();
    let expected = concat!(
        "/ask - Control which agents receive messages in the current conversation.\n\n",
        "Subcommands:\n",
        "/ask list\n",
        "  List all subscribed agents and their current status.\n",
        "/ask status {agent_name}\n",
        "  Show one agent's current status.\n",
        "  agent_name (required) - Configured agent name in this conversation.\n",
        "/ask disable {agent_name}\n",
        "  Disable an agent for subsequent messages.\n",
        "  agent_name (required) - Configured agent name in this conversation.\n",
        "/ask enable {agent_name}\n",
        "  Enable an agent for subsequent messages.\n",
        "  agent_name (required) - Configured agent name in this conversation.\n\n",
        "Use /ask {subcommand} help for details.",
    );

    assert_eq!(
        registry.route("/ask help"),
        CommandResolution::Reply(expected.to_string())
    );
    assert_eq!(
        registry.route("/ask"),
        CommandResolution::Reply(expected.to_string())
    );
    assert_eq!(
        registry.route("/ask enable help"),
        CommandResolution::Reply(
            "/ask enable - Enable an agent for subsequent messages.\n\n\
Usage:\n\
/ask enable {agent_name}\n\n\
Arguments:\n\
agent_name (required) - Configured agent name in this conversation."
                .to_string()
        )
    );
}

#[test]
fn command_registry_generates_validation_errors_from_registered_arguments() {
    let registry = CommandRegistry::standard().unwrap();

    assert_eq!(
        registry.route("run cargo test"),
        CommandResolution::AgentInput
    );
    assert_eq!(
        registry.route("/stop codex-dev reviewer"),
        CommandResolution::Reply("Usage: /stop [{agent_name}]".to_string())
    );
    assert_eq!(
        registry.route("/ask disable"),
        CommandResolution::Reply("Usage: /ask disable {agent_name}".to_string())
    );
    assert_eq!(
        registry.route("/ask unknown"),
        CommandResolution::Reply(
            "Unknown subcommand: /ask unknown\nUse /ask help for usage.".to_string()
        )
    );
    assert_eq!(
        registry.route("/unknown"),
        CommandResolution::Reply(
            "Unknown command: /unknown\nUse /help to list commands.".to_string()
        )
    );
}

#[test]
fn command_registry_resolves_arbitrarily_nested_subcommands() {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum NestedHandler {
        Run,
    }

    let mut registry = CommandRegistry::new();
    registry
        .register(
            CommandNode::new("outer", "Outer command").subcommand(
                CommandNode::new("middle", "Middle command").subcommand(
                    CommandNode::new("inner", "Inner command")
                        .argument(Argument::required("value", "Value to process"))
                        .handler(NestedHandler::Run),
                ),
            ),
        )
        .unwrap();

    let CommandResolution::Invocation(invocation) = registry.route("/outer middle inner payload")
    else {
        panic!("expected nested invocation");
    };
    let (handler, arguments) = invocation.into_parts();
    assert_eq!(handler, NestedHandler::Run);
    assert_eq!(arguments.argument("value"), Some("payload"));
}

#[tokio::test]
async fn command_registry_executes_a_registered_handler_without_central_dispatch() {
    fn echo<'a>(_context: CommandContext<'a>, arguments: CommandArguments) -> CommandFuture<'a> {
        let value = arguments.argument("value").unwrap_or_default().to_string();
        Box::pin(async move { Ok(ChannelReply::new(format!("Echo: {value}"))) })
    }

    let mut registry: CommandRegistry<CommandHandler> = CommandRegistry::new();
    registry
        .register(
            CommandNode::new("echo", "Echo one value")
                .argument(Argument::required("value", "Value to echo"))
                .handler(echo as CommandHandler),
        )
        .unwrap();
    let CommandResolution::Invocation(invocation) = registry.route("/echo hello") else {
        panic!("expected echo invocation");
    };

    let temp = tempfile::tempdir().unwrap();
    let dispatcher =
        AgentDispatcher::new(SessionStore::open(temp.path().join("store.db")).unwrap());
    let reply = CommandExecutor::new("test", "session", &[], &dispatcher)
        .execute(invocation)
        .await
        .unwrap();

    assert_eq!(reply, ChannelReply::new("Echo: hello"));
}

#[test]
fn command_registry_rejects_invalid_tree_definitions() {
    #[derive(Clone, Copy)]
    enum TestHandler {
        Run,
    }

    let duplicate = CommandNode::new("root", "Root command")
        .subcommand(CommandNode::new("child", "First child").handler(TestHandler::Run))
        .subcommand(CommandNode::new("child", "Second child").handler(TestHandler::Run));
    assert_eq!(
        CommandRegistry::new()
            .register(duplicate)
            .unwrap_err()
            .to_string(),
        "duplicate subcommand in /root: child"
    );

    let invalid_arguments = CommandNode::new("run", "Run a task")
        .argument(Argument::optional("first", "Optional first argument"))
        .argument(Argument::required("second", "Required second argument"))
        .handler(TestHandler::Run);
    assert_eq!(
        CommandRegistry::new()
            .register(invalid_arguments)
            .unwrap_err()
            .to_string(),
        "required argument follows an optional argument in /run"
    );
}

#[tokio::test]
async fn help_commands_reply_without_starting_agents() {
    let temp = tempfile::tempdir().unwrap();
    let dispatcher =
        AgentDispatcher::new(SessionStore::open(temp.path().join("store.db")).unwrap());
    let replies = Arc::new(Mutex::new(Vec::new()));
    let channel = CommandTestChannel::new(Arc::clone(&replies));
    let mut runs = tokio::task::JoinSet::new();
    let registry = CommandRegistry::standard().unwrap();

    Daemon::route_channel_task(
        &channel,
        &[],
        &dispatcher,
        &registry,
        CommandTestTask::new("ask-help", "chat-1", "/ask help"),
        &mut runs,
    )
    .await
    .unwrap();
    Daemon::route_channel_task(
        &channel,
        &[],
        &dispatcher,
        &registry,
        CommandTestTask::new("stop-help", "chat-1", "/stop help"),
        &mut runs,
    )
    .await
    .unwrap();
    Daemon::route_channel_task(
        &channel,
        &[],
        &dispatcher,
        &registry,
        CommandTestTask::new("reset-help", "chat-1", "/reset help"),
        &mut runs,
    )
    .await
    .unwrap();
    Daemon::route_channel_task(
        &channel,
        &[],
        &dispatcher,
        &registry,
        CommandTestTask::new("root-help", "chat-1", "/help"),
        &mut runs,
    )
    .await
    .unwrap();

    assert_eq!(
        replies.lock().unwrap().as_slice(),
        [
            command_reply(&registry, "/ask help"),
            command_reply(&registry, "/stop help"),
            command_reply(&registry, "/reset help"),
            command_reply(&registry, "/help"),
        ]
    );
}

fn command_reply(registry: &CommandRegistry<CommandHandler>, input: &str) -> ChannelReply {
    let CommandResolution::Reply(reply) = registry.route(input) else {
        panic!("expected command reply for {input}");
    };
    ChannelReply::new(reply)
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
async fn card_stop_action_cancels_only_the_target_logical_task() {
    let temp = tempfile::tempdir().unwrap();
    let dispatcher =
        AgentDispatcher::new(SessionStore::open(temp.path().join("store.db")).unwrap());
    let key = SessionKey::new("codex", IsolationScope::session("lark", "chat-1"));
    let mut target = dispatcher.active_runs.register(ActiveRunScope::new(
        "lark",
        "chat-1",
        "task-2",
        key.clone(),
    ));
    let mut duplicate = dispatcher.active_runs.register(ActiveRunScope::new(
        "lark",
        "chat-1",
        "task-2",
        key.clone(),
    ));
    let mut other = dispatcher
        .active_runs
        .register(ActiveRunScope::new("lark", "chat-1", "task-3", key));
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
        &[],
        &dispatcher,
        command_registry(),
        CommandTestTask::stop_action("callback-1", "chat-1", "task-2", "codex"),
        &mut runs,
    )
    .await
    .unwrap();

    assert_eq!(target.cancelled().await, RunCancellation::Stopped);
    assert_eq!(duplicate.cancelled().await, RunCancellation::Stopped);
    assert!(
        timeout(Duration::from_millis(20), other.cancelled())
            .await
            .is_err()
    );
    assert!(replies.lock().unwrap().is_empty());
}

#[cfg(unix)]
#[tokio::test]
async fn stopping_a_card_run_advances_the_next_queued_task() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().unwrap();
    let script = temp.path().join("slow-agent");
    std::fs::write(&script, "#!/bin/sh\ncat >/dev/null\nexec sleep 30\n").unwrap();
    let mut permissions = std::fs::metadata(&script).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&script, permissions).unwrap();

    let agent = ConfiguredAgent::from_config(AgentConfig {
        name: "codex-dev".to_string(),
        isolate: IsolateMode::Session,
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
    let events = Arc::new(Mutex::new(Vec::new()));
    let contexts = Arc::new(Mutex::new(Vec::new()));
    let replies = Arc::new(Mutex::new(Vec::new()));
    let channel = CommandTestChannel {
        tasks: VecDeque::new(),
        events: Arc::clone(&events),
        contexts: Arc::clone(&contexts),
        replies: Arc::clone(&replies),
    };
    let dispatcher =
        AgentDispatcher::new(SessionStore::open(temp.path().join("store.db")).unwrap());
    let mut runs = tokio::task::JoinSet::new();

    Daemon::route_channel_task(
        &channel,
        std::slice::from_ref(&agent),
        &dispatcher,
        command_registry(),
        CommandTestTask::new("task-1", "chat-1", "first task"),
        &mut runs,
    )
    .await
    .unwrap();
    timeout(Duration::from_secs(2), async {
        loop {
            if events
                .lock()
                .unwrap()
                .iter()
                .any(|event| matches!(event, RunEvent::Started { .. }))
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();

    Daemon::route_channel_task(
        &channel,
        std::slice::from_ref(&agent),
        &dispatcher,
        command_registry(),
        CommandTestTask::new("task-2", "chat-1", "second task"),
        &mut runs,
    )
    .await
    .unwrap();
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

    Daemon::route_channel_task(
        &channel,
        &[],
        &dispatcher,
        command_registry(),
        CommandTestTask::stop_action("callback-1", "chat-1", "task-1", "codex-dev"),
        &mut runs,
    )
    .await
    .unwrap();
    timeout(Duration::from_secs(2), async {
        loop {
            let started = events
                .lock()
                .unwrap()
                .iter()
                .filter(|event| matches!(event, RunEvent::Started { .. }))
                .count();
            if started == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();

    Daemon::route_channel_task(
        &channel,
        &[],
        &dispatcher,
        command_registry(),
        CommandTestTask::stop_action("callback-2", "chat-1", "task-2", "codex-dev"),
        &mut runs,
    )
    .await
    .unwrap();
    timeout(Duration::from_secs(2), async {
        while let Some(result) = runs.join_next().await {
            result.unwrap().unwrap();
        }
    })
    .await
    .unwrap();

    let events = events.lock().unwrap();
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, RunEvent::Started { .. }))
            .count(),
        2
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| event == &&RunEvent::Stopped)
            .count(),
        2
    );
    assert!(events.contains(&RunEvent::Queued { ahead: 1 }));
    assert!(replies.lock().unwrap().is_empty());
    assert_eq!(
        contexts.lock().unwrap().as_slice(),
        ["codex-dev", "codex-dev"]
    );
}

#[tokio::test]
async fn active_runs_stop_every_run_using_a_reset_session_key() {
    let runs = ActiveRuns::default();
    let shared = SessionKey::new("codex", IsolationScope::Shared);
    let other = SessionKey::new("reviewer", IsolationScope::Shared);
    let mut lark = runs.register(ActiveRunScope::new(
        "lark",
        "chat-1",
        "task-1",
        shared.clone(),
    ));
    let mut telegram = runs.register(ActiveRunScope::new(
        "telegram",
        "chat-2",
        "task-2",
        shared.clone(),
    ));
    let mut reviewer = runs.register(ActiveRunScope::new("lark", "chat-1", "task-3", other));

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

    let daemon = tokio::spawn(Daemon::run_channel(
        channel,
        vec![agent],
        dispatcher,
        Arc::new(CommandRegistry::standard().unwrap()),
    ));
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
    let mut active_run = dispatcher.active_runs.register(ActiveRunScope::new(
        "telegram",
        "chat-2",
        "active-task",
        key.clone(),
    ));
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
        command_registry(),
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
        command_registry(),
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
        command_registry(),
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
        command_registry(),
        CommandTestTask::new("list", "chat-1", "/ask list"),
        &mut runs,
    )
    .await
    .unwrap();
    assert_eq!(
        replies.lock().unwrap().as_slice(),
        [ChannelReply::agent_list(vec![
            ChannelAgentStatus::new("codex-dev", false),
            ChannelAgentStatus::new("reviewer", true),
        ])]
    );

    replies.lock().unwrap().clear();
    Daemon::route_channel_task(
        &channel,
        &agents,
        &dispatcher,
        command_registry(),
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
        command_registry(),
        CommandTestTask::agent_enabled_action("action", "chat-1", "reviewer", false),
        &mut runs,
    )
    .await
    .unwrap();

    assert_eq!(
        replies.lock().unwrap().as_slice(),
        [ChannelReply::agent_list(vec![
            ChannelAgentStatus::new("codex-dev", true),
            ChannelAgentStatus::new("reviewer", false),
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
        replies: Arc::new(Mutex::new(Vec::new())),
    };
    let mut runs = tokio::task::JoinSet::new();

    Daemon::route_channel_task(
        &channel,
        &agents,
        &dispatcher,
        command_registry(),
        CommandTestTask::new("task", "chat-1", "review this project"),
        &mut runs,
    )
    .await
    .unwrap();

    assert_eq!(contexts.lock().unwrap().as_slice(), ["reviewer"]);
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
        command_registry(),
        CommandTestTask::new("task", "chat-1", "review this project"),
        &mut runs,
    )
    .await
    .unwrap();

    assert_eq!(
        replies.lock().unwrap().as_slice(),
        [ChannelReply::new(
            "No agents are enabled in this conversation."
        )]
    );
}

fn command_test_agent(name: &str, workspace: &std::path::Path) -> ConfiguredAgent {
    ConfiguredAgent::from_config(AgentConfig {
        name: name.to_string(),
        isolate: IsolateMode::Session,
        workspace: workspace.to_string_lossy().into_owned(),
        agent_type: AgentType::Custom,
        path: "/bin/cat".to_string(),
        model: None,
        effort: None,
        agent_sandbox: None,
        env: Default::default(),
        subscribe: Vec::new(),
    })
    .unwrap()
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
    action: Option<ChannelAction>,
}

impl CommandTestTask {
    fn new(task_id: &str, session_id: &str, content: &str) -> Self {
        Self {
            task_id: task_id.to_string(),
            session_id: session_id.to_string(),
            content: TaskContent::new(content),
            action: None,
        }
    }

    fn stop_action(
        task_id: &str,
        session_id: &str,
        target_task_id: &str,
        agent_name: &str,
    ) -> Self {
        Self {
            task_id: task_id.to_string(),
            session_id: session_id.to_string(),
            content: TaskContent::new(""),
            action: Some(ChannelAction::StopTask {
                task_id: target_task_id.to_string(),
                agent_name: agent_name.to_string(),
            }),
        }
    }

    fn agent_enabled_action(
        task_id: &str,
        session_id: &str,
        agent_name: &str,
        enabled: bool,
    ) -> Self {
        Self {
            task_id: task_id.to_string(),
            session_id: session_id.to_string(),
            content: TaskContent::new(""),
            action: Some(ChannelAction::SetAgentEnabled {
                agent_name: agent_name.to_string(),
                enabled,
            }),
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

    fn action(&self) -> Option<&ChannelAction> {
        self.action.as_ref()
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

impl CommandTestChannel {
    fn new(replies: Arc<Mutex<Vec<ChannelReply>>>) -> Self {
        Self {
            tasks: VecDeque::new(),
            events: Arc::new(Mutex::new(Vec::new())),
            contexts: Arc::new(Mutex::new(Vec::new())),
            replies,
        }
    }
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
