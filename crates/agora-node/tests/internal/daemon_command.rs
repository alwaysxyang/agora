use super::command::{
    Argument, CommandContext, CommandExecution, CommandHandler, CommandNode, CommandRegistry,
    CommandResolution, CommandRuntime,
};
use super::execution::{ExecutionScheduler, ExecutionScope, ExecutionTicket};
use super::{AgentDispatcher, Daemon};
use crate::agent::{
    AgentOutput, AgentRunCancellation, AgentRunControl, AgentTask, ConfiguredAgent,
};
use crate::channel::{
    Channel, ChannelAgentStatus, ChannelButton, ChannelButtonStyle, ChannelReply, ChannelRun,
    ChannelRunContext, ChannelTask, InterruptCallback, RunEvent,
};
use crate::config::{AgentConfig, AgentType, IsolateMode, IsolationScope};
use crate::store::{SessionKey, SessionStore};
use crate::task::{ChannelTaskInput, CommandRequest, OutputEvent, TaskContent};
use anyhow::Result;
use std::collections::VecDeque;
use std::future::pending;
use std::sync::{Arc, Mutex};
use tokio::time::{Duration, timeout};

#[test]
fn neutral_command_request_and_button_preserve_data() {
    let request = CommandRequest::new(["ask", "disable"]).with_argument("agent_name", "codex-dev");
    let input = ChannelTaskInput::Command(request.clone());
    let button = ChannelButton::new("Disable", ChannelButtonStyle::Default, request.clone());

    assert_eq!(request.path(), ["ask", "disable"]);
    assert_eq!(request.argument("agent_name"), Some("codex-dev"));
    assert_eq!(input.command(), Some(&request));
    assert_eq!(button.text(), "Disable");
    assert_eq!(button.style(), ChannelButtonStyle::Default);
    assert_eq!(button.command(), &request);
}

#[tokio::test]
async fn interrupt_callback_stops_only_its_registered_agent_run() {
    let scheduler = ExecutionScheduler::default();
    let key = SessionKey::new("codex", IsolationScope::session("lark", "chat-1"));
    let (_target_ticket, target) = scheduled_run(
        &scheduler,
        ExecutionScope::new("lark", "chat-1", key.clone()),
    );
    let (_duplicate_ticket, duplicate) =
        scheduled_run(&scheduler, ExecutionScope::new("lark", "chat-1", key));
    let interrupt_control = target.clone();
    let interrupt = InterruptCallback::new(move || interrupt_control.stop());

    assert!(interrupt.trigger());
    assert_eq!(target.cancelled().await, AgentRunCancellation::Stopped);
    assert!(
        timeout(Duration::from_millis(20), duplicate.cancelled())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn execution_ticket_combines_fifo_admission_and_run_cancellation() {
    let scheduler = ExecutionScheduler::default();
    let scope = ExecutionScope::new(
        "lark",
        "chat-1",
        SessionKey::new("codex", IsolationScope::session("lark", "chat-1")),
    );
    let first = scheduler.enqueue(scope.clone());
    let mut second = scheduler.enqueue(scope);
    let first_control = first.control();
    let second_control = second.control();

    assert_eq!(first.ahead(), 0);
    assert_eq!(second.ahead(), 1);
    assert!(first_control.stop());
    assert_eq!(
        first_control.cancelled().await,
        AgentRunCancellation::Stopped
    );
    assert!(
        timeout(Duration::from_millis(20), second_control.cancelled())
            .await
            .is_err()
    );

    drop(first);
    assert_eq!(second.changed().await.unwrap(), 0);
}

#[tokio::test]
async fn scheduler_barrier_serializes_reset_without_becoming_an_agent_run() {
    let scheduler = ExecutionScheduler::default();
    let key = SessionKey::new("codex", IsolationScope::session("lark", "chat-1"));
    let run = scheduler.enqueue(ExecutionScope::new("lark", "chat-1", key.clone()));
    let mut barrier = scheduler.barrier(&key);

    assert_eq!(barrier.ahead(), 1);
    assert_eq!(scheduler.interrupt_all(), 1);
    drop(run);
    barrier.wait_until_front().await.unwrap();
    timeout(Duration::from_millis(20), scheduler.wait_until_empty())
        .await
        .unwrap();
}

fn run_scope(channel_name: &str, session_id: &str, agent_name: &str) -> ExecutionScope {
    ExecutionScope::new(
        channel_name,
        session_id,
        SessionKey::new(
            agent_name,
            IsolationScope::session(channel_name, session_id),
        ),
    )
}

fn scheduled_run(
    scheduler: &ExecutionScheduler,
    scope: ExecutionScope,
) -> (ExecutionTicket, AgentRunControl) {
    let ticket = scheduler.enqueue(scope);
    let control = ticket.control();
    (ticket, control)
}

fn command_runtime(dispatcher: &AgentDispatcher) -> CommandRuntime {
    CommandRuntime::new(dispatcher.store.clone(), dispatcher.scheduler.clone()).unwrap()
}

fn isolated_command_runtime() -> CommandRuntime {
    let temp = tempfile::tempdir().unwrap();
    let dispatcher =
        AgentDispatcher::new(SessionStore::open(temp.path().join("store.db")).unwrap());
    command_runtime(&dispatcher)
}

#[test]
fn command_registry_routes_default_handlers_and_subcommands() {
    let runtime = isolated_command_runtime();
    let registry = runtime.registry();

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
fn command_registry_routes_ask_prompt_to_the_default_handler() {
    let runtime = isolated_command_runtime();
    let registry = runtime.registry();

    let CommandResolution::Invocation(invocation) =
        registry.route("/ask codex-dev review this project")
    else {
        panic!("expected targeted ask invocation");
    };
    let (_, arguments) = invocation.into_parts();
    assert_eq!(arguments.argument("agent_name"), Some("codex-dev"));
    assert_eq!(arguments.argument("prompt"), Some("review this project"));

    let CommandResolution::Invocation(list) = registry.route("/ask list") else {
        panic!("expected ask list invocation");
    };
    let (_, arguments) = list.into_parts();
    assert_eq!(arguments.argument("agent_name"), None);
    assert_eq!(arguments.argument("prompt"), None);
}

#[test]
fn command_registry_generates_root_and_command_help() {
    let runtime = isolated_command_runtime();
    let registry = runtime.registry();

    assert_eq!(
        registry.route("/help"),
        CommandResolution::Reply(
            "Agora 命令：\n\
/stop - 停止当前对话中正在运行或排队的 Agent 任务。\n\
/reset - 停止任务并重置后端 Agent 会话。\n\
/ask - 向指定 Agent 提问或控制 Agent 的消息接收状态。\n\
/help - 显示所有命令。\n\n\
使用 /{command} help 查看详情。"
                .to_string()
        )
    );
    assert_eq!(
        registry.route("/stop help"),
        CommandResolution::Reply(
            "/stop - 停止当前对话中正在运行或排队的 Agent 任务。\n\n\
用法：\n\
/stop [{agent_name}]\n\
\n参数：\n\
agent_name (可选) - 已配置的 Agent 名称；省略时停止全部 Agent。"
                .to_string()
        )
    );
    assert_eq!(
        registry.route("/reset help"),
        CommandResolution::Reply(
            "/reset - 停止任务并重置后端 Agent 会话。\n\n\
用法：\n\
/reset"
                .to_string()
        )
    );
}

#[test]
fn command_registry_generates_subcommand_and_argument_help() {
    let runtime = isolated_command_runtime();
    let registry = runtime.registry();
    let expected = concat!(
        "/ask - 向指定 Agent 提问或控制 Agent 的消息接收状态。\n\n",
        "用法：\n",
        "/ask {agent_name} {prompt}\n\n",
        "参数：\n",
        "agent_name (必填) - 当前对话中已配置的 Agent 名称。\n",
        "prompt (必填) - 仅发送给指定 Agent 的提示词。\n\n",
        "子命令：\n",
        "/ask list\n",
        "  列出所有已订阅 Agent 及其当前状态。\n",
        "/ask status {agent_name}\n",
        "  查看指定 Agent 的当前状态。\n",
        "  agent_name (必填) - 当前对话中已配置的 Agent 名称。\n",
        "/ask disable {agent_name}\n",
        "  禁止指定 Agent 接收后续消息。\n",
        "  agent_name (必填) - 当前对话中已配置的 Agent 名称。\n",
        "/ask enable {agent_name}\n",
        "  允许指定 Agent 接收后续消息。\n",
        "  agent_name (必填) - 当前对话中已配置的 Agent 名称。\n\n",
        "使用 /ask {子命令} help 查看详情。",
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
            "/ask enable - 允许指定 Agent 接收后续消息。\n\n\
用法：\n\
/ask enable {agent_name}\n\n\
参数：\n\
agent_name (必填) - 当前对话中已配置的 Agent 名称。"
                .to_string()
        )
    );
}

#[test]
fn command_registry_generates_validation_errors_from_registered_arguments() {
    let runtime = isolated_command_runtime();
    let registry = runtime.registry();

    assert_eq!(
        registry.route("run cargo test"),
        CommandResolution::AgentInput
    );
    assert_eq!(
        registry.route("/stop codex-dev reviewer"),
        CommandResolution::Reply("用法：/stop [{agent_name}]".to_string())
    );
    assert_eq!(
        registry.route("/ask disable"),
        CommandResolution::Reply("用法：/ask disable {agent_name}".to_string())
    );
    assert_eq!(
        registry.route("/ask unknown"),
        CommandResolution::Reply("用法：/ask {agent_name} {prompt}".to_string())
    );
    assert_eq!(
        registry.route("/unknown"),
        CommandResolution::Reply("未知命令：/unknown\n使用 /help 查看全部命令。".to_string())
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

#[test]
fn command_registry_validates_structured_arguments() {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum TestHandler {
        Enable,
    }

    let mut registry = CommandRegistry::new();
    registry
        .register(
            CommandNode::new("ask", "Control agents").subcommand(
                CommandNode::new("enable", "Enable one agent")
                    .argument(Argument::required("agent_name", "Agent name"))
                    .handler(TestHandler::Enable),
            ),
        )
        .unwrap();

    let valid = CommandRequest::new(["ask", "enable"]).with_argument("agent_name", "codex-dev");
    let CommandResolution::Invocation(invocation) = registry.route_structured(&valid) else {
        panic!("expected structured invocation");
    };
    let (handler, arguments) = invocation.into_parts();
    assert_eq!(handler, TestHandler::Enable);
    assert_eq!(arguments.argument("agent_name"), Some("codex-dev"));

    assert_eq!(
        registry.route_structured(&CommandRequest::new(["ask", "enable"])),
        CommandResolution::Reply("用法：/ask enable {agent_name}".to_string())
    );
}

#[tokio::test]
async fn command_registry_executes_a_registered_handler_without_central_dispatch() {
    let mut registry: CommandRegistry<CommandHandler> = CommandRegistry::new();
    registry
        .register(
            CommandNode::new("echo", "Echo one value")
                .argument(Argument::required("value", "Value to echo"))
                .handler(CommandHandler::new(|_context, arguments| async move {
                    let value = arguments.argument("value").unwrap_or_default();
                    Ok(Some(ChannelReply::new(format!("Echo: {value}"))))
                })),
        )
        .unwrap();
    let CommandResolution::Invocation(invocation) = registry.route_text("/echo hello") else {
        panic!("expected echo invocation");
    };
    let (handler, arguments) = invocation.into_parts();
    let execution = handler
        .execute(
            CommandContext::text("test", "session", Vec::new()),
            arguments,
        )
        .await
        .unwrap();
    let CommandExecution::Reply(reply) = execution else {
        panic!("expected command reply");
    };

    assert_eq!(reply, Some(ChannelReply::new("Echo: hello")));
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

    let invalid_remaining = CommandNode::new("ask", "Ask one agent")
        .argument(Argument::required_remaining("prompt", "Prompt"))
        .argument(Argument::required("agent_name", "Agent name"))
        .handler(TestHandler::Run);
    assert_eq!(
        CommandRegistry::new()
            .register(invalid_remaining)
            .unwrap_err()
            .to_string(),
        "remaining argument is not last in /ask: prompt"
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
    let commands = command_runtime(&dispatcher);
    let registry = commands.registry();

    Daemon::route_channel_task(
        &channel,
        &[],
        &dispatcher,
        &commands,
        CommandTestTask::new("ask-help", "chat-1", "/ask help"),
        &mut runs,
    )
    .await
    .unwrap();
    Daemon::route_channel_task(
        &channel,
        &[],
        &dispatcher,
        &commands,
        CommandTestTask::new("stop-help", "chat-1", "/stop help"),
        &mut runs,
    )
    .await
    .unwrap();
    Daemon::route_channel_task(
        &channel,
        &[],
        &dispatcher,
        &commands,
        CommandTestTask::new("reset-help", "chat-1", "/reset help"),
        &mut runs,
    )
    .await
    .unwrap();
    Daemon::route_channel_task(
        &channel,
        &[],
        &dispatcher,
        &commands,
        CommandTestTask::new("root-help", "chat-1", "/help"),
        &mut runs,
    )
    .await
    .unwrap();

    assert_eq!(
        replies.lock().unwrap().as_slice(),
        [
            command_reply(registry, "/ask help"),
            command_reply(registry, "/stop help"),
            command_reply(registry, "/reset help"),
            command_reply(registry, "/help"),
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
async fn execution_stops_all_agents_only_in_the_current_session() {
    let scheduler = ExecutionScheduler::default();
    let (_codex_ticket, codex) = scheduled_run(&scheduler, run_scope("lark", "chat-1", "codex"));
    let (_reviewer_ticket, reviewer) =
        scheduled_run(&scheduler, run_scope("lark", "chat-1", "reviewer"));
    let (_other_ticket, other_session) =
        scheduled_run(&scheduler, run_scope("lark", "chat-2", "codex"));

    assert_eq!(
        scheduler.stop("lark", "chat-1", None),
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
async fn execution_stops_only_the_named_agent() {
    let scheduler = ExecutionScheduler::default();
    let (_codex_ticket, codex) = scheduled_run(&scheduler, run_scope("lark", "chat-1", "codex"));
    let (_reviewer_ticket, reviewer) =
        scheduled_run(&scheduler, run_scope("lark", "chat-1", "reviewer"));

    assert_eq!(
        scheduler.stop("lark", "chat-1", Some("codex")),
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
    let interrupts = Arc::new(Mutex::new(Vec::new()));
    let replies = Arc::new(Mutex::new(Vec::new()));
    let channel = CommandTestChannel {
        tasks: VecDeque::new(),
        events: Arc::clone(&events),
        contexts: Arc::clone(&contexts),
        interrupts: Arc::clone(&interrupts),
        replies: Arc::clone(&replies),
    };
    let dispatcher =
        AgentDispatcher::new(SessionStore::open(temp.path().join("store.db")).unwrap());
    let mut runs = tokio::task::JoinSet::new();

    Daemon::route_channel_task(
        &channel,
        std::slice::from_ref(&agent),
        &dispatcher,
        &command_runtime(&dispatcher),
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
        &command_runtime(&dispatcher),
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

    assert!(interrupts.lock().unwrap()[0].trigger());
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

    assert!(interrupts.lock().unwrap()[1].trigger());
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
async fn execution_stops_every_run_using_a_reset_session_key() {
    let scheduler = ExecutionScheduler::default();
    let shared = SessionKey::new("codex", IsolationScope::Shared);
    let other = SessionKey::new("reviewer", IsolationScope::Shared);
    let (_lark_ticket, lark) = scheduled_run(
        &scheduler,
        ExecutionScope::new("lark", "chat-1", shared.clone()),
    );
    let (_telegram_ticket, telegram) = scheduled_run(
        &scheduler,
        ExecutionScope::new("telegram", "chat-2", shared.clone()),
    );
    let (_reviewer_ticket, reviewer) =
        scheduled_run(&scheduler, ExecutionScope::new("lark", "chat-1", other));

    assert_eq!(
        scheduler.stop_session_keys(std::slice::from_ref(&shared)),
        vec!["codex".to_string()]
    );
    assert_eq!(lark.cancelled().await, AgentRunCancellation::Stopped);
    assert_eq!(telegram.cancelled().await, AgentRunCancellation::Stopped);
    assert!(
        timeout(Duration::from_millis(20), reviewer.cancelled())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn execution_interrupts_every_run_during_process_shutdown() {
    let scheduler = ExecutionScheduler::default();
    let (_codex_ticket, codex) = scheduled_run(&scheduler, run_scope("lark", "chat-1", "codex"));
    let (_reviewer_ticket, reviewer) =
        scheduled_run(&scheduler, run_scope("lark", "chat-2", "reviewer"));

    assert_eq!(scheduler.interrupt_all(), 2);
    assert_eq!(codex.cancelled().await, AgentRunCancellation::Interrupted);
    assert_eq!(
        reviewer.cancelled().await,
        AgentRunCancellation::Interrupted
    );
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
        interrupts: Arc::new(Mutex::new(Vec::new())),
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
    let commands = Arc::new(command_runtime(&dispatcher));

    let daemon = tokio::spawn(Daemon::run_channel(
        channel,
        vec![agent],
        dispatcher,
        commands,
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
        [ChannelReply::new("已停止 1 个 Agent：codex-dev。")]
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

    let active_ticket =
        dispatcher
            .scheduler
            .enqueue(ExecutionScope::new("telegram", "chat-2", key.clone()));
    let active_control = active_ticket.control();
    let active_run = tokio::spawn(async move {
        assert_eq!(
            active_control.cancelled().await,
            AgentRunCancellation::Stopped
        );
        drop(active_ticket);
    });

    let replies = Arc::new(Mutex::new(Vec::new()));
    let channel = CommandTestChannel {
        tasks: VecDeque::new(),
        events: Arc::new(Mutex::new(Vec::new())),
        contexts: Arc::new(Mutex::new(Vec::new())),
        interrupts: Arc::new(Mutex::new(Vec::new())),
        replies: Arc::clone(&replies),
    };
    let mut runs = tokio::task::JoinSet::new();
    Daemon::route_channel_task(
        &channel,
        std::slice::from_ref(&agent),
        &dispatcher,
        &command_runtime(&dispatcher),
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
        [ChannelReply::new("重置成功。")]
    );

    let mut output = IgnoreAgentOutput;
    dispatcher
        .execute_agent(
            &key,
            &agent,
            AgentTask::new("next task"),
            AgentRunControl::new(),
            &mut output,
        )
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
        interrupts: Arc::new(Mutex::new(Vec::new())),
        replies: Arc::clone(&replies),
    };
    let mut runs = tokio::task::JoinSet::new();
    Daemon::route_channel_task(
        &channel,
        std::slice::from_ref(&agent),
        &dispatcher,
        &command_runtime(&dispatcher),
        CommandTestTask::new("reset", "chat-1", "/reset"),
        &mut runs,
    )
    .await
    .unwrap();

    assert_eq!(store.get(&key).unwrap().as_deref(), Some("old-session"));
    assert_eq!(
        replies.lock().unwrap().as_slice(),
        [ChannelReply::new("以下 Agent 重置失败：codex-dev。")]
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
    let replies = Arc::new(Mutex::new(Vec::new()));
    let channel = CommandTestChannel::new(Arc::clone(&replies));
    let mut runs = tokio::task::JoinSet::new();

    Daemon::route_channel_task(
        &channel,
        std::slice::from_ref(&agent),
        &dispatcher,
        &command_runtime(&dispatcher),
        CommandTestTask::new("reset", "chat-1", "/reset"),
        &mut runs,
    )
    .await
    .unwrap();

    assert_eq!(store.get(&key).unwrap(), None);
    assert_eq!(
        replies.lock().unwrap().as_slice(),
        [ChannelReply::new("重置成功。")]
    );
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

fn agent_status_with_button(name: &str, enabled: bool) -> ChannelAgentStatus {
    let (text, style, command) = if enabled {
        ("禁用", ChannelButtonStyle::Default, "disable")
    } else {
        ("启用", ChannelButtonStyle::Primary, "enable")
    };
    ChannelAgentStatus::new(name, enabled).with_button(ChannelButton::new(
        text,
        style,
        CommandRequest::new(["ask", command]).with_argument("agent_name", name),
    ))
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
    input: ChannelTaskInput,
}

impl CommandTestTask {
    fn new(task_id: &str, session_id: &str, content: &str) -> Self {
        Self {
            task_id: task_id.to_string(),
            session_id: session_id.to_string(),
            input: ChannelTaskInput::Message(TaskContent::new(content)),
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
            input: ChannelTaskInput::Command(
                CommandRequest::new(["ask", if enabled { "enable" } else { "disable" }])
                    .with_argument("agent_name", agent_name),
            ),
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

    fn input(&self) -> &ChannelTaskInput {
        &self.input
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
    interrupts: Arc<Mutex<Vec<InterruptCallback>>>,
    replies: Arc<Mutex<Vec<ChannelReply>>>,
}

impl CommandTestChannel {
    fn new(replies: Arc<Mutex<Vec<ChannelReply>>>) -> Self {
        Self {
            tasks: VecDeque::new(),
            events: Arc::new(Mutex::new(Vec::new())),
            contexts: Arc::new(Mutex::new(Vec::new())),
            interrupts: Arc::new(Mutex::new(Vec::new())),
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
        if let Some(interrupt) = context.interrupt {
            self.interrupts.lock().unwrap().push(interrupt);
        }
        Ok(CommandTestRun {
            events: Arc::clone(&self.events),
        })
    }

    async fn reply(&self, _task: &Self::Task, reply: ChannelReply) -> Result<()> {
        self.replies.lock().unwrap().push(reply);
        Ok(())
    }
}
