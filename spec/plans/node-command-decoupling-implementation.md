# Node Command Decoupling Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan inline. Project rules prohibit subagents. Do not create commits unless the user explicitly requests one.

**Goal:** Unify text commands and native channel controls behind `CommandRuntime` while preserving every current user-visible behavior.

**Architecture:** Channels transport `ChannelTaskInput` and generic `CommandRequest` values without concrete action variants. Command modules capture shared runtime components and expose direct async handlers through one private boxed-future adapter. Daemon composition distinguishes only pass-through input from handled commands, while `AgentDispatcher` owns normal agent execution only.

**Tech Stack:** Rust 2024, Tokio, anyhow, serde_json, rusqlite, existing Lark JSON 2.0 and Telegram adapters.

---

### Task 1: Add Neutral Task And Button Contracts

**Files:**
- Modify: `crates/agora-node/src/task/mod.rs`
- Modify: `crates/agora-node/src/channel/mod.rs`
- Test: `crates/agora-node/src/daemon/command/tests/execution.rs`

- [ ] Add a failing contract test that constructs a message input and a structured request, verifies ordered command paths and named arguments, and verifies a generic channel button retains its request.
- [ ] Run `cargo test -p agora-node daemon::command::tests::execution::neutral_command_request_and_button_preserve_data -- --exact` and confirm the missing types fail compilation.
- [ ] Add `CommandRequest`, `ChannelTaskInput`, `ChannelButtonStyle`, and `ChannelButton`. Replace `ChannelTask::content` plus `ChannelTask::action` with `ChannelTask::input` and remove `ChannelAction`.

```rust
pub struct CommandRequest {
    path: Vec<String>,
    arguments: BTreeMap<String, String>,
}

pub enum ChannelTaskInput {
    Message(TaskContent),
    Command(CommandRequest),
}

pub struct ChannelButton {
    text: String,
    style: ChannelButtonStyle,
    command: CommandRequest,
}
```

- [ ] Add read-only accessors and builders without exposing mutable collections.
- [ ] Run the new contract test and existing channel-independent tests.

### Task 2: Add Public/Internal Resolution And Async Handler Adapter

**Files:**
- Modify: `crates/agora-node/src/daemon/command/registry.rs`
- Replace: `crates/agora-node/src/daemon/command/executor.rs`
- Modify: `crates/agora-node/src/daemon/command/mod.rs`
- Test: `crates/agora-node/src/daemon/command/tests/registry.rs`

- [ ] Add failing tests proving public handlers resolve from text and structured requests, internal handlers resolve only structurally, internal nodes are absent from help, and both inputs execute one registered async handler.
- [ ] Run the four focused registry tests and confirm failures before implementation.
- [ ] Add `CommandVisibility`, `route_text`, and `route_structured`. Structured resolution must validate named arguments against the selected node and produce the existing `CommandArguments` representation.
- [ ] Replace the borrowed function-pointer alias with a cloneable private adapter:

```rust
type BoxCommandFuture =
    Pin<Box<dyn Future<Output = Result<Option<ChannelReply>>> + Send + 'static>>;

#[derive(Clone)]
struct CommandHandler {
    inner: Arc<dyn Fn(CommandContext, CommandArguments) -> BoxCommandFuture + Send + Sync>,
}
```

- [ ] Give `CommandHandler::new` generic `F` and `Fut` parameters so registered command code supplies ordinary async closures. Keep the box and pin private to the adapter.
- [ ] Make `CommandContext` own channel name, session id, source task id, and subscribed agents. It must not contain `AgentDispatcher`.
- [ ] Run all command registry tests with zero warnings.

### Task 3: Move Command Behavior Out Of AgentDispatcher

**Files:**
- Modify: `crates/agora-node/src/daemon/mod.rs`
- Modify: `crates/agora-node/src/daemon/command/mod.rs`
- Modify: `crates/agora-node/src/daemon/command/stop.rs`
- Modify: `crates/agora-node/src/daemon/command/reset.rs`
- Modify: `crates/agora-node/src/daemon/command/ask.rs`
- Add: `crates/agora-node/src/daemon/execution.rs`
- Test: `crates/agora-node/src/daemon/command/tests/`

- [ ] Add failing tests that construct `CommandRuntime` from a shared store and execution scheduler and execute stop, reset, and ask without an `AgentDispatcher` in context.
- [ ] Change daemon construction to create `SessionStore` and `ExecutionScheduler` once, then pass clones into dispatcher and command runtime. Each task has one scheduler ticket containing both FIFO admission and its agent-layer `AgentRunControl`.
- [ ] Implement command-owned structs:

```rust
struct StopCommand { scheduler: ExecutionScheduler }
struct ResetCommand {
    store: SessionStore,
    scheduler: ExecutionScheduler,
}
struct AskCommand { store: SessionStore }
```

- [ ] Move stop, targeted stop, reset barrier, backend deletion, mapping removal, status query, and enable or disable behavior into those command modules.
- [ ] Keep ordinary-input enabled-agent filtering in `AgentDispatcher::start_channel_task`; it reads the shared store before opening runs. Exact selected-agent dispatches reuse the lower-level run path without applying that filter.
- [ ] Delete dispatcher methods `stop_runs`, `stop_task`, `reset_sessions`, `reset_agent_session`, `agent_statuses`, `enabled_agents`, and `set_agent_enabled` after their callers migrate.
- [ ] Run stop, reset, ask, queue, and shutdown tests.

### Task 4: Convert Channel-Native Controls To Generic Requests

**Files:**
- Modify: `crates/agora-node/src/channel/mod.rs`
- Modify: `crates/agora-node/src/channel/lark/channel.rs`
- Modify: `crates/agora-node/src/channel/lark/card.rs`
- Modify: `crates/agora-node/src/channel/lark/lark_api.rs`
- Modify: `crates/agora-node/src/channel/telegram/channel.rs`
- Test: `crates/agora-node/src/channel/lark/channel/tests/`
- Test: `crates/agora-node/src/channel/lark/card/tests/`
- Test: `crates/agora-node/src/channel/telegram/channel/tests/`

- [ ] Add failing tests for a generic `agora_command` callback round trip, ignored callbacks without that envelope, generic stop-button rendering, and generic ask-toggle rendering.
- [ ] Change `LarkTask` to store `ChannelTaskInput::Message` or `ChannelTaskInput::Command` while preserving its private message-versus-card reply target.
- [ ] Parse only the generic `agora_command` envelope. Do not match `stop_task`, `set_agent_enabled`, or any command path in Lark code.
- [ ] Extend `ChannelAgentStatus` with an optional generic button and `ChannelRunContext` with an optional run-bound `InterruptCallback`. Ask command replies own toggle request construction; active-run registration owns interrupt callback construction.
- [ ] Make `LarkReplyCard` render generic command buttons and `LarkAgentCard` register the run callback behind a private `agora_interrupt` id for its channel-native stop control. Preserve PATCH-versus-threaded-reply behavior.
- [ ] Keep Telegram text output unchanged and ignore unsupported button metadata.
- [ ] Run all Lark and Telegram channel tests.

### Task 5: Collapse Daemon Routing Into CommandRuntime

**Files:**
- Modify: `crates/agora-node/src/daemon/command/mod.rs`
- Modify: `crates/agora-node/src/daemon/mod.rs`
- Test: `crates/agora-node/src/daemon/command/tests/channel.rs`

- [ ] Add failing integration tests showing ordinary messages pass through, slash commands are handled, structured commands are handled, malformed commands never reach an agent, and native stop consumes the event without a new reply.
- [ ] Implement `CommandRuntime::handle` returning:

```rust
pub enum CommandOutcome {
    PassThrough,
    Reply(Option<ChannelReply>),
    Dispatch(AgentDispatch),
}
```

- [ ] Replace daemon matches on `ChannelAction`, `CommandResolution`, and concrete command helpers with one `CommandRuntime::handle` call.
- [ ] On pass-through, obtain neutral run buttons from `CommandRuntime`, pass them to dispatcher, and start only enabled agents. On replies, call the channel's existing reply method or return success for no reply. On exact dispatch, run only the selected agents with the normalized content supplied by the command.
- [ ] Delete obsolete executor exports, central handler aliases, and concrete command imports from daemon composition.
- [ ] Run the complete `daemon::command::tests` suite.

### Task 6: Documentation And Full Verification

**Files:**
- Modify: `spec/architecture/agent-channel.md`
- Modify: `spec/plans/node-command-registry.md`

- [ ] Update architecture wording from separate native actions to neutral structured command requests and one command runtime.
- [ ] Verify the documented Lark ACK, card PATCH, stop, reset, ask, queue, session, and Telegram behaviors remain unchanged.
- [ ] Run `cargo fmt --all -- --check`.
- [ ] Run `cargo test --workspace --all-targets --all-features -- --test-threads=1`.
- [ ] Run `cargo clippy --workspace --all-targets --all-features -- -D warnings`.
- [ ] Run `git diff --check`.
- [ ] Run the project spec checker when available. Every required command must finish with zero warnings and zero errors.
