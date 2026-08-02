# Lark Structured Agent Output Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reply to each incoming Lark message with a clean per-agent card that streams concise thinking and execution progress separately from the final answer.

**Architecture:** Add a backend-neutral output event module shared by agents, the daemon, and channels. `CodexAgent` owns Codex JSONL parsing and emits semantic thinking, progress, and answer events; `LarkAgentCard` owns reply delivery, bounded card state, rendering, and update coalescing. Agents and channels remain independent.

**Tech Stack:** Rust, Tokio, Reqwest, Serde JSON, Lark IM OpenAPI, Codex `exec --json`.

---

### Task 1: Neutral output events

**Files:**
- Create: `crates/agora-node/src/output.rs`
- Modify: `crates/agora-node/src/lib.rs`
- Modify: `crates/agora-node/src/agent/mod.rs`
- Modify: `crates/agora-node/src/agent/custom.rs`
- Modify: `crates/agora-node/src/channel/mod.rs`
- Modify: `crates/agora-node/src/daemon/mod.rs`
- Test: `crates/agora-node/tests/agent.rs`
- Test: `crates/agora-node/tests/daemon.rs`

- [x] **Step 1: Write failing tests for semantic output forwarding**

Update test outputs to collect this neutral event model:

```rust
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OutputEvent {
    Thinking { text: String },
    Progress {
        id: String,
        text: String,
        status: ProgressStatus,
    },
    CommandExecution {
        id: String,
        command: String,
        status: ProgressStatus,
        exit_code: Option<i32>,
    },
    Answer { text: String },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProgressStatus {
    Running,
    Completed,
    Failed,
}
```

Assert that custom-agent output becomes `OutputEvent::Answer` and that the daemon forwards the event unchanged inside a channel run event.

- [x] **Step 2: Run focused tests and verify the new event types are missing**

Run: `cargo test -p agora-node --test agent --test daemon`

Expected: compilation fails because `OutputEvent` and semantic forwarding do not exist.

- [x] **Step 3: Implement the neutral event boundary**

Create `output.rs`, export it from `lib.rs`, change `AgentOutput::write` to accept `OutputEvent`, and replace `RunEvent::OutputChunk` with `RunEvent::Output(OutputEvent)`. Keep the daemon as a pass-through adapter and classify custom stdout/stderr as `Answer`.

- [x] **Step 4: Run focused tests**

Run: `cargo test -p agora-node --test agent --test daemon`

Expected: all agent and daemon tests pass.

### Task 2: Codex JSONL thinking, progress, and final-answer classification

**Files:**
- Modify: `crates/agora-node/src/agent/codex.rs`
- Test: `crates/agora-node/tests/agent.rs`

- [x] **Step 1: Write failing Codex event tests**

Use the existing executable shell fixture to emit:

```json
{"type":"thread.started","thread_id":"thread-123"}
{"type":"item.completed","item":{"id":"reason-1","type":"reasoning","text":"Inspecting the channel path"}}
{"type":"item.started","item":{"id":"cmd-1","type":"command_execution","command":"cargo test","aggregated_output":"","exit_code":null,"status":"in_progress"}}
{"type":"item.completed","item":{"id":"cmd-1","type":"command_execution","command":"cargo test","aggregated_output":"ok","exit_code":0,"status":"completed"}}
{"type":"item.completed","item":{"id":"msg-1","type":"agent_message","text":"All checks passed"}}
{"type":"turn.completed","usage":{"input_tokens":1,"cached_input_tokens":0,"output_tokens":1,"reasoning_output_tokens":1}}
```

Assert one `Thinking`, one updated `CommandExecution`, one `Answer`, and one `Usage`. Assert both new and resumed command invocations include `--config model_reasoning_summary=concise`.

- [x] **Step 2: Run the Codex tests and verify failure**

Run: `cargo test -p agora-node --test agent codex_agent`

Expected: assertions fail because only completed agent messages are currently emitted.

- [x] **Step 3: Implement Codex semantic parsing**

Add `model_reasoning_summary=concise` to both command forms. Keep the latest `agent_message` pending; move an older pending message to completed progress when more work follows, and emit the last pending message as `Answer` on `turn.completed`. Map completed reasoning summaries to `Thinking`, command item lifecycle to typed `CommandExecution` events with stable ids, complete unmodified commands, and optional exit codes, concise file/todo milestones to `Progress`, and valid `turn.completed.usage` fields to neutral `Usage`. Preserve existing session and stderr behavior.

- [x] **Step 4: Run focused Codex tests**

Run: `cargo test -p agora-node --test agent codex_agent`

Expected: all Codex tests pass.

### Task 3: Reply card transport and execution-timeline rendering

**Files:**
- Create: `crates/agora-node/src/channel/lark/card.rs`
- Modify: `crates/agora-node/src/channel/lark.rs`
- Modify: `crates/agora-node/src/lib.rs`
- Create: `crates/agora-node/src/channel/lark/card/tests/mod.rs`
- Create: `crates/agora-node/src/channel/lark/card/tests/content.rs`
- Create: `crates/agora-node/src/channel/lark/card/tests/api.rs`
- Modify: `crates/agora-node/tests/lark_channel.rs`

- [x] **Step 1: Write failing reply-target and renderer tests**

Assert `LarkMessageEvent::reply_target()` retains the source `message_id`. Exercise a crate-internal card state and assert:

```text
header title = agent name
header status tag = Running / Completed / Failed
Thinking starts a numbered display phase
Command execution uses one light terminal container inside its phase
Progress or command updates with the same id replace the existing item
All process phases remain available oldest first, with entries inside each phase newest first
Final answer is rendered after a divider in its own section
An empty running card shows `> 正在等待 Agent 输出...` until the first output
Completed usage is rendered as four columns for Total, Input, Output, and Reasoning
```

- [x] **Step 2: Run Lark tests and verify failure**

Run: `cargo test -p agora-node --test lark_channel && cargo test -p agora-node --lib lark_card`

Expected: tests fail because reply targets use `chat_id` and the existing card stores one raw output string.

- [x] **Step 3: Implement reply delivery and card state**

Move card-specific state and rendering into `channel/lark/card.rs`. Replace `send_card` with a concrete `LarkApi::reply_card` call to:

```text
POST /open-apis/im/v1/messages/{source_message_id}/reply
```

Send `msg_type=interactive`, serialized card `content`, and `reply_in_thread=true` so every agent card appears in the message thread rooted at the user's request. Store the returned reply message id for later PATCH calls. Render Thinking, CommandExecution, and Progress in one lightly framed `任务过程` panel. Number thinking phases chronologically from `01`, append new phases at the bottom, and render the phase number and `✦` marker in blue. Keep process state unbounded, but limit each rendered process snapshot to 160 nested elements so the complete card stays below Lark's 200-element limit; remove the oldest complete phases from the snapshot, retain the newest phases, and report how many phases were omitted. Render every command as one compact light console whose shared outer container holds both a toolbar and the native command block. Put `SHELL` on the left and semantic-color status or exit code on the right of the toolbar, place the complete `$` command below it as a native fenced `bash` Markdown code block, and keep ordinary progress as status-marked text outside the console. The native code block provides monospace syntax presentation and horizontal scrolling for long command lines; the surrounding process panel remains collapsible. Render Final answer after a divider with a blue vertical title marker, render a temporary blockquote placeholder while the running card has no agent output, and render completed Usage through a four-column JSON 2.0 `column_set` when the backend supplies it. Failed runs render a safe, user-facing failure summary and collapsed technical note before any Partial answer while retaining the complete raw error only in daemon logs.

- [x] **Step 4: Run renderer and Lark tests**

Run: `cargo test -p agora-node --test lark_channel && cargo test -p agora-node --lib lark_card`

Expected: all reply-target and renderer tests pass.

### Task 4: Latest-snapshot card update coalescing

**Files:**
- Modify: `crates/agora-node/src/channel/lark/card.rs`
- Test: `crates/agora-node/src/channel/lark/card/tests/api.rs`

- [x] **Step 1: Write a failing coalescing test**

Use a local test HTTP listener and an injected Lark API base URL. Publish `Started`, several progress events in one burst, wait slightly longer than 400 milliseconds, and then publish `Completed`. Assert one reply request, at most one intermediate PATCH for the burst, and one terminal PATCH containing the latest state.

- [x] **Step 2: Run the coalescing test and verify failure**

Run: `cargo test -p agora-node --lib lark_card_coalesces_intermediate_updates_and_flushes_completion`

Expected: failure because every output event currently performs a blocking PATCH.

- [x] **Step 3: Implement one scheduled latest-state flush**

Track state and sent versions plus whether a flush is scheduled. `Started` awaits the initial reply. Intermediate output mutates state and schedules at most one task for the next 400-millisecond boundary; the task snapshots the newest state and logs patch failures. `Completed` and `Failed` synchronously flush the newest state, while an older scheduled task observes that its version is already sent and exits without a duplicate patch.

- [x] **Step 4: Run all Lark tests**

Run: `cargo test -p agora-node --test lark_channel && cargo test -p agora-node --lib lark_card`

Expected: all tests pass.

### Task 5: Verification and spec consistency

**Files:**
- Modify if implementation differs: `spec/architecture/agent-channel.md`

- [x] **Step 1: Format and run the complete test suite**

Run: `cargo fmt --all`

Run: `cargo test --workspace`

Expected: all tests pass.

- [x] **Step 2: Run static checks**

Run: `cargo clippy --workspace --all-targets -- -D warnings`

Run: `cargo fmt --all -- --check`

Run: `git diff --check`

Expected: all commands pass without warnings or formatting changes.

- [x] **Step 3: Check project spec tooling**

Run: `just spec-check` when `just` is installed. If unavailable, report that explicitly and manually compare the implementation against `spec/architecture/agent-channel.md`.
