# Telegram Channel Implementation Plan

**Goal:** Add an active Telegram text-input channel with topic-aware sessions
and Telegram Rich Message streaming output.

**Architecture:** Keep Telegram under `channel/telegram/` with three private
implementation files: `telegram_api.rs` for Bot API transport, `channel.rs` for
task normalization and channel traits, and `rich_message.rs` for `RunEvent`
state/rendering/streaming. The parent channel module composes Telegram through
the existing enum aggregation; agents and the daemon remain channel-neutral.

**Tech stack:** Rust 2024, Tokio, Reqwest 0.13, Serde/serde_json, Telegram Bot
API 10.2 Rich Messages, existing Agora channel/task traits.

**Execution constraint:** Run every task inline with the current agent. Do not
create subagents and do not create a Git commit unless the user separately asks
for one.

---

## File Map

- Create `crates/agora-node/src/channel/telegram/mod.rs`: private module wiring
  and narrow re-exports.
- Create `crates/agora-node/src/channel/telegram/channel.rs`: update-to-task
  normalization and `Channel` implementations.
- Create `crates/agora-node/src/channel/telegram/telegram_api.rs`: Bot API HTTP
  client, response envelopes, long polling, reply/send/edit methods, and draft
  id allocation.
- Create `crates/agora-node/src/channel/telegram/rich_message.rs`: run state,
  Rich Markdown renderer, coalescing, private draft lifecycle, and group edits.
- Create `crates/agora-node/src/channel/telegram/channel/tests/`: parsing,
  identity, polling, command reply, and API transport tests.
- Create `crates/agora-node/src/channel/telegram/rich_message/tests/`: pure
  rendering and streaming lifecycle tests.
- Modify `crates/agora-node/src/config.rs`: concrete Telegram config.
- Modify `crates/agora-node/src/channel/mod.rs`: Telegram enum aggregation.
- Modify `crates/agora-node/tests/config.rs`: Telegram config coverage.
- Modify `crates/agora-node/src/main.rs`: active Telegram CLI help.
- Modify `spec/architecture/agent-channel.md`: active adapter behavior.
- Modify `spec/architecture/node-config.md`: config and runtime contract.

## Task 1: Concrete Telegram Configuration

- [x] Add a failing config test proving a name-only Telegram entry is rejected:

```rust
#[test]
fn telegram_channel_requires_a_token() {
    let config = r#"{"channels":[{"type":"telegram","name":"telegram1"}],"agents":[]}"#;
    assert!(serde_json::from_str::<NodeConfig>(config).is_err());
}
```

- [x] Run `cargo test -p agora-node --test config telegram_channel_requires_a_token`
  and verify the assertion fails because the placeholder `NamedChannelConfig`
  currently accepts the entry.
- [x] Add `TelegramChannelConfig { name, token }`, use it in
  `ChannelConfig::Telegram`, and keep `ChannelConfig::name()` exhaustive.
- [x] Add a parsing test that pattern-matches `ChannelConfig::Telegram` and
  verifies both fields.
- [x] Re-run `cargo test -p agora-node --test config` and verify it passes.

## Task 2: Telegram Update Normalization

- [x] Attach `channel/telegram/channel/tests/` from `channel.rs` with
  `#[cfg(test)] mod tests;` and add failing tests for these JSON updates:

```rust
// Private chat
{"update_id":101,"message":{"message_id":7,"from":{"id":1,"is_bot":false},
 "chat":{"id":1,"type":"private"},"text":"hello"}}

// Forum topic
{"update_id":102,"message":{"message_id":8,"message_thread_id":44,
 "from":{"id":1,"is_bot":false},"chat":{"id":-1001,"type":"supergroup"},
 "text":"run tests"}}
```

  Assertions must cover `task_id`, `TaskContent.text`, reply target, and session
  ids `chat:1` and `chat:-1001:topic:44`.
- [x] Add tests proving media-only and empty-text messages return no task.
- [x] Add command tests proving `/stop@agora_bot codex` becomes
  `/stop codex`, while `/stop@another_bot` is ignored.
- [x] Run the Telegram channel test target and verify it fails before the
  parser exists.
- [x] Implement private Serde update/message/chat types and normalization in
  `channel.rs`. Keep the resulting `TelegramTask` limited to neutral
  `TaskContent` plus a private Telegram reply target.
- [x] Re-run the focused tests and verify they pass.

## Task 3: Bot API Client And Long Polling

- [x] Add local HTTP server tests for:
  - `getMe` reads the bot username;
  - `getUpdates` sends `offset`, positive `timeout`, and
    `allowed_updates=["message"]`;
  - an API envelope with `ok:false` returns a contextual error without exposing
    the bot token;
  - a 429 envelope exposes and honors `parameters.retry_after`;
  - `sendMessage` includes `reply_parameters.message_id` and optional
    `message_thread_id`.
- [x] Run the focused tests and verify they fail because `TelegramApi` does not
  exist.
- [x] Implement `TelegramApi` with this client policy:

```rust
reqwest::Client::builder()
    .pool_max_idle_per_host(10)
    .pool_idle_timeout(Some(Duration::from_secs(300)))
    .connect_timeout(Duration::from_secs(10))
    .timeout(Duration::from_secs(60))
    .build()?
```

- [x] Keep request URLs internal as `{base_url}/bot{token}/{method}` and ensure
  errors mention only the method and safe Telegram response fields.
- [x] Implement `TelegramChannel::recv` with an in-memory `VecDeque`, an
  in-memory next offset, one-time `getMe`, and one long poll per empty queue.
- [x] Add a test returning a mixed update batch and verify supported tasks are
  returned in order while the next request advances past every update id.
- [x] Re-run `cargo test -p agora-node --lib telegram_channel_tests`.

## Task 4: Rich Markdown State And Rendering

- [x] Add pure failing tests for a `TelegramRichContent` state:
  - queued/running/completed/failed/stopped/interrupted labels;
  - thinking-led phases ordered oldest first with no in-memory maximum count;
  - command and progress attachment to the current phase;
  - progress replacement by id without changing its original phase;
  - terminal command blocks with complete command text, status, and exit code;
  - completed/running/failed/stopped summary counts;
  - oldest-phase omission when a rendered process reaches Telegram limits;
  - answer chunks preserved in original order and original Markdown retained;
  - usage rendered only after terminal state;
  - failure and partial-answer wording.
- [x] Assert the generated Rich Markdown includes channel framing similar to:

```markdown
## codex-dev · Running

<details open><summary>任务过程 · 2 个阶段 · ✓ 1 项已完成</summary>

**01 · 思考过程**

> ✦ Inspect the project

**SHELL** · ✓ exit 0

<pre><code class="language-bash">$ cargo test</code></pre>

</details>
```

- [x] Run the tests and verify they fail before the renderer exists.
- [x] Implement run/content/progress state in `rich_message.rs`, mapping every
  `RunEvent` and `OutputEvent` without importing agent or daemon types.
- [x] Escape only Agora-owned/interpolated structural text where needed; append
  the final answer Markdown unchanged below `## Final answer`.
- [x] Re-run the pure renderer tests and verify they pass.

## Task 5: Private Draft Streaming

- [x] Add local HTTP tests proving a private run:
  - allocates a non-zero process-local draft id;
  - calls `sendRichMessageDraft` on `Started` and replies to no persistent
    message yet;
  - coalesces rapid output events into the latest draft update;
  - refreshes an active draft before Telegram's 30-second expiry;
  - calls `sendRichMessage` exactly once on a terminal event with the source
    reply parameters and topic id when present;
  - ignores duplicate terminal events.
- [x] Use paused Tokio time or a test-only timing constructor so the heartbeat
  and coalescing tests finish deterministically without real waits.
- [x] Run the focused tests and verify the missing transport behavior fails.
- [x] Implement `TelegramRichMessage` as an `Arc`-backed cloneable run with one
  mutex-protected state, a scheduled coalesced flush, and a private-chat draft
  heartbeat that stops after any terminal event.
- [x] Re-run private streaming tests and verify they pass without leaked tasks.

## Task 6: Group And Topic Streaming

- [x] Add local HTTP tests proving a group/topic run:
  - first event calls `sendRichMessage` with reply parameters and topic id;
  - returned `message_id` is retained;
  - later events call `editMessageText` with `rich_message` on the same message;
  - terminal state flushes immediately;
  - two agent runs use independent Telegram message ids and never overwrite
    each other.
- [x] Run the tests and verify they fail before group transport is connected.
- [x] Implement the group strategy behind the same content state, selecting the
  strategy from the normalized source chat kind.
- [x] Implement `TelegramRun::publish` by delegating only to the private Rich
  Message object.
- [x] Re-run Telegram Rich Message tests and verify both private and group paths
  pass.

## Task 7: Configured Channel Integration

- [x] Add a failing test proving `ConfiguredChannel::from_config` returns an
  active Telegram channel rather than `None`.
- [x] Add `Telegram` variants to `ConfiguredTask`, `ConfiguredRun`, and
  `ConfiguredChannel`, including exhaustive delegation for `name`, `recv`,
  `open_run`, and `reply`.
- [x] Keep `Local` and `Http` as the only inactive placeholder variants.
- [x] Re-run config, daemon, and Telegram tests.

## Task 8: CLI And Specification Consistency

- [x] Update `agora-node --help` text to describe Telegram fields `name` and
  `token`, and remove Telegram from the reserved channel list.
- [x] Add a Telegram JSON example without replacing the existing Lark example.
- [x] Update `spec/architecture/node-config.md` with the active config shape,
  text-only input, topic session behavior, and Rich Message streaming split.
- [x] Update `spec/architecture/agent-channel.md` to mark Telegram as an active
  adapter while preserving channel autonomy.
- [x] Verify no documentation claims Telegram image input, webhook intake, or
  cursor persistence is implemented.

## Task 9: Final Verification

- [x] Run `cargo fmt --all -- --check`; if it fails, run `cargo fmt --all` and
  re-run the check.
- [x] Run `cargo test -p agora-node --lib telegram_channel_tests`.
- [x] Run `cargo test -p agora-node --lib telegram_rich_message_tests`.
- [x] Run `cargo test -p agora-node`.
- [x] Run `cargo test --workspace`.
- [x] Run `cargo clippy --workspace --all-targets --all-features -- -D warnings`.
- [x] Run `just spec-check` when available; if unavailable or failing for an
  environment reason, report the exact reason.
- [x] Inspect `git diff --check`, `git status --short`, and the focused diff.
- [x] Confirm no token can appear in logs or error URLs, no production test is
  embedded in a source file, and no module beyond the narrow Telegram channel
  types is exported.
