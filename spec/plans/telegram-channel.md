# Telegram Channel Design

## Goal

Add a Telegram channel to `agora-node` that receives text messages through the
official Telegram Bot API, routes them through the existing neutral channel
boundary, and streams each subscribed agent's structured run output back as an
independent Telegram Rich Message.

The implementation must keep Telegram transport and rendering details inside
the Telegram channel. Agents remain unaware of Telegram, and the daemon keeps
composing channels and agents through `ChannelTask`, `ChannelRun`, `RunEvent`,
and `TaskContent`.

## Initial Scope

The first Telegram implementation supports:

- Bot API authentication with a configured bot token.
- Text and photo message intake through `getUpdates` long polling.
- Private chats, groups, supergroups, and forum topics visible to the bot.
- Topic-aware channel sessions.
- Slash commands through the existing daemon command pipeline.
- Rich, streaming run output for queued, running, completed, failed, stopped,
  and interrupted states.
- Independent output messages when multiple agents subscribe to one Telegram
  channel.
- Automatic retry for idempotent polling, draft, and edit requests after transient
  network and Telegram API failures.

The first implementation does not support generic file input, webhooks,
subscription filters, persistent update cursors, or inline mode. It supports an
inline stop button for active runs but does not expose generic command buttons.

## Configuration

Telegram is a concrete `ChannelConfig` variant rather than a reserved named
channel:

```json
{
  "type": "telegram",
  "name": "telegram1",
  "token": "123456:bot-token"
}
```

`name` is the stable channel name referenced by agent subscriptions. `token` is
the Bot API token and must not be logged. The public Bot API base URL remains an
implementation detail; tests may construct the API client with a local base URL.

## Module Boundary

Telegram lives under `agora-node/src/channel/telegram/`:

- `channel.rs` owns Telegram update normalization and implements `Channel`,
  `ChannelTask`, and `ChannelRun`.
- `telegram_api.rs` owns the bot token, HTTP client, Bot API request/response
  types, long polling, and Telegram error handling.
- `rich_message.rs` owns `RunEvent` state, Rich Markdown rendering, update
  coalescing, and terminal flushing.
- `mod.rs` keeps implementation modules private and re-exports only
  `TelegramChannel`, `TelegramTask`, and `TelegramRun` to the parent channel
  module.

`ConfiguredChannel`, `ConfiguredTask`, and `ConfiguredRun` gain Telegram enum
variants and delegate through the existing static trait boundary. No dynamic
trait object or `async_trait` is introduced.

## Message Intake

`TelegramChannel::recv` uses `getUpdates` with a positive long-poll timeout and
`allowed_updates = ["message", "callback_query"]`. A Bot API response can contain multiple
updates, so the channel keeps a bounded `VecDeque` containing only the supported
tasks from the current response. It returns queued tasks one at a time through
the existing `Channel::recv` contract.

The channel maintains the next `offset` in memory. It advances the offset for an
individual update only after that update has been ignored or fully materialized
as a task or callback. In particular, a photo download failure leaves the offset
unchanged so Telegram may redeliver the update. The next `getUpdates` request
confirms processed updates. A daemon restart does not restore the cursor;
Telegram retains unconfirmed updates according to its Bot API behavior.

Messages with non-empty `text`, a photo, or both become tasks. For a photo, the
channel downloads the largest available variant and creates one neutral image
attachment; a caption becomes task text. Unsupported messages and service
updates are ignored without producing an error. The implementation processes
exactly the updates Telegram delivers; Telegram privacy-mode and bot membership
settings determine which group messages are visible.

Before returning its first task, the API calls `getMe` once and remembers the
bot username. A command such as `/stop@my_bot` is normalized to `/stop` only
when the suffix matches the configured bot. A command addressed to another bot
is ignored. Ordinary message text is otherwise forwarded unchanged.

The implementation does not remove an existing webhook automatically. If
Telegram rejects `getUpdates` because a webhook is configured, the channel logs
a contextual error and keeps retrying with bounded backoff. Changing external
bot configuration remains an explicit operator action.

## Task And Session Identity

Each task contains:

- `task_id`: the Telegram `update_id` encoded as a string.
- `session_id`: `chat:{chat_id}` when no topic is present, or
  `chat:{chat_id}:topic:{message_thread_id}` for a topic.
- `TaskContent`: normalized text plus an optional downloaded image attachment.
- Reply target: `chat_id`, source `message_id`, optional `message_thread_id`, and
  chat kind.

The channel name remains part of the daemon's isolation key, so the generated
session identifier only needs to be collision-free within one Telegram channel.
Different topics in the same group therefore resume different backend sessions
when an agent uses `isolate: session`.

## Rich Output

`TelegramRichMessage` accumulates the same neutral events used by the Lark card:

- run state and queue depth;
- thinking updates, newest first;
- progress entries, newest first, with updates replacing an entry by id;
- answer chunks in original order;
- final token usage.

It renders an `InputRichMessage` through the Bot API `markdown` field. Telegram
Rich Markdown is compatible with GitHub Flavored Markdown where supported, so
the agent's final answer is passed through without a second Markdown parser.
Agora adds only channel-owned framing around it:

- agent name and run status;
- a collapsible `<details>` section for accumulated thinking;
- a collapsible `<details>` section for progress and its status summary;
- a `Final answer` or `Partial answer` heading;
- a compact usage footer after a terminal event;
- concise failure, stopped, or interrupted notices.

While a private-chat run is active, the newest thinking text may additionally
use Telegram's draft-only `<tg-thinking>` block. The persisted final message
uses `<details>` because thinking blocks are valid only in drafts.

## Streaming Strategy

Telegram restricts `sendRichMessageDraft` to private chats. The channel therefore
uses two transport strategies behind the same `TelegramRichMessage` state:

### Private Chat

1. The first queued, started, or output event calls `sendRichMessageDraft` with
   a non-zero run-local `draft_id`.
2. Later non-terminal events update the same draft id, which Telegram animates.
3. While the run is active, a low-frequency refresh keeps the ephemeral draft
   alive when the agent produces no event for close to 30 seconds.
4. A terminal event immediately calls `sendRichMessage` with the complete Rich
   Message and `reply_parameters.message_id` referencing the source message.
5. The final send persists the response; the draft remains an ephemeral preview
   and expires according to Telegram behavior.

### Group, Supergroup, Or Topic

1. The first event calls `sendRichMessage`, replies to the source message, and
   includes `message_thread_id` when present.
2. The returned Telegram `message_id` is retained by the run.
3. Later events call `editMessageText` with `rich_message` to update that same
   reply.

Both strategies coalesce non-terminal output for a short interval to avoid one
HTTP request per agent chunk. Queued, started, completed, failed, stopped, and
interrupted events flush immediately. Each agent run owns independent state,
draft id, and message id, so multiple subscribed agents never overwrite one
another.

## Command Replies

Slash-prefixed text still enters the existing daemon command parser rather than
an agent. `Channel::reply` sends a Telegram Rich Message reply to the source
message in the same topic. Agent runs continue to use independently updated Rich
Messages.

## Error Handling And Reconnection

`TelegramApi` decodes the standard Bot API response envelope. A non-successful
response becomes an error containing the method, Telegram error code, and safe
description, but never the token or complete request URL.

- Long-poll network and API errors return through `Channel::recv`; the daemon's
  existing channel loop logs the failure, waits, and polls again without
  terminating the process.
- Idempotent `getUpdates`, draft, and edit operations retry bounded transient
  failures. HTTP 429 responses honor Telegram's `retry_after` value.
- Non-idempotent sends are attempted once. Their errors are returned to the
  caller, and background flush logic does not blindly repeat an initial send.
- A malformed individual update is logged and skipped without discarding valid
  siblings in the same response.
- Command-reply and terminal run-output failures are returned synchronously
  through `Channel::reply` or `ChannelRun::publish`, following the existing
  daemon error path; they never panic.
- Terminal rendering is idempotent within one run so duplicate terminal events
  do not create additional messages.

The shared HTTP client uses the project's established connection and request
timeouts. Long polling uses a request timeout greater than the Telegram poll
timeout so a healthy empty poll is not mistaken for a network timeout.

## Testing

Tests remain outside production files under `tests/internal/` and are attached
to the corresponding production modules with test-only `#[path]` declarations:

- `tests/internal/telegram_channel.rs` covers update parsing, unsupported update
  filtering, offset advancement, command suffix normalization, chat/topic
  session identity, photo download/redelivery, reply targets, and
  configured-channel delegation.
- `tests/internal/telegram_rich_message.rs` covers event accumulation, newest-
  first thinking/progress order, status summaries, original answer Markdown,
  private draft/final behavior, group send/edit behavior, update coalescing,
  independent agent runs, delivery failures, non-idempotent retry boundaries,
  and terminal states.
- Config tests cover the Telegram token shape and reject the old name-only
  placeholder form.

Network tests use a local HTTP test server through a test-only API constructor;
they do not call Telegram. Tests are written before each production behavior and
must demonstrate the intended failure before implementation.

## Documentation Impact

`spec/architecture/agent-channel.md`, `spec/architecture/node-config.md`, and the
CLI help must describe Telegram as an active text-input, Rich Message-output
channel. Existing Lark behavior and all agent contracts remain unchanged.
