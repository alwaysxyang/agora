# Node Configuration

`agora-node` is the local daemon that runs on a user's machine. Its first configuration format separates reusable channels from local agents. A channel can be subscribed to by multiple agents.

The config should answer only the first practical questions:

- Which channel receives tasks for this agent?
- Which backend agent type and command should be started?
- Which workspace should the backend agent run in?
- How should backend session isolation be derived?

Daemon process settings such as pid files, state directory, log level, foreground/background mode, and worker limits should come from CLI flags or internal defaults, not from this first agent config format.

## Shape

```json
{
  "proxy": "127.0.0.1:7890",
  "channels": [
    {
      "type": "lark",
      "name": "lark1",
      "app_id": "xxx",
      "secret": "xxx"
    }
  ],
  "agents": [
    {
      "name": "codex-dev",
      "isolate": "none",
      "workspace": "/Users/example/work/agents",
      "type": "codex",
      "path": "/opt/homebrew/bin/codex",
      "model": "gpt-5.4",
      "effort": "xhigh",
      "agent_sandbox": "danger-full-access",
      "subscribe": [
        {
          "channel": "lark1",
          "filter": {}
        }
      ]
    }
  ]
}
```

This shape keeps channels and agents separate. `channels` defines named channel adapters. `agents` defines local agent entries with direct `isolate`, `type`, and `path` fields plus optional `workspace`, `model`, `effort`, `agent_sandbox`, and `proxy` overrides. The optional top-level `proxy` supplies the default HTTP proxy for every channel and agent that does not define its own value.

The config file should parse as one object with `channels` and `agents` lists. A list with one channel and one agent is valid. Adding another local agent should only require appending another object to `agents` and subscribing it to one or more existing channel names.

## Fields

`channels` lists reusable channel configurations. Each channel must have a stable unique `name`.

`agents` lists local backend agents that can subscribe to channels.

`name` is the stable local name for this agent config.

`isolate` controls backend session mapping and process-local FIFO isolation. It does not change the agent workdir.

Supported values:

- `none`
- `session`

`none` gives one configured agent a shared backend session across every subscribed channel and conversation. `session` gives each `(channel_name, channel_session_id)` conversation its own backend session for that agent.

`workspace` is the optional workdir used by every execution of this configured agent. When omitted, it defaults to `~/.agora/workspace` using the daemon user's home directory.

`type` describes the backend agent kind.

Supported initial agent `type` values:

- `codex`
- `coco`
- `claude_code`
- `custom`

`path` is the executable path, such as `/opt/homebrew/bin/codex`. For `custom`, the daemon treats the path as a generic one-shot command without backend-specific arguments.

`model` is an optional backend model override. `CodexAgent` passes it as `--model {model}`. When omitted or `null`, Codex uses its normal CLI and user-config resolution.

`effort` is an optional Codex reasoning-effort override. `CodexAgent` passes it as `--config model_reasoning_effort={effort}`. When omitted or `null`, Codex uses its normal model-specific default or user configuration. Values are forwarded to Codex rather than validated by Agora so supported effort levels can evolve with the CLI and selected model.

`agent_sandbox` is the optional sandbox policy of the backend agent. It is deliberately named separately from Agora's future runtime sandbox and from `isolate`, which controls backend conversation and queue boundaries rather than filesystem access. Supported values are `read-only`, `workspace-write`, and `danger-full-access`. When omitted or `null`, Codex uses its normal CLI and user-config resolution. When configured, `CodexAgent` passes the selected `sandbox_mode` and sets `approval_policy` to `never` because the daemon cannot service an interactive approval prompt. `danger-full-access` therefore gives the Codex child process the permissions of the daemon user and should only be enabled for trusted channel inputs.

`proxy` is an optional HTTP proxy in `host:port`, `http://host:port`, or `http://user:password@host:port` form. A component-level proxy overrides the top-level default. Agent processes receive the selected proxy through `HTTP_PROXY`, `HTTPS_PROXY`, `http_proxy`, and `https_proxy`. Lark and Telegram use the selected proxy for their HTTP transport; Lark also uses HTTP CONNECT for its WebSocket connection.

The `model`, `effort`, and `agent_sandbox` fields are currently consumed only by `CodexAgent`. Other agent implementations remain responsible for defining and interpreting their own backend-specific execution options. Agent configuration has no arbitrary child-process `env` field. Unknown agent fields, including the removed legacy `env` field, are ignored during deserialization and have no effect.

`subscribe` lists channel subscriptions this agent consumes. Each entry must include `channel`, the name of a configured channel. The same channel name may appear in multiple agents' `subscribe` lists.

`subscribe[].filter` is reserved for future channel-specific routing rules. The first implementation should parse it as optional raw JSON and should not assign behavior to its internal fields yet.

## Channel

A channel is responsible for receiving tasks and sending run events back to the origin. It should not spawn the backend agent directly.

Initial channel variants:

- `local`: reserved for local development and manual testing.
- `http`: reserved for task intake by polling and output by WebSocket.
- `lark`: active IM-style channel for daily use.
- `telegram`: active IM-style channel using the Telegram Bot API.

Example Lark channel:

```json
{
  "type": "lark",
  "name": "lark1",
  "app_id": "xxx",
  "secret": "xxx"
}
```

For the first Lark implementation, `app_id` and `secret` are used to obtain a tenant access token. Run output is sent as a Lark interactive card. The first run event sends the card, and later output chunks update the same card by message id. Cards used for this flow must set `config.update_multi` to `true`. Each subscribed agent opens an independent run and therefore sends an independent card.

If multiple agents subscribe to the same channel, each card must identify the replying agent so users can distinguish the responses.

For the local MVP, Lark message intake must use an in-process WebSocket long connection created from the configured `app_id` and `secret`. The daemon should not require `lark-cli`, shelling out to local developer tools, or a third-party Lark channel wrapper crate to receive events. The receive path should acknowledge Lark events promptly and hand normalized message tasks to the daemon for backend agent execution.

The Lark intake loop should reconnect indefinitely when the WebSocket disconnects, endpoint bootstrap fails, or the local network is temporarily unavailable. Reconnect attempts should use bounded backoff so a broken network does not cause a tight retry loop.

When a Lark channel uses an HTTP proxy, the complete WebSocket CONNECT handshake, including TCP connection, request write, and response-header read, has a 10-second timeout. A timeout fails that connection attempt and enters the normal reconnect path.

Example Telegram channel:

```json
{
  "type": "telegram",
  "name": "telegram1",
  "token": "123456:bot-token"
}
```

The Telegram channel uses `getUpdates` long polling and accepts text plus photo messages. It downloads the largest photo variant into a neutral image attachment before confirming that update. It keeps the update offset in memory, so a daemon restart may redeliver an update that Telegram has not yet observed as confirmed. A normal chat maps to `chat:{chat_id}`. A forum topic maps to `chat:{chat_id}:topic:{message_thread_id}` so different topics do not share an Agora channel session.

For private chats, each subscribed agent streams its run through an ephemeral Rich Message draft and replaces it with one persistent Rich Message when the run reaches a terminal state. For groups and forum topics, the channel sends one persistent Rich Message per subscribed agent and edits that message as output changes. Group replies retain `message_thread_id` when the source message belongs to a topic. Telegram output uses Rich Markdown for collapsible `思考过程` and `执行进度` sections while preserving the agent's final Markdown answer. Fixed node-authored copy is shared with the Lark renderer through `agora-node/src/i18n/`; agent-produced content is passed through unchanged.

Example HTTP channel:

```json
{
  "type": "http",
  "name": "http1",
  "base_url": "https://agora.example.com",
  "token": "xxx",
  "poll_interval_ms": 1000,
  "output": "websocket"
}
```

HTTP channel intake should use polling because local nodes may run behind NAT or firewalls. HTTP output should use WebSocket because backend agent output is streaming.

An agent can subscribe to multiple channel names. A channel implementation should stay reusable and should not embed agent-specific backend execution settings.

## CLI Entry

The first node binary starts from one config file containing named channels and flat agent configs:

```text
agora-node --config agent.json
```

`--config` loads one JSON object with `channels` and `agents`.

Task content, including text and neutral attachments, session identity, and reply targets should come from channel intake. The daemon CLI should not expose temporary task submission or channel-specific reply-target flags.

The daemon process is expected to stay resident. Transient channel receive errors, closed channel connections, and single task reply failures should be logged and retried or skipped without terminating the whole process.

## Backend Agent

The first Codex and custom agent implementations execute the configured `path` as a one-shot child process for every accepted message. One-shot process lifetime does not imply stateless Codex conversations: the daemon looks up an opaque backend session id for the current channel session before invoking the agent.

Agent `type` selects backend-specific command arguments and output normalization rules. A `codex` task without a mapped session runs as `codex exec --json --color never [configured options] [--image path] -`; a task with a mapped session runs as `codex exec resume --json [configured options] [--image path] {thread_id} -`. Codex image attachments are written to a temporary directory inside the selected workdir for one run and removed afterwards. Configured options include model, effort, and agent sandbox only when their corresponding fields are present. When a proxy is selected, the shared command helper injects only the standard HTTP proxy variables derived from that setting. `custom` executes `path` without implicit arguments, receives the same selected proxy variables, and rejects attachments because it has no generic attachment protocol. One-shot command forms for `coco` and `claude_code` remain unsupported until their native non-interactive contracts are implemented.

The daemon and configured agent process a normalized task like:

```text
ChannelTask
  -> SessionStore lookup
  -> AgentTask
  -> ConfiguredAgent
  -> agent-owned execution
  -> SessionStore update
  -> RunEvent
  -> Channel output
```

Command-based agents may use `agent::command::Command`, which writes input to stdin, delivers raw stdout and stderr bytes to an agent-provided handler, and reports the child exit status. The command helper does not know which channel requested the task, which agent uses it, how output is encoded, or whether a session exists.

`CodexAgent` supplies its own command arguments and JSONL handler. It consumes an optional opaque session id, extracts `thread.started.thread_id`, publishes `item.completed` agent-message text instead of raw JSON lines, and returns a neutral session update. It does not own the channel-to-agent session mapping. Other agents can reuse the command helper with another output handler or implement a different execution strategy entirely.

## Workspace And Workdir

`workspace` is the workdir for every execution of the configured agent. When it is absent from the JSON config, the daemon uses `~/.agora/workspace`. Session isolation never derives a child directory.

```text
none:    workdir = workspace
session: workdir = workspace
```

The configured agent creates `workspace` when it is missing before starting backend execution. Channel and session identifiers are not used as filesystem path components.

## Task, Session, And Run Identity

The daemon should keep these identifiers distinct:

- `task_id`: one external unit of work, such as one message or one HTTP task.
- `session_id`: the conversation or continuity boundary normalized by the channel.
- `run_id`: one concrete backend agent execution attempt.
- `external_session_id`: the source channel's original conversation, sender, thread, or job grouping id.
- `isolation_scope`: either the configured agent-wide shared scope or a channel-qualified session scope.

A single session can contain many tasks. A single task usually creates one run, but retries can create multiple runs for the same task.

The channel `session_id` and backend Codex thread id are separate concepts. For `none`, the agent name selects one persistent backend session mapping and one FIFO across every channel conversation. For `session`, channel session identity, together with `channel.name` and `agent.name`, selects a persistent backend session mapping. Consequently, a session-isolated agent can maintain many independent Codex conversations, while repeated tasks from the same channel session resume the same conversation. All conversations still execute in the configured `workspace`.

The mapping is stored in SQLite at `~/.agora/db/store.db`. The daemon derives one `IsolationScope` and uses it consistently for the persistent mapping and process-local FIFO. Executions for the same scope enter one FIFO; different scopes may execute concurrently in the same workspace. A waiting task publishes `Queued { ahead }` when admitted and whenever the number of tasks ahead changes, then publishes Started when it reaches the front. If Codex reports that a mapped thread no longer exists, `CodexAgent` classifies that backend response and the daemon retries the task once without a session before saving the replacement thread id.

## Isolation Modes

`none` runs all tasks for the agent in `workspace`, maps every channel conversation to one backend agent session, and serializes all executions for that agent. This is useful when the agent should behave as one continuous identity across every entry point, but it provides no conversation isolation.

`session` gives each channel-qualified conversation its own backend session and FIFO. Different conversations for the same configured agent may execute concurrently in the same configured workspace. This fits IM-style channels because a group, private chat, or thread usually expects continuity across messages without sharing model context with another conversation.

## Agent Card

Agent Card metadata is not part of the initial `agora-node` configuration. It belongs to the future agent registry and A2A-facing server boundary, where it can describe discoverable capabilities independently from local process execution settings. The node MVP config therefore contains only the fields needed to subscribe, execute, isolate, and resume local agents.

## Secrets

The example shape allows direct string values for early local testing.

Before using real channel credentials or proxy credentials in shared configs, introduce an explicit secret-reference form such as:

```json
{
  "secret": {
    "env": "AGORA_LARK_SECRET"
  }
}
```

The first implementation may start with direct strings, but channel and proxy credential fields should not be required to remain plain strings forever.

## Validation Rules

The daemon should reject invalid config before starting the channel:

- Channel `name` must be present and unique.
- Channel `type` must be present.
- Agent `name` must be present and unique.
- `isolate` must be `none` or `session`.
- When `workspace` is omitted, the daemon must resolve the default under the current user's home directory.
- An explicitly configured `workspace` should be absolute.
- Agent `type` must be present and supported.
- Agent `path` must be present.
- `model` and `effort`, when present, must be strings; Agora forwards their values to Codex without maintaining its own model or effort allowlist.
- `proxy`, whether top-level or component-specific, must use HTTP, include a valid host and non-zero port, and use `user:password` when credentials are present.
- Every `subscribe[].channel` value must reference an existing channel name.

## Initial Implementation Boundary

The active implementation should run the Lark long-connection or Telegram long-polling message intake, instantiate each configured agent once, use its configured workspace, look up the channel-session-to-agent-session mapping, run the agent's own execution implementation, persist any returned session update, and stream each subscribed agent's output through an independent channel-owned reply. The mapping survives daemon restarts; event cursors and in-flight runs do not.

The active implementation does not interpret `subscribe[].filter` or persist event cursors. Lark accepts text, post, and image messages; Telegram accepts text and photo messages. Both route slash-prefixed text to the daemon command pipeline instead of an agent. Telegram strips a matching `@bot_username` suffix from the command name and ignores commands explicitly addressed to another bot. `/stop` cancels active or queued agent runs in the current channel session, while `/stop {agent_name}` limits cancellation to one configured agent. `/reset` stops runs for every subscribed agent's derived isolation scope, serializes reset behind existing work and ahead of new work, deletes a supported backend session, and removes the local mapping so the next task starts a new session. `/ask {agent_name} {prompt...}` sends one prompt only to that subscribed agent and intentionally bypasses its current-conversation disabled state for that invocation without changing persistence. `/ask disable {agent_name}`, `/ask enable {agent_name}`, `/ask list`, and `/ask status {agent_name}` manage and inspect persisted agent intake controls for the current frontend conversation without changing the configured subscription or backend session. The daemon builds one immutable recursive command registry at startup. `/help` lists root commands, while `/{command path} help` renders generated usage for any registered node; command groups without a default handler render their help when invoked directly. Help returns channel-neutral multiline text. A queued or running Lark card also exposes an `结束任务` callback action backed by the exact run's one-shot `InterruptCallback`; invoking it lets later work in that FIFO advance without routing an internal command. Lark `/ask list` cards expose one command callback button per agent; Telegram falls back to text status. Task submission should still be modeled as channel intake rather than temporary CLI flags.

Do not move channel traits, agent traits, or config types into `agora-core` until `agora-server` or another crate truly needs them. `agora-node` owns these unstable boundaries for now.
