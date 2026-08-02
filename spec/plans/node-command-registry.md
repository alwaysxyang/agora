# Node Command Registry

## Goal

Use one recursively registered command tree for slash-command text and channel-native controls. A command may execute directly, contain subcommands, or do both. The command subsystem owns parsing, structured invocation, argument validation, generated help, and execution while remaining separate from channels and agents.

The command runtime is a stable control boundary. Existing stop, reset, ask-control, persistence, cancellation, queue advancement, session reset, Lark card update, and Telegram fallback behavior remains unchanged while the `ask` root gains an explicit selected-agent prompt form.

## Command Tree

The generic registry stores `CommandNode<H>` values. Every node registers:

- a unique name within its parent;
- a short description;
- zero or more ordered argument definitions;
- an optional handler identifier of generic type `H`;
- public or internal exposure;
- zero or more child `CommandNode<H>` values.

Each argument registers its name, whether it is required, its purpose, and whether the final argument consumes all remaining text tokens. Required arguments must precede optional arguments, and a remaining-text argument must be last.

Nodes can be nested to arbitrary depth. A node with a handler has a default behavior, so `/stop codex-dev` invokes the `stop` node directly with `agent_name=codex-dev`. The `ask` node has both a default handler and children: `/ask codex-dev review this project` captures `agent_name=codex-dev` and `prompt=review this project`, while `/ask enable codex-dev` descends to the exact `enable` child before invoking its handler. Invoking `/ask` without its required default arguments displays node help.

Public nodes may be resolved from text or structured invocation and appear in generated help. Internal nodes may be invoked only through a structured request and never appear in help. The Lark run-card stop control uses an internal command carrying the source task id and agent name. Ask toggle buttons structurally invoke the same public enable or disable handlers used by text commands.

The built-in tree is:

```text
root
├── stop [agent_name]
├── reset
└── ask {agent_name} {prompt...}
    ├── list
    ├── status {agent_name}
    ├── disable {agent_name}
    └── enable {agent_name}
```

## Input And Resolution Rules

The channel boundary carries one neutral input:

```rust
pub enum ChannelTaskInput {
    Message(TaskContent),
    Command(CommandRequest),
}

pub struct CommandRequest {
    path: Vec<String>,
    arguments: BTreeMap<String, String>,
}
```

Native callback payloads place the request under one reserved `agora_command` field. Channels recognize that generic envelope and serialize or deserialize the request without matching command names or interpreting arguments. Callbacks without the reserved field retain the channel's normal ignore behavior.

For message text, the registry resolves one of three internal results:

- `AgentInput` when input does not start with `/`;
- `Invocation(CommandInvocation<H>)` after resolving a handler and validated named arguments;
- `Reply(String)` for generated help, unknown commands, unknown subcommands, or invalid arguments.

At each node an exact child name is matched before the current node's handler is considered. If no child matches and the node has a handler, remaining tokens are positional arguments for that handler; a registered final remaining-text argument joins all of its tokens with spaces. If no invocation tokens are present and a node with required default arguments also has children, the node renders help. If the node has no handler, an absent token renders node help and an unknown token returns a command-specific error.

Structured resolution locates the same registered node and produces the same validated named arguments. It rejects unknown paths, missing or extra arguments, and attempts to invoke an internal command through text.

The immutable registry is constructed once when the daemon starts. Registration rejects reserved names, duplicate siblings, arguments on nodes without handlers, duplicate argument names, required arguments after optional arguments, and any remaining-text argument that is not last.

## Help Behavior

- `/help` lists every root command with its description and tells the user to run `/{command} help` for details.
- Internal commands and command groups are absent from root, node, and recursive help.
- `help` is a registry-provided reserved token at every command depth and is never passed to a handler.
- `/ask help`, `/stop help`, and `/reset help` render help for those nodes.
- `/ask enable help` renders the leaf command's usage and argument meaning.
- Invoking a command group without a handler renders its help. `/ask` also renders the same output as `/ask help` because its default handler requires arguments and the node has subcommands.
- Root help shows command entry points only. Node help shows the node's own usage and arguments plus its immediate subcommands. Deeper details remain available through recursive `{command path} help` requests.

## Module Boundaries

The implementation lives under `agora-node/src/daemon/command/`:

- `mod.rs` owns `CommandRuntime`, constructs the built-in tree, and exposes only neutral command outcomes to daemon composition;
- `registry.rs` contains generic `CommandRegistry<H>`, `CommandNode<H>`, argument parsing, validation, and help rendering;
- the private handler adapter performs the single async return-type erasure required by the heterogeneous recursive tree;
- `stop.rs`, `reset.rs`, and `ask.rs` each construct their own command subtree and own its runtime behavior.

The generic registry has no Agent, Channel, SQLite, or daemon runtime dependencies. Concrete command implementations use ordinary `async fn` or async closures. They do not mention `CommandFuture`, `Pin`, `Box::pin`, explicit handler lifetimes, or `async_trait`. A generic registration adapter accepts a handler returning `impl Future` and privately stores one boxed `'static` future because different async functions have different opaque return types.

The runtime does not enumerate command names or match a central handler enum. Adding a root command requires only its command module plus one registration in `command/mod.rs`; adding a subcommand is contained by its owning command module. The owned per-invocation `CommandContext` contains channel name, channel session id, subscribed agents, optional source message content, and whether the request came from text or a structured control. It contains no `AgentDispatcher` reference and no concrete Lark or Telegram implementation.

The daemon constructs `SessionStore` and `ExecutionScheduler` once and shares clones with `AgentDispatcher` and `CommandRuntime`. Each execution is admitted once and receives an execution ticket that combines FIFO position, cancellation control, and drop-based removal. `stop.rs` captures the scheduler; `reset.rs` captures the store and scheduler, using scheduler barriers for exclusive session deletion; `ask.rs` captures the store. `AgentDispatcher` retains only enabled-agent filtering, scheduler admission, agent execution, backend-session lookup and update, and run-event publication. It exposes no stop, reset, status, enable, or disable command methods.

`CommandRuntime` is the only command entry point visible to daemon composition. It returns a neutral pass-through for ordinary agent input, an optional channel reply for a consumed control command, or an exact selected-agent dispatch containing normalized task content. `/ask {agent_name} {prompt...}` uses the selected-agent dispatch to run only that subscribed agent and bypass the normal disabled-agent filter for one request. The command does not mutate persisted enablement, and the dispatcher does not know that the dispatch originated from `/ask`. The daemon does not import or match concrete commands, handler types, registry resolutions, or native action variants.

Interactive command replies use a neutral button description containing display text, channel-neutral style, and a `CommandRequest`. Ask commands attach Enable or Disable requests to Agent status replies. Active-run interruption is deliberately separate from commands: the daemon creates an `InterruptCallback` bound to one registered run and forwards it through `ChannelRunContext`. Lark stores it behind a private one-shot callback id and renders an `结束任务` button; Telegram may ignore the unsupported control while preserving textual output.

## Registered Inputs

```text
/help
/stop [{agent_name}]
/stop help
/reset
/reset help
/ask
/ask help
/ask {agent_name} {prompt...}
/ask list
/ask status {agent_name}
/ask status help
/ask disable {agent_name}
/ask disable help
/ask enable {agent_name}
/ask enable help
```

## Errors

- Unknown root commands include a `/help` hint.
- Unknown child commands include a help hint for the current command path.
- Missing or extra arguments return usage generated from the selected node.
- A targeted ask for an agent not subscribed to the current channel returns an unknown-agent reply and opens no run.
- Unknown, text-inaccessible, or invalid structured requests return a safe neutral command reply.
- Lark callbacks without the reserved command envelope retain their current ignore and acknowledgement behavior.
- A recognized command envelope with malformed required fields retains the current parsing-error and acknowledgement behavior.
- Control commands and help requests never reach an agent. The targeted ask handler explicitly converts its prompt into normalized agent input after validating the subscribed target.
- A malformed structured command never falls through to agent input.
- Store, cancellation, backend-session deletion, and channel delivery failures retain the existing daemon error path and logging behavior.

## Verification

1. Test generic registration, default handlers, nested subcommands, registration validation, remaining-text argument parsing, root help, and recursive node help.
2. Verify text and structured invocation execute the same registered handler.
3. Verify internal commands are absent from help and cannot be invoked through text.
4. Verify Lark round-trips a generic request without matching concrete command names.
5. Verify targeted ask selects only the requested subscribed agent, runs even when that agent is disabled, preserves the denylist row, and rejects unsubscribed names.
6. Retain existing stop, reset, ask controls, native callback, store, Lark rendering, and Telegram fallback tests as behavior-regression coverage.
7. Verify daemon composition does not match concrete commands or native actions and channel code contains no concrete command-action enum.
8. Run command tests, workspace tests serially, clippy with warnings denied, formatting, diff checks, and the spec checker when available. Every required check must finish with zero warnings and zero errors.
