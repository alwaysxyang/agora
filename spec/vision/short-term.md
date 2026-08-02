# Short-Term Goal

The short-term goal is to build the Agent Channel MVP.

This MVP proves that an external task source can deliver work to a local daemon, the daemon can invoke a real agent command, and execution output can be streamed back as structured run events.

## MVP Statement

Agora should support this flow:

```text
task arrives from a channel
  -> agora-node claims or accepts the task
  -> daemon routes the task to each subscribed configured agent
  -> daemon loads the opaque agent session mapped to this channel session
  -> a command-based agent invokes a real command as a one-shot child process
  -> the agent returns a neutral backend session update
  -> daemon persists that mapping for the next task
  -> the agent emits output chunks and returns final status
  -> channel sends run events back to the origin
```

## First User-Facing Scenario

The first scenario is local agent execution from a channel message:

- A user sends a task through a simple channel.
- The node daemon receives the task.
- The node starts a configured agent command.
- The user sees real-time progress.
- The node reports completion or failure.

This does not yet require multi-agent planning, marketplace discovery, billing, or eval.

## Short-Term Scope

In scope:

- `agora-node` as the local daemon process.
- Channel abstraction inside `agora-node`.
- Lark WebSocket channel for task intake and card output.
- One-shot command-based Codex and custom agents.
- SQLite-backed Codex session continuity keyed by channel session and configured agent.
- Recovery from a stale Codex session by starting one replacement session.
- One independent reply card per subscribed agent.
- Structured run event model.
- Basic logger and binary process lifecycle.

Out of scope:

- Agent marketplace.
- Billing and revenue sharing.
- Full agent registry.
- Automatic multi-agent planner.
- Long-term memory.
- Enterprise policy engine.
- Full sandbox enforcement.
- Persistent interactive PTY sessions.
- Persistence for in-flight runs and channel delivery cursors.
- Artifact store beyond minimal references needed by run events.

## Success Criteria

The first implementation pass is successful when:

- `agora-node` can run as a daemon-style binary.
- A channel can provide a task without knowing how the agent executes it.
- An agent can execute a task without knowing which channel requested it.
- Repeated tasks from one channel session can resume the corresponding agent session after a daemon restart.
- The shared command helper has no backend protocol, session, or channel knowledge.
- Output is represented as structured events before it is sent to a channel.
- Repeated output is chunked and rate-limitable by channel implementation.
- The process can report started, output chunk, completed, failed, and cancelled states.

The key proof is not many channels. The key proof is a clean boundary between channel transport, daemon routing, neutral session persistence, agent-owned execution, and future sandbox constraints.

The MVP does not inject skills, prompts, hooks, or channel-specific tools into an agent. It invokes the configured agent command and only schedules its input and output.
