# Agora Spec

Agora is a context-isolated multi-agent collaboration runtime.

The project starts from one narrow capability: a local node receives tasks from external channels, invokes real agent tools, and streams execution events back to the channel. Long term, this grows into infrastructure for specialist agents to discover each other, exchange artifacts, and complete work under explicit context, permission, and audit boundaries.

This directory records product direction, architecture boundaries, near-term milestones, and engineering conventions. Keep these documents aligned with code changes that affect module responsibility, runtime behavior, public APIs, protocols, data flow, security assumptions, or operational expectations.

## Documents

- [Long-Term Vision](vision/long-term.md)
- [Short-Term Goal](vision/short-term.md)
- [Project Modules](architecture/modules.md)
- [Agent Channel](architecture/agent-channel.md)
- [Local Session Store](architecture/local-store.md)
- [Node Configuration](architecture/node-config.md)
- [Node Process Lifecycle](architecture/process-lifecycle.md)
- [Sandbox Network](architecture/sandbox-network.md)
- [Sandbox Executable Cache](architecture/sandbox.md)
- [Milestones](roadmap/milestones.md)
- [Engineering Conventions](engineering/conventions.md)

## Current Focus

The current focus is the Agent Channel MVP:

```text
external channel
  -> agora-node daemon
  -> persistent channel-session-to-agent-session mapping
  -> configured agent implementation
  -> agent-owned execution, currently a one-shot command
  -> streamed run events back to channel
```

Marketplace, billing, automatic planning, rich eval, and enterprise governance are intentionally out of scope for the first implementation pass.
