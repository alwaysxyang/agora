# Milestones

Agora should be built by validating one hypothesis at a time.

## Milestone 0: Concept Narrowing

Goal: define Agora as a context-isolated multi-agent collaboration runtime, not a general agent social network.

Deliverables:

- Project spec.
- Workspace crate structure.
- Initial logger and binary skeletons.
- Clear short-term scope.

Exit criteria:

- The project can be explained in one sentence.
- The first implementation target is Agent Channel MVP.
- Non-goals are documented.

## Milestone 1: Agent Channel MVP

Goal: external tasks can reach a local node, execute a real agent command, and stream output back.

Deliverables:

- `agora-node` daemon loop.
- Lark WebSocket channel and interactive-card output.
- Command-based Codex and custom agent implementations.
- SQLite-backed mapping from each channel session to each agent session.
- Stale Codex session replacement and per-mapping execution serialization.
- One independent Lark card per subscribed agent.
- Run state machine.

Exit criteria:

- A task can be submitted through one channel.
- The node can execute a configured command.
- Output is streamed as structured events.
- Completion and failure are reported.

Persistent PTY agent implementations, in-flight run recovery, and channel delivery cursor persistence are deferred. The MVP resumes one-shot Codex executions through the local SQLite session mapping, which survives daemon restarts.

## Milestone 2: Context and Artifact Boundaries

Goal: move from raw text handoff to structured task and artifact exchange.

Deliverables:

- Task envelope.
- Run event model.
- Minimal artifact reference model.
- Context envelope model.
- Basic lineage between task input and agent output.

Exit criteria:

- Each agent invocation has explicit input, constraints, and expected output.
- Output can be referenced by downstream work without exposing full raw history.

## Milestone 3: Configurable Flow

Goal: support simple multi-step execution without hardcoding every sequence.

Deliverables:

- Flow definition model.
- DAG execution for simple workflows.
- Quality gate nodes.
- Controlled retry or rework loops.

Exit criteria:

- A user can define a simple flow.
- Failed quality gates can route work back to a previous step.
- Each iteration is separately visible and auditable.

## Milestone 4: Agent Registry

Goal: select agents by declared capability instead of hardcoded command names.

Deliverables:

- Agent card model.
- Capability tags.
- Input/output contract declarations.
- Runtime configuration per agent.
- Basic resolver.

Exit criteria:

- Multiple agent candidates can satisfy one role.
- The system can explain which agent was selected and why.

## Milestone 5: Evaluation

Goal: collect performance data from real runs.

Deliverables:

- Success and failure records.
- Cost and duration records.
- Rework count.
- User acceptance signal.
- Agent performance summary.

Exit criteria:

- Agent selection can use historical performance.
- Low quality or unreliable agents can be identified.

## Milestone 6: Local Sandbox

Goal: execute local tasks with clearer file, command, network, and secret boundaries.

Deliverables:

- Isolated workspace strategy.
- Command permission policy.
- Environment variable policy.
- Network policy.
- Artifact egress checks.
- Audit records.

Exit criteria:

- Each run has a clear local boundary.
- High-risk actions can be blocked or require confirmation.

## Milestone 7: Marketplace and Governance

Goal: expose agent discovery, workspace governance, billing, and reputation after execution data exists.

Deliverables:

- Agent publishing.
- Workspace allowlists.
- Pricing model.
- Billing ledger.
- Governance dashboards.

Exit criteria:

- Users can choose agents based on capability, cost, and reliability.
- Organizations can constrain which agents and tools are usable.
