# Local Store

`agora-node` persists backend session mappings and channel-session agent controls in SQLite. The default database path is `~/.agora/db/store.db`; the daemon creates its parent directory and database when it starts.

The store is a neutral node-local component. It does not import channel or agent implementations, parse Codex output, choose an isolation mode, or decide how a backend session is resumed. Channel adapters do not know that the store exists, and agent implementations only receive and return opaque session ids through the agent contract. The daemon owns both key derivation and policy application.

## Mapping Identity

The daemon derives one `IsolationScope` for each configured agent run:

```text
none:
  (shared, agent_name) -> agent_session_id

session:
  (session, agent_name, channel_name, channel_session_id) -> agent_session_id
```

`none` therefore gives one backend session to the configured agent across every channel and conversation. `session` gives each channel-qualified conversation its own backend session. Including `channel_name` prevents equal external ids from different channel adapters from colliding.

The reverse pair `(agent_name, agent_session_id)` is also unique. This prevents one backend session from being assigned to two scopes for the same agent while still allowing different agents to use equal backend-generated ids.

## Schema

Schema version 3 contains two tables plus two partial unique indexes. Earlier versions are intentionally not migrated during the development phase; an old local database must be removed before starting the new node.

The canonical schema is kept in `crates/agora-node/src/store/schema.sql` and embedded into the node binary at compile time with `include_str!`.

```sql
CREATE TABLE agent_sessions (
    isolation_scope     TEXT    NOT NULL CHECK (isolation_scope IN ('shared', 'session')),
    channel_name        TEXT,
    channel_session_id  TEXT,
    agent_name          TEXT    NOT NULL,
    agent_session_id    TEXT    NOT NULL CHECK (length(agent_session_id) > 0),
    created_at          INTEGER NOT NULL,
    updated_at          INTEGER NOT NULL,

    CHECK (
        (isolation_scope = 'shared' AND channel_name IS NULL AND channel_session_id IS NULL)
        OR
        (
            isolation_scope = 'session'
            AND channel_name IS NOT NULL
            AND channel_session_id IS NOT NULL
            AND length(channel_name) > 0
            AND length(channel_session_id) > 0
        )
    ),
    UNIQUE (agent_name, agent_session_id)
);
```

The shared-scope partial index is unique on `agent_name`. The session-scope partial index is unique on `(agent_name, channel_name, channel_session_id)`. Nullable channel columns therefore represent the shared scope explicitly without relying on empty-string sentinels or SQLite's `NULL` behavior in a composite unique constraint.

Timestamps are Unix milliseconds written by the node. Updating a mapping changes `agent_session_id` and `updated_at` while preserving `created_at`.

Per-conversation agent controls use a sparse denylist:

```sql
CREATE TABLE channel_session_agent_blocks (
    channel_name       TEXT NOT NULL CHECK (length(channel_name) > 0),
    channel_session_id TEXT NOT NULL CHECK (length(channel_session_id) > 0),
    agent_name         TEXT NOT NULL CHECK (length(agent_name) > 0),
    PRIMARY KEY (channel_name, channel_session_id, agent_name)
) WITHOUT ROWID;
```

The absence of a row means that the agent is enabled. A row disables that configured agent only for the identified frontend conversation. `channel_name` is part of the key because equal session ids from different adapters or configured channel instances must not collide. The table does not reference config-backed channel or agent definitions with foreign keys; stale rows are harmless and are ignored when the daemon merges persisted state with the current subscriptions.

## Execution Flow

For each accepted channel task and subscribed agent, the daemon:

1. Derives one `IsolationScope` from the agent mode, channel name, and normalized channel session id.
2. Uses the resulting `SessionKey` for both the process-local FIFO and persistent mapping.
3. Publishes `Queued { ahead }` while earlier tasks for that scope remain.
4. Publishes Started after reaching the front and reads the optional agent session id.
5. Invokes the agent without a session when no mapping exists, or asks the agent to resume the mapped session.
6. Saves a non-empty session id returned by the agent.

An agent outcome can leave the mapping unchanged, set a session id, or report that the supplied session does not exist. Missing-session recognition is backend-specific and therefore belongs to the agent implementation. When a supplied session is reported missing, the daemon conditionally removes the stale row, retries once without a session, and saves the replacement id returned by that run.

The per-key FIFO is process-local and owned by `ExecutionScheduler`. One execution ticket combines queue admission and cancellation state, then leaves automatically when its run completes, fails, or is cancelled so later positions advance. In `none`, all runs for one configured agent share one key and serialize across channels. In `session`, different channel sessions have different keys and may run concurrently. SQLite transactions and connection locks must not be held while an agent command runs.

For `/reset`, the daemon enqueues a barrier for every affected `SessionKey` before stopping existing runs. Once a barrier reaches the front, the daemon reads the mapped opaque session id, asks the agent to delete it when supported, and conditionally removes the row. A backend deletion failure preserves the row. The barrier remains until that reset attempt finishes, so a later task cannot read or replace the mapping concurrently; after successful removal, the next task starts without a backend session and persists the new id returned by the agent.

For ordinary agent input, the daemon reads the disabled-agent names for `(channel_name, channel_session_id)` before opening channel runs. Disabled agents therefore receive no ordinary task and create no run card. Existing running and queued tasks are not changed. `/ask disable`, `/ask enable`, and native channel toggle actions insert or remove one denylist row; `/ask list` and `/ask status` merge those rows with the agents currently subscribed to that channel. `/ask {agent_name} {prompt...}` is a one-request override: it may select a subscribed disabled agent without modifying the denylist row, so later ordinary messages continue to exclude that agent.

## Operational Rules

- Enable SQLite WAL mode and a bounded busy timeout.
- Reject unsupported schema versions instead of silently rewriting them.
- Treat an empty backend session id as invalid.
- Preserve mappings across daemon restarts.
- Do not persist channel credentials, agent commands, task content, or in-flight run state in these tables.
