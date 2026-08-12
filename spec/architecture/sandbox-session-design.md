# Shared Sandbox Workspace Sessions

Status: implemented.

## Objective

Allow concurrent invocations of `agora-sandbox run` to use one persistent
filesystem view when they resolve to the same work directory and equivalent
runtime configuration. Each invocation may execute a different command and
retains its own terminal, process group, caller environment, working directory,
and exit status.

The user-facing command remains:

```bash
agora-sandbox run -c sandbox.json -e '<command>'
```

The first overlapping invocation starts a workspace session. Later overlapping
invocations join that session. The session stops after its final command exits.

## Constraints

- One runtime owner must hold `<workdir>/fs/.fs.lock` for the complete session.
- All entries must share the same encrypted local Broker, plaintext vnodes,
  per-inode lock anchors, NFS Broker, network controller, execution controller,
  audit controller, and runtime files.
- The existing encrypted content and metadata formats do not change.
- Existing Hook-to-Broker protocols and descriptor transfer do not change.
- Child terminal traffic must not be proxied through the session owner.
- Plaintext content must not gain a host-visible path.
- Normal shutdown correctness is required. Crash or power-loss recovery is not
  added.
- The SDK's existing one-command `Sandbox::run` API remains available.

## Architecture

`Sandbox::run` is refactored around an internal `SandboxRuntime`. The runtime
owns the filesystem workspace lock and every controller that is currently
created inside one call to `Sandbox::run`. It can prepare more than one launch
while it is alive and performs controller shutdown and final encrypted
writeback exactly once.

The CLI adds a per-workspace session layer:

```text
run client A ----\
run client B ----- session UDS ---- session daemon ---- SandboxRuntime
run client C ----/                         |             |-- Local Broker
                                            |             |-- NFS Broker
                                            |             |-- Network
                                            |             |-- Execution
                                            |             `-- Audit
                                            `-- active launch leases
```

The session daemon is the same `agora-sandbox` binary running a hidden internal
subcommand. It is an ephemeral per-workspace helper rather than a machine-wide
service. It owns the shared runtime but never owns a client's terminal.

The runtime assigns one `sandbox_id` and one callback-visible `run_id` to the
session. Each launch receives a distinct root trace ID and internal launch ID,
which distinguish its process, file, and network activity without widening the
existing audit and network protocols. A later non-overlapping session receives
new identifiers.

## Discovery And Startup

The client canonicalizes the configured work directory. A short deterministic
socket path is derived from the effective UID and SHA-256 of that canonical
path beneath a mode-0700 per-user directory in `/tmp`. This avoids Darwin Unix
socket path-length limits without persisting a secret or plaintext data.

Startup is serialized by `<workdir>/runtime/session-start.lock`:

1. Try to connect to the deterministic session socket.
2. On a missing or refused socket, acquire the startup lock and retry.
3. If no live session answers, start the hidden daemon through `current_exe`.
4. Pass an inherited readiness channel to the daemon.
5. The daemon validates the configuration, acquires `.fs.lock`, starts every
   runtime controller, binds and secures the session socket, and reports ready.
6. The daemon inherits and retains the startup lock for its complete lifetime;
   the client connects after the readiness response.

Only the daemon holds `.fs.lock`. Concurrent daemon candidates therefore cannot
own one workspace. A stale same-user socket is removed only while holding the
startup lock and after connection failure. The new daemon then acquires
`.fs.lock`; an old one-shot runner that holds that lock but has no session
endpoint remains a clear `filesystem is already in use` error.

The daemon detaches from the launching terminal, redirects its standard streams
away from the client terminal, and writes lifecycle, NFS, and audit records only
through the configured project logger.

## Session Protocol

The session uses the repository's bounded JSON framing over a Unix domain
socket. Session messages do not transfer descriptors. The socket directory is
mode 0700, the socket is mode 0600, and the server verifies the peer effective
UID with the native peer-credential API before returning runtime secrets.

The initial `Join` carries the session protocol version, build identity, and
configuration identity. Every frame is bounded by the existing 1 MiB
control-frame limit. Non-UTF-8 paths, arguments, and environment values use
validated byte-string wire wrappers.

The logical exchange is:

```text
Client -> Join(version, build identity, config identity)
Server -> Joined(session identity)
Client -> Prepare(resolved executable)
Server -> Prepared(launch ID, prepared command, protected environment)
Client -> Finished(launch ID)
Server -> Released
```

The server may send `RuntimeFailed` while a prepared launch lease is active. The client then terminates
its own process group using the existing graceful-then-forced termination path
and reports the runtime failure instead of presenting it as the child status.

The typed, default-expanded, path-resolved runtime configuration has a
deterministic semantic encoding. Its SHA-256 identity includes all fields that
affect filesystem mode and key, NFS routes and credentials, network and TLS,
Hook compatibility, audit, and logging. The digest is exchanged only over the
owner-only socket and is never persisted or logged. JSON formatting and object
key order do not affect it. A protocol, build, or configuration mismatch is
rejected before preparing a command.

## Launching A Command

The run client resolves the requested executable against its own explicit
command environment, inherited `PATH`, and working directory before sending the
request. This preserves the current caller-relative launch semantics without
copying the caller's complete environment into the daemon. The daemon prepares
that resolved executable with the shared execution controller, including
Mach-O preparation and shebang adjustment. It returns a launch specification
containing:

- the prepared executable and adjusted arguments;
- protected environment additions for Hook injection, controller endpoints and
  tokens, filesystem mode and derived key, NFS routes, TLS trust, and trace;
- protected environment removals that prevent stale nested runtime values.

The run client combines that protected specification with the current caller's
ordinary environment and working directory, then spawns the child locally. It
reuses the existing foreground-terminal handoff, independent process group,
signal handling, wait, and process-group termination logic. Standard input,
output, and error therefore remain direct terminal file descriptors and do not
cross the session socket.

A spawn or terminal-handoff failure cancels the prepared launch lease.

## Filesystem Data Plane

The session layer does not proxy filesystem reads and writes.

- Native lower reads continue to use host descriptors directly.
- Overlay lookup and namespace mutations continue in the Hook under the short
  `.vfs.lock` transaction boundary.
- A plain-upper mutating open holds a per-file staging lease through native
  descriptor creation and `cow` publication. Reconciliation skips orphan
  cleanup while that lease is active, closing the cross-process interval in
  which another client could otherwise discard the new upper file without
  holding the global VFS transaction across native work. Encrypted opens retain
  that lease for their existing Broker path.
- An encrypted upper open connects to the shared Local Broker. The Broker keys
  its weak plaintext cache by ciphertext device and inode, reuses one anonymous
  plaintext vnode, creates an independent logical-open state descriptor, and
  sends content, state, and lock descriptors through the existing
  `SCM_RIGHTS` protocol.
- Hooked `read`, `write`, positioned and vector I/O continue against those local
  descriptors. Write reservations and synchronization notifications continue
  to the Local Broker.
- The Broker continues coalescing completed ranges for at most ten milliseconds
  before encrypted block writeback. `fsync`, full synchronization, mapped-memory
  synchronization, close, exec, and shutdown retain their current durability
  behavior.
- NFS operations continue through the shared remote Broker, with ordinary data
  I/O against anonymous local snapshot descriptors.

Consequently, joining a session adds no per-read or per-write IPC and does not
change encrypted storage formats.

## Lifetime And Shutdown

An accepted launch owns a session lease. Its control connection stays open
while the command runs. `Finished`, cancellation after a local spawn failure,
or connection loss releases that launch's lease. Normal client shutdown first
terminates the launch process group as the current runner does, then releases
the lease.

Releasing a non-final lease does not affect other commands. Releasing the final
lease transitions the daemon to draining:

1. Stop accepting new joins and remove the socket; racing clients reconnect and
   repeat normal startup election.
2. Stop accepting new controller work.
3. Drain accepted work, close inherited persistent controller streams that are
   idle between requests, and perform one final encrypted flush and durable
   sync. An orphan descendant can therefore finish a request already being
   serviced but cannot keep the daemon alive solely by retaining a Local
   Broker control descriptor; a `Ping` accepted during draining is answered
   once and is not promoted back into an idle persistent wait.
4. Shut down NFS, network, execution, and audit controllers. NFS shutdown first
   closes every accepted UDS endpoint so a persistent receive running on the
   blocking pool cannot outlive its cancelled connection task.
5. Remove the session socket and release `.fs.lock`.

A client whose connection races final shutdown retries the ordinary startup
election. The inherited startup lock prevents a replacement daemon from
starting until the previous runtime has released `.fs.lock`. The design does
not keep an idle daemon and does not add an explicit stop command.

Key migration continues to acquire `.fs.lock` exclusively and therefore fails
while any shared session is active.

## Module Boundaries

The intended layout is:

```text
runner/
|-- mod.rs          one-command facade and command launch behavior
`-- runtime.rs      shared workspace and controller ownership

session/
|-- mod.rs
|-- protocol.rs     bounded validated wire types
|-- startup.rs      discovery, startup lock, daemon readiness
|-- client.rs       join, prepare, local launch lease
`-- server.rs       daemon, runtime health, lease lifecycle
```

The existing filesystem, NFS, network, execution, audit, and platform Hook
modules retain their current responsibilities. No new dependency, public
configuration key, encrypted format, metadata version, or user-visible CLI
subcommand is introduced.

## Verification

Focused and integration coverage must demonstrate:

- two shells sharing encrypted content, file locks, and writable mappings;
- SQLite WAL transactions and lock exclusion across separate run clients;
- different commands such as Bash, `ls`, and a CLI joining one workspace;
- one command exiting without affecting another;
- final encrypted writeback, controller shutdown, socket cleanup, and immediate
  `.fs.lock` reuse after the last command;
- concurrent first entry electing exactly one daemon;
- join rejection for UID, protocol, build, and semantic-config mismatch;
- startup recovery from a stale socket without bypassing a live `.fs.lock`;
- runtime failure notification and per-client process-group termination;
- equivalent behavior in plain, encrypted, and configured NFS modes;
- unchanged one-command SDK behavior.

Workspace formatting, Clippy, tests, coverage at the repository threshold, and
the specification check remain required by the repository workflow.
