# Native Filesystem Passthrough Allowlist Design

## Goal

Provide one centrally maintained, compile-time filesystem passthrough allowlist. The initial root is
the macOS device filesystem at `/dev`. Any operation whose resolved logical path is inside an
allowlisted root bypasses Agora filesystem virtualization and filesystem audit entirely.

This removes device and terminal traffic from the encrypted overlay path, preserves native device
semantics, and eliminates high-volume synchronous `/dev/tty` audit traffic during Codex startup.

## Scope

- Define the allowlisted roots once as a static code constant. Adding or removing a root requires a
  code change and rebuild; there is no CLI, environment, or user-configurable bypass.
- Initially allowlist exactly `/dev` and its descendants.
- Apply passthrough to path-based filesystem operations covered by the hook, including `*at`
  operations after resolving their directory descriptor to a logical absolute path.
- Do not change network or process auditing.
- Do not add application-specific exceptions for Codex, `node_repl`, or Lark.

## Path Matching

The hook resolves a request to a normalized logical absolute path before checking the allowlist.
Matching is by path component, not string prefix: `/dev`, `/dev/null`, and `/dev/fd/1` match, while
`/developer` does not. Parent components must be normalized before matching so a path such as
`/dev/../Users/name/file` cannot acquire passthrough privileges.

Relative paths and `*at` paths match only when their resolved logical absolute path is under an
allowlisted root. A descriptor opened through passthrough remains native and is not registered as
an overlay-backed file descriptor.

For an operation with multiple filesystem operands, native passthrough applies only when every
operand that the operation can mutate is allowlisted. This prevents an allowlisted source or
destination from turning a cross-boundary rename, link, clone, or copy into a host-filesystem
bypass.

## Hook Behavior

The allowlist decision is owned by the filesystem hook because it controls libc interception,
descriptor registration, and audit publication. The VFS remains responsible only for paths that
are not allowlisted.

For an allowlisted path, the interposer calls the original libc function with the normalized native
path and skips all of the following:

- overlay lookup, copy-up, whiteouts, encryption, and metadata publication;
- logical permission and attribute virtualization;
- rewritten backing paths and anonymous encrypted-file descriptors;
- open-file and directory-view tracking;
- `filesystem.open` and `filesystem.close` audit publication.

Because passthrough descriptors are not registered, descriptor-only calls such as `close` continue
through the native libc path without producing an audit record or attempting writeback. Native
kernel permissions and errors remain authoritative for operations under `/dev`.

## Security Boundary

The allowlist is deliberately narrow and compile-time-only. Adding a writable host directory would
allow sandboxed processes to mutate that host directory directly, so every future root requires an
explicit code review and specification update. Component-safe normalized matching prevents prefix
and parent-directory traversal bypasses.

## Codex Startup Relationship

In the observed Codex startup, the main process produced 2,981 filesystem audit events before the
first turn; 618 targeted `/dev`, including 598 for `/dev/tty`. Each event currently waits for the
audit controller and audit-file flush. Codex uses a bounded 128-item app-server event queue and
renders pending MCP servers as interrupted after event-stream lag. Removing `/dev` traffic addresses
a confirmed source of startup backpressure, but acceptance tests must determine whether remaining
filesystem or TLS-proxy work also needs optimization.

## Verification

Automated tests must verify:

- `/dev/null` read/write opens use the literal native path and create no overlay state;
- allowlisted `open`, `openat`, `fopen`, metadata, and directory operations publish no filesystem
  audit events;
- closing or duplicating an allowlisted descriptor produces no audit or writeback;
- path, descriptor, and multi-path mutations beneath `/dev` preserve native libc results and errno,
  while mixed-boundary operations never enter the overlay;
- `/developer` and normalized traversal paths do not match the allowlist;
- non-allowlisted paths retain existing virtualization, auditing, and fail-closed behavior;
- an end-to-end sandbox command can repeatedly use `/dev/null` without descriptor errors and leaves
  no `/dev` records in the audit stream.

The Codex acceptance run must then confirm that `node_repl` and `codex_apps` reach ready state without
the `MCP startup interrupted` warning. If they do not, startup timing and logs will separate remaining
filesystem audit latency from TLS proxy or remote MCP latency.
