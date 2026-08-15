# Interactive Trace Viewer Design

Status: implemented and verified

Date: 2026-08-13

## Context

Agora already writes compact JSON Lines audit records for intercepted descendant process execution,
file open and close activity, and network connection attempts. Those records are useful for machines,
but a user currently has to inspect the log manually and correlate events by `trace_id`. The existing
Runtime Trace animation demonstrates a clearer experience, but it is a generated document asset and
not an operational product surface.

The Trace Viewer turns that presentation into a real local tool. It combines an interactive terminal
running inside Agora Sandbox with a live, human-readable timeline of the resulting command, file, and
network events.

## Goals

- Provide a real browser terminal capable of running interactive programs such as `codex`.
- Launch the terminal only through the existing `agora-sandbox run` command boundary.
- Show new `EXEC`, `FILE OPEN`, and `NETWORK` audit records while the terminal is active.
- Preserve the visual language of the Runtime Trace demonstration: terminal on the left and one
  chronological trace on the right.
- Remain rootless, local-only, and usable without installing a system service or browser extension.
- Keep the viewer in a dedicated `agora-tools` crate and avoid changes to the sandbox runtime.
- Require no Node.js or external CDN at runtime.

## Non-goals

- Replacing the JSON Lines log as the durable audit source.
- Adding audit events, fields, policy decisions, or interception coverage to `agora-sandbox`.
- Recording complete URLs, HTTP bodies, terminal keystrokes, or terminal output as new audit data.
- Providing a remote terminal, multi-user service, desktop application, or system-wide dashboard.
- Supporting multiple simultaneous terminal tabs in the first version.
- Providing cryptographic proof that child-supplied trace identity is trustworthy.
- Hiding all operating-system file activity automatically. The viewer supplies filters without
  pretending that a heuristic can always distinguish relevant and irrelevant files.

## Repository Placement

All implementation files live below a new workspace member:

```text
crates/agora-tools/
├── Cargo.toml
├── src/
│   ├── main.rs
│   └── trace_viewer/
│       ├── mod.rs
│       ├── audit.rs
│       ├── protocol.rs
│       ├── server.rs
│       └── terminal.rs
├── web/
├── tests/
└── third-party/
```

`agora-tools` is a binary crate and a member of the root Cargo workspace. Its CLI is organized by
subcommand; `trace-viewer` owns the browser terminal and audit presentation described here. This
keeps developer tooling out of `agora-sandbox` while leaving a clear home for future local diagnostic
tools. The root workspace manifest adds only the new member, and no existing crate needs to depend on
`agora-tools`.

The browser assets are built into the viewer binary. A pinned xterm.js distribution and its license
are stored locally below `third-party/`; the running viewer never downloads scripts, fonts, or styles
from a CDN. A packaged release may ship the compiled viewer binary, but running from a source checkout
may build it through the repository's Rust toolchain on first use.

## User Entry Point

The normal source-checkout entry point is:

```bash
cargo run -p agora-tools -- trace-viewer --config ./sandbox.json
```

Optional startup-only flags may select an explicit `agora-sandbox` binary or disable automatic
browser opening. The command resolves and validates the config and binary paths before starting the
HTTP listener. The browser cannot change either path.

The viewer derives the configured log location from `workdir` and `log.file` using the documented
CLI path rules. It does not return the config contents to the browser. Unsupported or ambiguous
config shapes stop startup with an actionable error instead of silently watching a different file.

## Architecture

### `agora-tools::trace_viewer`

The Trace Viewer module owns four responsibilities:

1. Serve embedded HTML, CSS, xterm.js, and application JavaScript.
2. Own one pseudoterminal and the `agora-sandbox` child process attached to it.
3. Tail complete JSON Lines appended to the configured sandbox log after the terminal session starts.
4. Multiplex terminal bytes, resize messages, lifecycle state, and normalized trace events over an
   authenticated WebSocket connection.

The backend binds an operating-system-selected port on `127.0.0.1`. It does not bind wildcard,
LAN, IPv6, or Unix-domain endpoints in the first version.

### Terminal process chain

The backend does not expose an HTTP method that accepts a command to execute. After an authenticated
viewer connects, it opens a PTY and directly spawns an argument vector equivalent to:

```text
agora-sandbox run -c <validated-config> -e /bin/bash
```

No host shell interprets this launch vector. The config path, sandbox binary, and root shell are fixed
at viewer startup. Browser input becomes raw PTY input only after the sandboxed Bash session exists.
Commands typed later, including `codex`, therefore execute as descendants of the sandboxed shell.

The PTY supplies `TERM=xterm-256color` and terminal dimensions, forwards resize changes, and preserves
control characters such as Ctrl-C. Agora's existing foreground terminal and process-group behavior
remains the authority for child job control and descendant cleanup.

### Audit stream

The viewer records the current log offset immediately before launching the PTY child, then consumes
only complete lines appended after that point. It ignores non-audit lifecycle and NFS status records.
The existing compact audit shapes are normalized as follows:

| Audit record | Viewer label | Primary presentation |
| --- | --- | --- |
| `process` | `EXEC` | executable plus arguments |
| `filesystem` with `operation=open` | `FILE OPEN` | logical path plus access mode |
| `filesystem` with `operation=close` | `FILE CLOSE` | logical path plus access mode |
| `network` | `NETWORK` | domain when available, destination IP, and port |

The detail panel retains the fields actually present in the log, including time, trace chain, PID,
PPID, current directory, process operation, structured file flags, destination IP, and destination
port. It does not infer a complete URL, HTTP payload, process result, or file content when the compact
record does not contain that information.

Events are grouped by the first component of the comma-separated trace chain. The first trace observed
after the terminal starts is highlighted as the active session. If another process appends records to
the same configured log concurrently, its different root trace remains visible as a separate group
rather than being attributed to the active terminal. The first version documents that exclusive use
of a log file gives the clearest view; it does not block other Agora clients.

Partial lines remain buffered until their terminating newline arrives. A malformed record increments
a visible diagnostic count and is skipped without terminating the terminal. Log truncation or file
replacement causes the tailer to reopen the configured path and continue from the new file without
replaying the previous file.

## Browser Experience

The page keeps the demonstrated two-column layout:

- The left pane is a real xterm.js terminal with scrollback, copy, paste, keyboard input, ANSI colors,
  alternate-screen support, and automatic resize.
- The right pane is a chronological event timeline using visually distinct `EXEC`, `FILE OPEN`,
  `FILE CLOSE`, and `NETWORK` badges.
- The header shows sandbox status, terminal state, active root trace, and elapsed time.
- Event filters, free-text search, and a “show close events” toggle control noisy traces without
  deleting or rewriting source records.
- The timeline follows the newest visible event while it is already at, or within 24 pixels of, the
  bottom.
  Scrolling upward pauses that follow behavior so incoming records do not interrupt inspection of
  older activity. Returning within the same 24-pixel threshold resumes following automatically.
  Initial snapshots start at the newest visible event, and timeline re-renders preserve the user's
  paused `scrollTop` position.
- Live audit events update bounded browser state immediately, but timeline DOM work is coalesced into
  at most one render per second. Terminal input and output bypass this presentation timer and remain
  immediate.
- Selecting an event opens a structured detail panel. Raw JSON is available as an explicit secondary
  view for technical diagnosis.
- Network rows prefer `domain:port` and fall back to `IP:port`. They never imply that the full URL or
  request body is known.

The first version owns one active shell. Exiting Bash leaves its terminal scrollback and trace visible
and presents a “Start new session” action. Starting again records a new log baseline and clears the
active terminal while allowing the user to keep or clear the previous trace view explicitly.

The browser stores neither the session token nor terminal contents in `localStorage`, IndexedDB, or
cookies. A bounded in-memory terminal replay buffer and bounded normalized-event list allow a page
refresh to reconnect without permitting unbounded memory growth. The durable source remains the
sandbox log.

## Local Security Boundary

The viewer is a same-user local development tool, but its ability to drive a terminal requires more
than relying on loopback alone.

- The listener binds only `127.0.0.1` on a random port.
- Startup generates a high-entropy, single-process session token. The browser receives it in the URL
  fragment so it is not sent in the initial HTTP request; JavaScript presents it during WebSocket
  authentication.
- The server validates the exact `Host` and same-origin `Origin`, exposes no CORS permission, and
  rejects unauthenticated WebSocket input before starting a PTY.
- A restrictive Content Security Policy allows only embedded/local assets and the viewer's own
  WebSocket connection.
- The config path, log path, sandbox binary, and root shell are startup-only values. Browser messages
  can carry PTY bytes, dimensions, trace filters, and lifecycle requests, but never an executable
  path or host command.
- Only one controlling browser connection is accepted. A reconnect with the same token replaces a
  disconnected client; a simultaneous second controller is rejected.
- Terminal output and audit fields may contain sensitive data. Possession of the token grants access
  for that viewer process, and shutting down the backend invalidates it.

This protects against ordinary cross-origin browser requests and accidental LAN exposure. It is not
a privilege boundary against another process already running as the same operating-system user.

## Lifecycle And Failure Handling

- The PTY starts only after an authenticated client is ready, so a failed browser launch does not
  leave an unseen shell running.
- A browser refresh or temporary WebSocket loss does not immediately terminate the shell. The backend
  retains a bounded output buffer for reconnection.
- The Stop action first asks the `agora-sandbox` process to terminate normally so its existing signal
  and process-group cleanup runs. After a bounded grace period, the backend closes the PTY and forces
  the viewer-owned process group to exit.
- Shutting down the viewer performs the same cleanup before closing the HTTP listener.
- Sandbox startup failure, invalid config, missing log access, PTY failure, or unexpected process exit
  is rendered as a terminal lifecycle error with the available exit status. The viewer does not retry
  a failed command automatically.
- A log-tail failure disables the trace pane and surfaces the reason but does not convert the terminal
  into an unsandboxed shell. The process remains under the already-started Agora Sandbox boundary.

## Resource Bounds

The backend uses explicit caps for terminal replay bytes, normalized trace events, maximum JSON line
length, WebSocket message size, and diagnostic history. Both backend and browser presentation state
retain at most the newest 5,000 normalized trace events. Reaching a presentation cap drops only the
oldest in-memory viewer data and shows a truncation indicator; it does not alter the durable log.
Terminal input and resize messages are processed with bounded queues so a stalled browser cannot
create unbounded backend memory use.

## Testing Strategy

The new crate has focused tests and participates in the repository's normal workspace formatting,
Clippy, test, and coverage requirements.

- Parser tests cover all compact audit variants, partial JSON Lines, malformed lines, oversized lines,
  truncation, file replacement, trace grouping, and domain-to-IP fallback.
- HTTP/WebSocket tests cover loopback binding, Host and Origin validation, missing or invalid tokens,
  second-controller rejection, message-size limits, and the absence of CORS permissions.
- PTY integration tests use a fake sandbox executable to verify the exact argument vector, input/output,
  Ctrl-C, resize propagation, exit status, reconnect buffering, and stop escalation without running a
  host command supplied by the browser.
- A sandbox smoke test uses a real `agora-sandbox` binary to start Bash, execute a descendant command,
  open a fixture file, make a local TCP request, and confirm the three corresponding timeline types.
- Browser verification checks xterm rendering, keyboard input, terminal resize, event filtering,
  detail expansion, smart timeline following, paused historical inspection, process exit, and
  reconnect behavior at the supported desktop viewport.
- A focused browser-logic test covers bottom detection and verifies that follow mode selects the
  newest scroll position while paused mode retains the previous position.
- A focused browser-logic test verifies that trace bursts schedule one one-second refresh, duplicate
  events retain their chronological position, immediate user actions cancel redundant refreshes, and
  the browser keeps only the newest 5,000 events.
- Dependency licenses and the absence of runtime CDN references are checked before delivery.

Adding the workspace crate changes the documented project module inventory. The implementation must
update `spec/architecture/modules.md` in the same change to record `agora-tools` ownership and its
one-way use of the public `agora-sandbox` CLI and log contract.

## Acceptance Criteria

The first version is complete when all of the following are true:

1. `cargo run -p agora-tools -- trace-viewer --config <path>` opens a local browser page without root
   privileges.
2. The page provides a functional interactive Bash terminal inside `agora-sandbox` and can run
   terminal-oriented programs such as `codex`.
3. Descendant execution, logical file access, and network destinations appear live in one timeline
   using only fields present in the existing sandbox log. The timeline follows new events until the
   user scrolls upward, preserves that historical reading position while paused, and resumes
   following when the user returns to the bottom.
4. Ctrl-C, terminal resize, shell exit, restart, viewer shutdown, and browser refresh have defined and
   verified behavior.
5. Requests without the startup token or with an invalid Host or Origin cannot read or control the
   terminal.
6. Runtime assets require no CDN or Node.js installation.
7. Viewer implementation is contained by `crates/agora-tools`; existing crates do not acquire a
   dependency on it, and `agora-sandbox` runtime behavior remains unchanged.
8. Existing repository changes remain untouched and all viewer-specific checks pass without warnings.

## Main Trade-offs

Adding `agora-tools` to the workspace expands workspace build and verification cost, but gives Rust
tooling one explicit, reusable ownership boundary and lets it follow the same dependency, lint, and
coverage discipline as the rest of the repository. Reusing the existing CLI and JSON Lines log avoids
sandbox runtime changes, but the viewer receives only compact audit fields and must tolerate unrelated
concurrent trace groups. A single terminal keeps lifecycle and control ownership clear; multi-tab
sessions can be considered later only if real usage demonstrates the need.
