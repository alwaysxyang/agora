# Interactive Trace Viewer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an `agora-tools trace-viewer` command that opens a secured loopback browser UI with a real PTY-backed Bash running through Agora Sandbox and a live unified audit timeline.

**Architecture:** A new `crates/agora-tools` binary crate owns the Trace Viewer without changing `agora-sandbox`. The Rust backend spawns `agora-sandbox run -c <config> -e /bin/bash` on a PTY, tails the configured JSON Lines log, and sends terminal bytes plus normalized trace events over one authenticated WebSocket; embedded HTML/CSS/JavaScript uses a vendored xterm.js terminal and renders the event timeline.

**Tech Stack:** Rust 2024, Tokio 1.53, Axum 0.8.9, portable-pty 0.9.0, Serde, Clap, xterm.js 6.0.0, xterm addon-fit 0.11.0, plain HTML/CSS/JavaScript.

## Global Constraints

- Put all viewer implementation in `crates/agora-tools`; do not change `agora-sandbox` runtime behavior.
- Add `agora-tools` as a root workspace member and update `spec/architecture/modules.md` in the same change.
- Keep the root shell fixed to `/bin/bash`; browser messages must never select a host executable, config, log, or shell path.
- Bind only an operating-system-selected `127.0.0.1` port and require exact Host, same-origin Origin, and a high-entropy per-process token before PTY creation.
- Keep xterm.js assets and MIT licenses in the repository; make no CDN or Node.js runtime request.
- Preserve existing user modifications and leave all work uncommitted.
- Use test-first red/green cycles for every Rust behavior.
- Run Cargo commands with 16 jobs or test threads and write every `.profraw` under the root `target/` directory.
- Before completion run formatting, focused checks, full workspace tests, Clippy, coverage at 80%, `just spec-check` when available, and the target-external `.profraw` scan.

---

## File Structure

**Create:**

- `crates/agora-tools/Cargo.toml` — binary crate dependencies and metadata.
- `crates/agora-tools/src/main.rs` — top-level CLI and shutdown error reporting.
- `crates/agora-tools/src/trace_viewer/mod.rs` — viewer options and orchestration.
- `crates/agora-tools/src/trace_viewer/config.rs` — sandbox config/log/binary resolution.
- `crates/agora-tools/src/trace_viewer/audit.rs` — JSONL normalization, trace grouping, and file cursor.
- `crates/agora-tools/src/trace_viewer/protocol.rs` — bounded browser/server message schema.
- `crates/agora-tools/src/trace_viewer/terminal.rs` — PTY lifecycle, replay, input, resize, stop.
- `crates/agora-tools/src/trace_viewer/server.rs` — loopback HTTP/WebSocket server and access checks.
- `crates/agora-tools/src/trace_viewer/assets.rs` — embedded asset responses and security headers.
- `crates/agora-tools/src/trace_viewer/tests.rs` — orchestration and browser-open unit tests.
- `crates/agora-tools/tests/cli.rs` — black-box CLI validation.
- `crates/agora-tools/web/index.html` — two-pane application shell.
- `crates/agora-tools/web/app.css` — Runtime Trace visual system and responsive layout.
- `crates/agora-tools/web/app.js` — xterm/WebSocket/timeline interaction.
- `crates/agora-tools/third-party/xterm/xterm.js`, `xterm.css`, `LICENSE` — pinned xterm.js 6.0.0 distribution.
- `crates/agora-tools/third-party/xterm-addon-fit/addon-fit.js`, `LICENSE` — pinned addon-fit 0.11.0 distribution.

**Modify:**

- `Cargo.toml` — add `crates/agora-tools` and the three new Rust dependency versions.
- `spec/README.md` — link the updated module inventory if its wording/count requires it.
- `spec/architecture/modules.md` — change the crate count and document `agora-tools` ownership and dependency direction.
- `docs/superpowers/specs/2026-08-13-trace-viewer-design.md` — mark written design reviewed after behavior is implemented.

---

### Task 1: Workspace crate and CLI contract

**Files:**

- Create: `crates/agora-tools/Cargo.toml`
- Create: `crates/agora-tools/src/main.rs`
- Create: `crates/agora-tools/src/trace_viewer/mod.rs`
- Create: `crates/agora-tools/tests/cli.rs`
- Modify: `Cargo.toml`

**Interfaces:**

- Produces: `Cli`, `Command::TraceViewer(TraceViewerArgs)`, and `trace_viewer::run(TraceViewerOptions) -> anyhow::Result<()>`.
- `TraceViewerArgs` accepts `--config <PATH>`, optional `--sandbox-bin <PATH>`, and `--no-open`.

- [ ] **Step 1: Write the failing black-box CLI tests**

Create tests that invoke `CARGO_BIN_EXE_agora-tools` and assert that `--help` lists `trace-viewer`, that the subcommand requires `--config`, and that removed/unknown flags are rejected:

```rust
#[test]
fn help_exposes_trace_viewer() {
    let output = Command::new(env!("CARGO_BIN_EXE_agora-tools"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("trace-viewer"));
}
```

- [ ] **Step 2: Run the test and verify RED**

Run: `cargo test -p agora-tools --test cli --jobs 16 -- --test-threads=16`

Expected: Cargo reports that workspace package `agora-tools` does not exist.

- [ ] **Step 3: Add the minimal workspace member and CLI**

Add `crates/agora-tools` to `workspace.members`, declare Axum, futures-util, and portable-pty versions in workspace dependencies, and create a Clap binary that converts arguments into:

```rust
pub(crate) struct TraceViewerOptions {
    pub(crate) config: PathBuf,
    pub(crate) sandbox_bin: Option<PathBuf>,
    pub(crate) open_browser: bool,
}

pub(crate) async fn run(options: TraceViewerOptions) -> anyhow::Result<()>;
```

Return a temporary explicit “not implemented” error from `run`; CLI shape tests must not start it.

- [ ] **Step 4: Run the CLI tests and verify GREEN**

Run: `cargo test -p agora-tools --test cli --jobs 16 -- --test-threads=16`

Expected: all CLI parsing tests pass with zero warnings.

- [ ] **Step 5: Review checkpoint**

Run `git diff --check` and confirm only the root manifest plus new `agora-tools` files changed in this task. Do not commit.

### Task 2: Config, log, and sandbox binary resolution

**Files:**

- Create: `crates/agora-tools/src/trace_viewer/config.rs`
- Modify: `crates/agora-tools/src/trace_viewer/mod.rs`

**Interfaces:**

- Produces:

```rust
pub(super) struct ResolvedViewerConfig {
    pub(super) config_path: PathBuf,
    pub(super) log_path: PathBuf,
    pub(super) sandbox_binary: PathBuf,
}

pub(super) fn resolve(options: &TraceViewerOptions) -> anyhow::Result<ResolvedViewerConfig>;
```

- Path rules match `agora-sandbox`: relative workdir from config directory, relative log from workdir, `~` from the current user home, defaults `~/.agora-sandbox` and `runtime/logs/sandbox.log`.

- [ ] **Step 1: Write failing resolver tests**

Cover relative paths, defaults with an injected test home, explicit binary, sibling `target/debug/agora-sandbox`, PATH fallback, missing/non-regular/symlink config, missing binary, and rejection of a log parent that is an existing non-directory. Tests must assert that config secrets are absent from errors.

- [ ] **Step 2: Run resolver tests and verify RED**

Run: `cargo test -p agora-tools trace_viewer::config::tests --jobs 16 -- --test-threads=16`

Expected: unresolved module/function failures.

- [ ] **Step 3: Implement minimal resolution**

Deserialize only the required projection while allowing unrelated sandbox fields:

```rust
#[derive(Deserialize)]
struct SandboxProjection {
    workdir: Option<PathBuf>,
    #[serde(default)]
    log: LogProjection,
}
```

Use lexical absolute normalization, validate the config with `symlink_metadata`, locate the binary without invoking a shell, and never serialize the loaded config back to the UI.

- [ ] **Step 4: Run resolver tests and verify GREEN**

Run the focused test command from Step 2 and confirm zero warnings.

- [ ] **Step 5: Review checkpoint**

Run `cargo fmt --all -- --check` and `git diff --check`. Do not commit.

### Task 3: Compact audit normalization and resilient JSONL cursor

**Files:**

- Create: `crates/agora-tools/src/trace_viewer/audit.rs`

**Interfaces:**

- Produces:

```rust
#[derive(Clone, Debug, Serialize)]
pub(super) struct TraceEvent {
    pub(super) id: u64,
    pub(super) root_trace_id: String,
    pub(super) kind: TraceKind,
    pub(super) occurred_at: String,
    pub(super) title: String,
    pub(super) detail: serde_json::Value,
}

pub(super) fn normalize_line(id: u64, line: &[u8]) -> Result<Option<TraceEvent>, AuditLineError>;
pub(super) struct LogCursor { /* path identity, offset, partial bytes */ }
pub(super) fn poll_cursor(cursor: &mut LogCursor) -> io::Result<Vec<CursorItem>>;
```

- [ ] **Step 1: Write failing audit tests**

Use representative real compact records for `process`, filesystem open/close, and network. Assert label/title/detail fields, first trace-chain component grouping, domain fallback to IP, ignoring non-audit records, malformed diagnostics, partial-line buffering, maximum line rejection, append order, truncation, and inode replacement.

- [ ] **Step 2: Run audit tests and verify RED**

Run: `cargo test -p agora-tools trace_viewer::audit::tests --jobs 16 -- --test-threads=16`

Expected: unresolved audit types/functions.

- [ ] **Step 3: Implement minimal parser and cursor**

Parse the logger envelope first, then a tagged compact audit enum. Preserve original audit JSON in `detail`; never infer URL paths, request bodies, execution results, or file contents. Cap a single JSONL record at 256 KiB and emit a diagnostic item instead of terminating the cursor.

- [ ] **Step 4: Run audit tests and verify GREEN**

Run the focused command from Step 2 and confirm all edge cases pass.

- [ ] **Step 5: Review checkpoint**

Run `cargo clippy -p agora-tools --all-targets --jobs 16 -- -D warnings`. Do not commit.

### Task 4: Bounded browser protocol and access guard

**Files:**

- Create: `crates/agora-tools/src/trace_viewer/protocol.rs`
- Begin: `crates/agora-tools/src/trace_viewer/server.rs`

**Interfaces:**

- Produces `ClientControl::{Auth, Resize, Stop, Start, ClearTrace}`; PTY input remains WebSocket binary data.
- Produces `ServerControl::{Status, Trace, TraceSnapshot, Diagnostic, ReplayStart, ReplayEnd}`; PTY output remains WebSocket binary data.
- Produces:

```rust
pub(super) struct AccessGuard {
    pub(super) token: String,
    pub(super) expected_host: String,
    pub(super) expected_origin: String,
}

pub(super) fn validate_upgrade(headers: &HeaderMap, guard: &AccessGuard) -> Result<(), StatusCode>;
pub(super) fn validate_auth(message: &Message, token: &str) -> Result<(), AuthError>;
```

- [ ] **Step 1: Write failing protocol/security tests**

Assert exact Host and Origin acceptance, missing/mismatched rejection, null/cross-origin rejection, a text Auth first message, invalid token rejection, binary-before-auth rejection, rows/columns bounds, oversize message rejection, and redacted Debug output for the token.

- [ ] **Step 2: Run tests and verify RED**

Run: `cargo test -p agora-tools trace_viewer::protocol::tests trace_viewer::server::access_tests --jobs 16 -- --test-threads=16`

Expected: missing protocol/access guard implementation.

- [ ] **Step 3: Implement minimal schemas and guards**

Use 24 random UUID v4 bytes encoded without exposing them through Debug; accept terminal sizes only in `2..=500` rows and columns. Configure Axum WebSocket maximum message/frame size to 64 KiB and require auth within three seconds.

- [ ] **Step 4: Run tests and verify GREEN**

Run the focused tests and Clippy for `agora-tools`.

- [ ] **Step 5: Review checkpoint**

Inspect responses to ensure there is no `Access-Control-Allow-Origin`, cookie, config payload, or token log. Do not commit.

### Task 5: PTY terminal lifecycle and bounded replay

**Files:**

- Create: `crates/agora-tools/src/trace_viewer/terminal.rs`

**Interfaces:**

- Produces:

```rust
pub(super) struct TerminalSpec {
    pub(super) sandbox_binary: PathBuf,
    pub(super) config_path: PathBuf,
    pub(super) shell: PathBuf,
}

pub(super) struct TerminalSession;
impl TerminalSession {
    pub(super) fn spawn(spec: TerminalSpec, size: TerminalSize, hub: Arc<EventHub>) -> anyhow::Result<Self>;
    pub(super) fn input(&self, bytes: &[u8]) -> io::Result<()>;
    pub(super) fn resize(&self, size: TerminalSize) -> io::Result<()>;
    pub(super) fn request_stop(&self) -> io::Result<()>;
    pub(super) fn is_exited(&self) -> bool;
}
```

- [ ] **Step 1: Write failing PTY tests**

Use an executable fake sandbox wrapper in a temporary directory. Verify the exact argv is `run -c <config> -e /bin/bash`, `TERM=xterm-256color`, input/output round-trip, `stty size` after resize, Ctrl-C delivery, replay capped at 1 MiB, graceful SIGTERM followed by bounded SIGKILL escalation, and exit status publication.

- [ ] **Step 2: Run tests and verify RED**

Run: `cargo test -p agora-tools trace_viewer::terminal::tests --jobs 16 -- --test-threads=16`

Expected: missing terminal implementation.

- [ ] **Step 3: Implement the minimal PTY session**

Use `portable_pty::native_pty_system`, attach the fixed command directly without a host shell, keep the reader/writer/master/child owners explicit, and use short polling rather than holding the child mutex across `wait`. Forward Stop as SIGTERM to the viewer-owned sandbox process, then SIGKILL only after the documented grace period if it remains alive.

- [ ] **Step 4: Run PTY tests and verify GREEN**

Run the focused test command and confirm no child process remains after the test.

- [ ] **Step 5: Review checkpoint**

Run Clippy and inspect production code for any command path or argument sourced from browser messages. Do not commit.

### Task 6: Session hub, log tail task, and authenticated WebSocket

**Files:**

- Complete: `crates/agora-tools/src/trace_viewer/server.rs`
- Modify: `crates/agora-tools/src/trace_viewer/audit.rs`
- Modify: `crates/agora-tools/src/trace_viewer/terminal.rs`
- Modify: `crates/agora-tools/src/trace_viewer/mod.rs`

**Interfaces:**

- Produces `EventHub` with a 1 MiB terminal ring, 5,000 normalized events, 100 diagnostics, broadcast subscription, and truncation flags.
- Produces `SessionManager::{start, stop, input, resize, snapshot, shutdown}`.
- Produces `serve(listener, state, shutdown) -> anyhow::Result<()>` and one-controller ownership.

- [ ] **Step 1: Write failing hub and WebSocket tests**

Assert event/replay bounds, ordered snapshots, clear-trace behavior, first root-trace highlighting, unrelated root-trace separation, PTY startup only after valid auth, invalid auth creates no child, second controller receives conflict, reconnect gets replay/snapshot, binary input reaches PTY, resize/control messages route correctly, and disconnect keeps the terminal alive.

- [ ] **Step 2: Run tests and verify RED**

Run: `cargo test -p agora-tools trace_viewer::server::tests --jobs 16 -- --test-threads=16`

Expected: missing hub/session/server behavior.

- [ ] **Step 3: Implement minimal session/server orchestration**

Capture the log cursor baseline immediately before PTY spawn, poll at 100 ms, publish only appended complete records, keep malformed records as bounded diagnostics, and keep the tail task until restart/shutdown. Use an atomic controller lease released on WebSocket drop. Send snapshot/replay before live subscription and tolerate broadcast lag by issuing a fresh snapshot.

- [ ] **Step 4: Run WebSocket tests and verify GREEN**

Run the focused tests and `cargo clippy -p agora-tools --all-targets --jobs 16 -- -D warnings`.

- [ ] **Step 5: Review checkpoint**

Confirm the server binds only a caller-provided loopback listener and that test connections with invalid Origin/Host/token never spawn a fake sandbox. Do not commit.

### Task 7: Embedded Runtime Trace browser UI

**Files:**

- Create: `crates/agora-tools/src/trace_viewer/assets.rs`
- Create: `crates/agora-tools/web/index.html`
- Create: `crates/agora-tools/web/app.css`
- Create: `crates/agora-tools/web/app.js`
- Create: vendored xterm.js/addon-fit files and licenses under `crates/agora-tools/third-party/`
- Modify: `crates/agora-tools/src/trace_viewer/server.rs`

**Interfaces:**

- HTTP paths: `/`, `/app.css`, `/app.js`, `/vendor/xterm.js`, `/vendor/xterm.css`, `/vendor/addon-fit.js`.
- `app.js` reads `#token=...`, clears the visible fragment after loading, authenticates the WebSocket, writes binary PTY data to xterm, sends binary keyboard data, sends bounded resize/control JSON, and renders/searches/filters timeline events.

- [ ] **Step 1: Write failing embedded-asset tests**

Assert every asset route has the expected MIME type, CSP includes only self/local WebSocket sources, cache policy is no-store for HTML/JS, no CORS header is present, all asset bodies are non-empty, licenses are present, and HTML/JS contains no `http://`, `https://`, CDN, React, Vue, or Node runtime reference.

- [ ] **Step 2: Run asset tests and verify RED**

Run: `cargo test -p agora-tools trace_viewer::assets::tests --jobs 16 -- --test-threads=16`

Expected: missing assets/routes.

- [ ] **Step 3: Vendor pinned assets and implement the UI**

Extract only the browser distribution and MIT license from `@xterm/xterm@6.0.0` and `@xterm/addon-fit@0.11.0`. Implement the approved two-pane design with accessible labels, status badges, filters (`EXEC`, `FILE`, `NETWORK`), text search, close-event toggle, event detail/raw JSON, Stop/Start controls, reconnect banner, trace truncation notice, and responsive stacking below 900 px.

- [ ] **Step 4: Run asset and Rust tests and verify GREEN**

Run the focused asset tests followed by all `agora-tools` tests.

- [ ] **Step 5: Visually verify the real page**

Start with `--no-open`, open the loopback URL in the in-app browser, verify xterm rendering and layout, type commands, resize the browser, use filters/detail, refresh and reconnect, stop/restart, and capture a screenshot for inspection. Fix visual or interaction defects only through new failing tests where the behavior is testable.

- [ ] **Step 6: Review checkpoint**

Search `crates/agora-tools` for remote URL and dynamic script references and verify only third-party license/provenance documentation contains registry URLs. Do not commit.

### Task 8: CLI orchestration, browser launch, and real sandbox smoke path

**Files:**

- Complete: `crates/agora-tools/src/trace_viewer/mod.rs`
- Create: `crates/agora-tools/src/trace_viewer/tests.rs`
- Modify: `crates/agora-tools/src/main.rs`
- Modify: `crates/agora-tools/tests/cli.rs`

**Interfaces:**

- `run` resolves paths, binds `127.0.0.1:0`, builds token/guard/state, prints the local URL without secrets in ordinary logs, opens the URL with the platform browser when requested, and gracefully shuts down terminal plus server on Ctrl-C.

- [ ] **Step 1: Write failing orchestration tests**

Inject a browser opener and listener factory in unit tests. Assert random loopback bind, URL fragment token placement, `--no-open`, browser-open failure as a visible warning without PTY startup, normal shutdown cleanup, and absence of token/config contents in Debug/errors.

- [ ] **Step 2: Run tests and verify RED**

Run: `cargo test -p agora-tools trace_viewer::tests --jobs 16 -- --test-threads=16`

Expected: orchestration still returns the temporary not-implemented error.

- [ ] **Step 3: Implement minimal orchestration**

Open browsers with `open` on macOS and platform-specific equivalents behind `cfg` without invoking a shell. Keep `--no-open` deterministic for tests and print an explicit copyable URL only to the controlling terminal.

- [ ] **Step 4: Run all crate tests and verify GREEN**

Run: `cargo test -p agora-tools --all-targets --jobs 16 -- --test-threads=16`

Expected: all tests pass with zero warnings.

- [ ] **Step 5: Run the real sandbox smoke scenario**

Use a temporary config/log and the real `target/debug/agora-sandbox`; start the viewer, authenticate in a browser, run a descendant `/bin/cat` against a fixture and a local HTTP request, then verify live `EXEC`, `FILE OPEN`, and `NETWORK` rows. Do not depend on external network availability.

- [ ] **Step 6: Review checkpoint**

Confirm the real shell process is under `agora-sandbox`, viewer shutdown leaves no process behind, and the temporary config/log contain no committed secrets. Do not commit.

### Task 9: Durable project documentation

**Files:**

- Modify: `spec/architecture/modules.md`
- Modify: `spec/README.md` only if its inventory text/link requires a change
- Modify: `docs/superpowers/specs/2026-08-13-trace-viewer-design.md`

**Interfaces:**

- Documents `agora-tools` as a binary workspace crate, `trace-viewer` ownership, CLI-only relationship to `agora-sandbox`, local security boundary, and compact-log presentation limits.

- [ ] **Step 1: Write the specification changes**

Change “four top-level crates” to five and add an `agora-tools` section that records: local developer tooling only; fixed `agora-sandbox` child launch; PTY/WebSocket/browser asset ownership; no dependency from production crates; loopback/token/Origin boundary; audit log is the durable source; and domain/IP/port are not full URL/body audit.

- [ ] **Step 2: Self-check code/spec consistency**

Compare implemented CLI flags, defaults, bounds, lifecycle, fields, and dependency direction line by line against the design and module spec. Remove any claim not implemented and document every externally visible implemented behavior.

- [ ] **Step 3: Run documentation checks**

Run: `git diff --check`

If `just --list` contains `spec-check`, run: `just spec-check`.

- [ ] **Step 4: Review checkpoint**

Confirm only expected design/plan/spec files changed and the design status says implemented only after verification succeeds. Do not commit.

### Task 10: Full verification and delivery

**Files:** all files changed by Tasks 1–9.

- [ ] **Step 1: Format**

Run: `cargo fmt --all -- --check`

Expected: exit 0, no diff.

- [ ] **Step 2: Run new crate tests**

Run: `cargo test -p agora-tools --all-targets --jobs 16 -- --test-threads=16`

Expected: exit 0, zero failures/warnings.

- [ ] **Step 3: Run full workspace tests**

Run: `cargo test --workspace --all-targets --jobs 16 -- --test-threads=16`

Expected: exit 0, zero failures/warnings.

- [ ] **Step 4: Run full workspace Clippy**

Run: `cargo clippy --workspace --all-targets --jobs 16 -- -D warnings`

Expected: exit 0, zero warnings/errors.

- [ ] **Step 5: Run workspace coverage**

Run:

```bash
LLVM_PROFILE_FILE="$PWD/target/agora-%p-%12m.profraw" \
  cargo llvm-cov --no-clean --workspace --all-targets --jobs 16 --fail-under-lines 80
```

Expected: exit 0 and workspace line coverage at least 80%.

- [ ] **Step 6: Verify coverage artifacts**

Run: `rg --files -uu -g '*.profraw' -g '!target/**'`

Expected: no output.

- [ ] **Step 7: Run spec and visual checks**

Run `just spec-check` when available, repeat the real browser smoke test, and verify the page at desktop and narrow widths.

- [ ] **Step 8: Inspect final diff and working tree**

Run `git diff --check`, `git diff --stat`, `git status --short`, and review every changed file. Distinguish pre-existing user changes from Trace Viewer changes and confirm no generated build output, config, logs, tokens, credentials, or profraw files are untracked outside `target/`.

- [ ] **Step 9: Final delivery**

Report what changed, why it was necessary, how the security boundary works, why a smaller static viewer was insufficient for interactive `codex`, all verification commands/results, and spec consistency. Leave changes uncommitted.
