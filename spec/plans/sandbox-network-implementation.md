# Sandbox Network Implementation Plan

> **For agentic workers:** Implement this plan inline with the current agent. Project rules prohibit subagents. Do not create commits unless the user explicitly requests one.

**Status:** Completed. The descriptions and checks below reflect the implemented behavior.

**Goal:** Deliver the first runnable macOS rootless network interception path for `agora-sandbox`, with standardized asynchronous policy callbacks, audit events, and an honest security boundary.

**Architecture:** `agora-sandbox` is a reusable SDK, injectable dylib, and thin CLI in one crate. A private protocol module defines the authenticated HTTP CONNECT preface shared by the host and private macOS hook module. Each sandbox run owns IPv4/IPv6 loopback proxies. The hook redirects covered TCP calls by invoking the original macOS `connectx` with the transparent CONNECT preface as initial data, preserving native nonblocking behavior without waiting for an acknowledgement. Covered interception failures are blocked without direct fallback. The proxy strips the preface, buffers bounded initial data to derive HTTP Host or TLS SNI, and asks one asynchronous callback to allow, deny, or route through an HTTP CONNECT proxy before opening upstream. The same callback receives later audit events.

**Tech Stack:** Rust 2024, Tokio, serde, clap, macOS dyld interposition, loopback TCP proxying.

## Delivery Boundary

This plan implements raw TCP interception and callback policy end to end. It does not claim that dylib interposition alone is a complete security boundary.

- `intercept` mode is available; failures inside covered `connect` and simple `connectx` paths fail closed.
- `strict` mode is rejected until the macOS native sandbox can deny direct external egress while permitting only Agora's proxy listeners.
- TLS `off` and `auto` are available. Auto terminates valid TLS ClientHello traffic and passes HTTP
  and other non-TLS TCP through unchanged. Termination uses an explicit or workdir-local fixed CA
  pair, verified upstream TLS, Public Suffix List-aware wildcard/IP leaf certificates,
  process-local `SecTrust` injection, and a CA-keyed trust bundle without Keychain changes.
- Static binaries, unsupported process-launch paths, and executables that cannot run after copying
  and ad-hoc signing may not be intercepted in intercept mode; these limitations are explicit in
  documentation and cannot always produce events because the hook does not run.

### Task 1: Standard Callback Contract

**Files:**
- Add: `crates/agora-sandbox/src/callback/mod.rs`
- Add: `crates/agora-sandbox/tests/callback.rs`

- [x] Add failing tests for the versioned owned event model, stable JSON field names, no-op callback, and closure callback.
- [x] Define `Callback`, `NoopCallback`, unified `Event`, `NetworkEvent`, `ProcessEvent`, `Decision`,
      subsystem-specific details, result, process identity, network identity, TLS metadata, and metrics.
- [x] Keep delivery asynchronous and storage-free. Do not add queues, files, databases, retry, or serialization policy to the callback runtime.
- [x] Add `Decision::Proxy`, HTTP proxy and Basic Auth types, and explicit `Redact` views that never serialize or debug-print proxy passwords.

### Task 2: Authenticated Proxy Protocol

**Files:**
- Add: `crates/agora-sandbox/src/protocol/mod.rs`
- Add: `crates/agora-sandbox/src/protocol/tests.rs`

- [x] Add failing round-trip, malformed-request, and trailing-payload tests.
- [x] Define a versioned HTTP/1.1 CONNECT preface.
- [x] Carry run token, original destination, process identity, a stable connection id, and the
      XFF-style trace chain. Domain data is derived by the host and is not part of the CONNECT preface.
- [x] Keep the protocol module private to `agora-sandbox`.

### Task 3: TCP Proxy

**Files:**
- Add: `crates/agora-sandbox/src/network/mod.rs`
- Add: `crates/agora-sandbox/src/network/config.rs`
- Add: `crates/agora-sandbox/src/network/proxy.rs`
- Add: `crates/agora-sandbox/src/network/tests/proxy.rs`

- [x] Add tests for authentication rejection, transparent CONNECT behavior, proxy relay, connection limits, listener health, and audit event ordering.
- [x] Start IPv4 and IPv6 loopback TCP listeners per sandbox run.
- [x] Strip the transparent CONNECT preface without sending a response, then inspect bounded initial client bytes before opening upstream.
- [x] Ask the asynchronous callback to allow, deny, or proxy the attempt before upstream, then emit denied, established, failed, and closed events.
- [x] Route `Decision::Proxy` through standard HTTP CONNECT with optional Basic Auth, preserve response bytes after the CONNECT head, and fail closed without direct fallback.
- [x] Inspect at most 64 KiB and 500 ms of initial client bytes for the first HTTP/1 Host or TLS ClientHello SNI, including fragmented ClientHello input.
- [x] Stop both proxy listeners when the run ends.
- [x] Bound active proxy connections per run and terminate the child if a listener exits unexpectedly.

### Task 4: macOS TCP Interposition Library

**Files:**
- Add: `crates/agora-sandbox/src/hook/mod.rs`
- Add: `crates/agora-sandbox/src/hook/tests.rs`

- [x] Add tests for socket-address conversion and configuration validation.
- [x] Interpose TCP `connect` on macOS with a thread-local recursion guard and original pointers from the Mach-O interposition table.
- [x] Ignore non-TCP and non-IP sockets.
- [x] Interpose only `connect` and `connectx`, and route simple calls through the original macOS `connectx` with the transparent CONNECT preface as initial data.
- [x] Preserve the application's descriptor flags, `EINPROGRESS`, and `poll`/`kqueue` behavior; do not wait for a proxy response or interpose readiness and I/O APIs.
- [x] Keep DNS resolution outside the hook; domain observation belongs to the host proxy's HTTP and TLS protocol inspection.
- [x] Keep descriptor inspection and lifecycle APIs unhooked; intercepted sockets expose the loopback proxy through `getpeername`.
- [x] Fail closed without connecting to the original destination when covered interception cannot be established or a `connectx` form is unsupported.
- [x] Refresh PID and PPID for every connection so descendants created by `fork()` without `exec()` have distinct audit identities.

### Task 5: SDK And CLI Lifecycle

**Files:**
- Add: `crates/agora-sandbox/src/lib.rs`
- Add: `crates/agora-sandbox/src/runner/mod.rs`
- Replace: `crates/agora-sandbox/src/main.rs`
- Replace: `crates/agora-sandbox/tests/hello.rs`
- Add: `crates/agora-sandbox/tests/runner.rs`

- [x] Add tests for configuration validation, real environment injection, child exit propagation,
  unsupported strict mode, TLS CA requirements, and cleanup.
- [x] Expose a typed SDK that accepts a command, network policy, hook path, and caller-owned callback.
- [x] Keep the CLI thin and support `agora-sandbox --hook-library <path> -c '<command>'`; expose
  TLS off/auto with an explicit or workdir-local fixed CA pair while keeping unsupported strict
  enforcement out of the CLI.
- [x] Preserve child stdout and stderr. The CLI callback writes compact network-attempt and
  descendant-process-attempt records as JSON Lines to stdout by default, or appends them to
  `--audit-file`.
- [x] Integrate `agora-core` lifecycle handling so signals terminate the child and network services cleanly.

### Task 6: Specifications And Verification

**Files:**
- Modify: `spec/architecture/modules.md`
- Modify: `spec/engineering/conventions.md`
- Add: `spec/architecture/sandbox-network.md`

- [x] Document SDK and CLI ownership, internal crates, protocol flow, callback semantics, rootless compatibility limits, unsupported modes, and the distinction between interception and strict enforcement.
- [x] Run `cargo fmt --all -- --check`.
- [x] Run focused sandbox tests.
- [x] Run `cargo test --workspace --all-targets --all-features -- --test-threads=1`.
- [x] Run `cargo clippy --workspace --all-targets --all-features -- -D warnings`.
- [x] Run `git diff --check`.
- [x] Check for a project spec checker. None is currently available; every available required command finished with zero warnings and zero errors.

### Task 7: Recursive Dynamic Executable Preparation

**Files:**
- Add: `crates/agora-sandbox/src/execution/`
- Add: `crates/agora-sandbox/src/hook/process.rs`
- Modify: `crates/agora-sandbox/src/runner/mod.rs`
- Modify: `crates/agora-sandbox/tests/runner.rs`

- [x] Add failing tests proving the root executable can use a prepared copy and an explicit copied
  shell recursively prepares a system command even after `env -i` clears its environment.
- [x] Add an authenticated per-run loopback execution controller backed by the persistent
  `<workdir>/fs` executable cache.
- [x] Thin universal binaries to the sandbox build target, normalize an arm64e fallback to arm64
  for aarch64 builds, ad-hoc sign each copy, and never modify the source executable.
- [x] Interpose `posix_spawn`, `posix_spawnp`, `execve`, `execv`, and `execvp`, rebuilding protected
  hook configuration from a dylib-load snapshot so descendants recursively load the hook.
- [x] Start the root as a process-group leader, terminate residual descendants, and retain valid
  prepared executables for reuse across runs.
- [x] Document the native-architecture dynamic Mach-O boundary, shebang interpreter preparation,
  unsupported launch paths, persistent checksum validation, and remaining rootless security
  limitations.

### Task 8: Native Build Architecture Selection

**Files:**
- Modify: `crates/agora-sandbox/src/execution/store.rs`
- Modify: `crates/agora-sandbox/src/execution/store/tests.rs`
- Modify: `crates/agora-sandbox/src/runner/mod.rs`
- Modify: `crates/agora-sandbox/tests/runner.rs`
- Modify: `spec/architecture/sandbox-network.md`
- Modify: `spec/architecture/modules.md`

- [x] Add failing tests for build-target slice selection and the arm64e fallback boundary.
- [x] Select the executable slice from the sandbox compile target instead of forcing arm64.
- [x] Remove the arm64-only runner guard and run macOS integration coverage on supported targets.
- [x] Document the native build-architecture behavior and verify the workspace.

### Task 9: Rootless TLS Termination

**Files:**
- Add: `crates/agora-sandbox/src/network/tls/`
- Modify: `crates/agora-sandbox/src/network/inspection.rs`
- Modify: `crates/agora-sandbox/src/network/proxy.rs`
- Modify: `crates/agora-sandbox/src/hook/trust.rs`
- Modify: `crates/agora-sandbox/src/runner/mod.rs`
- Modify: `crates/agora-sandbox/src/main.rs`

- [x] Parse fragmented TLS ClientHello SNI and ALPN while preserving all inspected bytes.
- [x] Validate a fixed PEM CA certificate/private-key pair and issue Public Suffix List-aware
  wildcard DNS or exact IP leaf certificates through a bounded in-memory cache.
- [x] Verify upstream TLS with native roots, mirror the selected ALPN downstream, and relay
  decrypted application bytes.
- [x] Make required detection and all certificate, verification, and handshake failures fail
  closed without raw fallback.
- [x] Inject the interception CA certificate, but never its private key, into covered macOS
  `SecTrust` SSL evaluations; preserve optional trust-only anchors and explicit application anchors.
- [x] Add certificate, replay-I/O, fragmented ClientHello, successful interception, untrusted
  upstream, plaintext passthrough, configuration, and CLI tests.

### Task 10: Persistent Preparation And Correlated Process Audit

**Files:**
- Modify: `crates/agora-sandbox/src/execution/`
- Modify: `crates/agora-sandbox/src/hook/process.rs`
- Modify: `crates/agora-sandbox/src/trace.rs`
- Modify: `crates/agora-sandbox/src/main.rs`
- Add: `spec/architecture/sandbox.md`

- [x] Mirror restricted executables beneath persistent `<workdir>/fs` paths and validate reusable
      copies with directory-local versioned `.metadata` cached checksums.
- [x] Remove the deprecated `clean` command; persistent state is removed only by explicitly
      deleting the work directory outside normal sandbox startup.
- [x] Publish intercepted descendant `process.exec.attempt` events through the shared asynchronous
      callback while leaving process decisions audit-only.
- [x] Propagate a bounded, comma-separated trace chain through `AGORA_SANDBOX_TRACE_ID`, audit
      protocol version 1, and network CONNECT protocol version 7. Keep execution preparation on
      protocol version 5 without audit metadata.
- [x] Bound process audit metadata to 256 arguments and 64 KiB, retaining a `[truncated]` marker
      rather than rejecting a valid launch.
- [x] Add full copied-bash/system-curl transparent TLS coverage, isolate malformed control
      connections, and retain relay byte counts when one direction fails.
