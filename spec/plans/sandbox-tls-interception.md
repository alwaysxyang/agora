# Sandbox TLS Interception Implementation Plan

> **For agentic workers:** Execute this plan inline with test-driven development. This repository
> forbids dispatching multiple agents or subagents.

**Status:** Completed. The descriptions and checks below reflect the implemented behavior.

**Goal:** Add rootless TLS interception to `agora-sandbox` by terminating covered client TLS,
validating a separate TLS connection to the real destination, and relaying plaintext application
bytes between them.

**Architecture:** A caller may supply one persistent CA certificate and matching private key, or
allow the runner to reuse or generate the default pair under the configured sandbox workdir. The
host proxy loads that material, issues bounded in-memory leaves for a Public Suffix List-aware
wildcard DNS identity or exact destination IP, and keeps the private key outside the child. The
hook injects the CA certificate into covered macOS `SecTrust` evaluations, while common
environment-aware clients receive a CA-keyed bundle containing the interception CA and native
roots. The proxy replays the already-inspected ClientHello into a rustls server connection,
establishes and verifies an upstream rustls client connection, aligns ALPN, and fails closed on
every TLS setup error.

**Tech Stack:** Rust 2024, Tokio, rustls, tokio-rustls, rcgen, rustls-native-certs,
rustls-pemfile.

---

### Task 1: Fixed CA loading and leaf issuance

**Files:**
- Create: `crates/agora-sandbox/src/network/tls/certificate.rs`
- Create: `crates/agora-sandbox/src/network/tls/certificate/tests.rs`
- Modify: `crates/agora-sandbox/src/network/tls/mod.rs`
- Modify: `crates/agora-sandbox/Cargo.toml`
- Modify: `Cargo.toml`

- [x] Add failing tests for malformed CA input, mismatched keys, DNS SAN issuance, IP SAN issuance,
      and bounded normalized-identity caching.
- [x] Run the certificate tests and confirm they fail because the issuer does not exist.
- [x] Implement PEM/DER CA parsing, key-pair validation, Public Suffix List-aware DNS wildcarding,
      exact IP issuance, and a bounded in-memory cache.
- [x] Run the certificate tests and confirm they pass without warnings.

### Task 2: ClientHello metadata and replay stream

**Files:**
- Modify: `crates/agora-sandbox/src/network/inspection.rs`
- Modify: `crates/agora-sandbox/src/network/inspection_tests.rs`
- Create: `crates/agora-sandbox/src/network/tls/io.rs`
- Create: `crates/agora-sandbox/src/network/tls/io/tests.rs`

- [x] Add failing tests that extract TLS identity and ALPN while preserving all inspected bytes.
- [x] Add failing async tests proving a replay stream returns buffered bytes before socket bytes and
      still forwards writes unchanged.
- [x] Run the focused tests and confirm the new assertions fail.
- [x] Extend inspection metadata and implement the minimal generic replay stream.
- [x] Run the focused tests and confirm they pass.

### Task 3: Bidirectional TLS bridge

**Files:**
- Create: `crates/agora-sandbox/src/network/tls/mod.rs`
- Create: `crates/agora-sandbox/src/network/tls/tests.rs`
- Modify: `crates/agora-sandbox/src/network/mod.rs`
- Modify: `crates/agora-sandbox/src/network/proxy.rs`
- Modify: `crates/agora-sandbox/src/network/tests/proxy.rs`

- [x] Add an end-to-end failing test with a local trusted TLS origin and a sandbox client that
      trusts the configured CA.
- [x] Add failing tests for upstream certificate rejection, plaintext passthrough, and ALPN
      propagation.
- [x] Run the proxy tests and confirm failures are caused by absent TLS termination.
- [x] Implement upstream verified TLS, downstream dynamically issued TLS, prefixed ClientHello
      replay, plaintext bidirectional relay, and fail-closed error propagation.
- [x] Populate `TlsContext` on established, failed, and closed events.
- [x] Run the proxy tests and confirm all TLS and existing raw relay cases pass.

### Task 4: Configuration, hook trust transport, and CLI

**Files:**
- Modify: `crates/agora-sandbox/src/network/config.rs`
- Modify: `crates/agora-sandbox/src/runner/mod.rs`
- Modify: `crates/agora-sandbox/src/runner/tests.rs`
- Modify: `crates/agora-sandbox/src/hook/trust.rs`
- Modify: `crates/agora-sandbox/src/hook/trust/tests.rs`
- Modify: `crates/agora-sandbox/src/main.rs`
- Modify: `crates/agora-sandbox/src/main/tests.rs`
- Modify: `crates/agora-sandbox/tests/cli.rs`
- Modify: `crates/agora-sandbox/tests/runner.rs`

- [x] Add failing validation tests accepting `Off` without a CA, allowing `Auto` to use its default
      CA paths, and rejecting incomplete or mismatched explicit material.
- [x] Add failing CLI tests for `--tls`, `--tls-ca-cert`, and `--tls-ca-key`.
- [x] Add failing hook tests for transporting and injecting the interception CA alongside an
      optional trust-only anchor.
- [x] Implement immutable CA-pair configuration, CLI parsing, host-only private-key loading, and
      CA DER transport to the child.
- [x] Run runner, hook, and CLI tests and confirm they pass.

### Task 5: Specification and complete verification

**Files:**
- Modify: `spec/architecture/sandbox-network.md`
- Modify: `spec/architecture/modules.md`
- Modify: `spec/plans/sandbox-network-implementation.md`

- [x] Document TLS `Off` and `Auto`, fixed/default CA ownership, TLS event outcomes, ALPN,
      fail-closed behavior, and the `SecTrust` and trust-bundle coverage limitations.
- [x] Run `cargo fmt --all -- --check`.
- [x] Run `cargo test --workspace --all-targets`.
- [x] Run `cargo clippy --workspace --all-targets -- -D warnings`.
- [x] Check for `just spec-check`; no checker is currently available.
- [x] Run `cargo llvm-cov --workspace --all-targets --fail-under-lines 90` and require at least 90%
      line coverage.

## Self-Review

- The plan covers persistent CA validation, normalized wildcard/IP issuance, ClientHello replay, upstream and
  downstream TLS, ALPN, callback events, CLI/API behavior, hook trust injection, fail-closed
  errors, documentation, and required validation.
- TLS content-level HTTP policy is intentionally absent because the approved scope is termination
  and transparent application-byte relay only.
- Certificate caching is bounded and per process; generated leaf material is never persisted.
- Existing raw TCP and outbound HTTP proxy decisions remain supported.
