# HTTP CONNECT Trace Target Implementation Plan

Status: implemented and verified

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Record and display an HTTP CONNECT logical target separately from the actual TCP proxy endpoint.

**Architecture:** Extend the existing HTTP protocol observation with an optional explicit CONNECT port, then project that observation into optional `target_host` and `target_port` network-event fields. Preserve `destination_ip` and `destination_port` as the intercepted socket address, carry both endpoint groups through compact audit JSON, and let Trace Viewer prefer the logical target for its title.

**Tech Stack:** Rust, serde, httparse, existing Agora network inspection/callback/audit pipeline.

## Global Constraints

- Only HTTP `CONNECT` is in scope; do not add SOCKS parsing.
- Never infer port 443 from a hostname or TLS SNI.
- Keep direct HTTP, direct TLS, authorization, and connection routing behavior unchanged.
- Do not add dependencies, public configuration, or CLI options.
- Keep changes uncommitted unless the user separately requests a commit.

---

### Task 1: Extract and publish the HTTP CONNECT target

**Files:**
- Modify: `crates/agora-sandbox/src/network/inspection.rs`
- Test: `crates/agora-sandbox/src/network/inspection_tests.rs`
- Modify: `crates/agora-sandbox/src/callback/mod.rs`
- Modify: `crates/agora-sandbox/src/network/mod.rs`
- Test: `crates/agora-sandbox/src/network/tests/mod.rs`
- Update constructors: `crates/agora-sandbox/src/tests.rs`

**Interfaces:**
- `DomainObservation` gains `target_port: Option<u16>`.
- `NetworkContext` gains a boxed optional `NetworkTarget { host: String, port: u16 }`; serde flattens
  it to `target_host` and `target_port` JSON fields while one optional pointer keeps `Event` below
  Clippy's large-variant threshold and enforces that both logical target fields exist together.
- `EVENT_SCHEMA_VERSION` advances from 8 to 9 because `NetworkContext` is public and serialized.
- A valid CONNECT observation sets `target_port`; ordinary Host and TLS SNI observations leave it `None`.

- [x] **Step 1: Write the failing inspection test**

Add a test that feeds `CONNECT chatgpt.com:443 HTTP/1.1` with a matching Host header and expects:

```rust
DomainObservation {
    domain: "chatgpt.com".to_string(),
    source: DomainSource::HttpHost,
    target_port: Some(443),
}
```

Update existing expectations to include `target_port: None` and add a case proving ordinary
`GET` plus `Host: example.com:8080` does not create a CONNECT target.

- [x] **Step 2: Run the inspection test and verify RED**

Run:

```bash
cargo test -p agora-sandbox network::inspection_tests --jobs 16
```

Expected: compilation or assertion failure because `target_port` does not exist.

- [x] **Step 3: Implement minimal CONNECT authority extraction**

In `ProtocolInspector::inspect_http`, recognize only `request.method == Some("CONNECT")`. Parse an
explicit DNS authority and `u16` port from `request.path`, require its normalized host to match the
existing normalized Host observation, and set `target_port`. Leave malformed, portless, IP-only, and
non-CONNECT requests at `None`.

- [x] **Step 4: Run inspection tests and verify GREEN**

Run the same focused command and expect all inspection tests to pass without warnings.

- [x] **Step 5: Write the failing network-context test**

Extend the existing context test with a CONNECT observation and assert:

```rust
assert_eq!(context.destination_ip, "127.0.0.1".parse().unwrap());
assert_eq!(context.destination_port, 1087);
let target = context.target.as_deref().unwrap();
assert_eq!(target.host, "chatgpt.com");
assert_eq!(target.port, 443);
```

Also assert that a TLS SNI observation leaves both target fields `None`.

- [x] **Step 6: Run the network-context test and verify RED**

Run:

```bash
cargo test -p agora-sandbox network::tests::tls_sni_populates_only_the_tls_domain_fields --jobs 16
```

Expected: compilation failure because `NetworkContext` has no target fields.

- [x] **Step 7: Publish the target fields**

Add the optional boxed target to `NetworkContext`. In `NetworkState::network_context`, populate it
only when `DomainObservation::target_port` is present; continue filling destination from
`RouteRegistration::destination` and domain fields from the existing observation.

- [x] **Step 8: Run focused sandbox tests and verify GREEN**

Run:

```bash
cargo test -p agora-sandbox network::tests --jobs 16
```

Expected: all focused tests pass without warnings.

### Task 2: Preserve both endpoints in compact audit and Trace Viewer

**Files:**
- Modify: `crates/agora-sandbox/src/main.rs`
- Test: `crates/agora-sandbox/src/tests.rs`
- Modify: `crates/agora-tools/src/trace_viewer/audit.rs`

**Interfaces:**
- `AuditRecord::Network` gains `target_host: Option<String>` and `target_port: Option<u16>`.
- `CompactAudit::Network` accepts those optional fields, including old records where they are absent.
- Viewer title selection prefers a complete logical target and otherwise preserves current behavior.

- [x] **Step 1: Write the failing audit serialization test**

Construct a network event with destination `127.0.0.1:1087` and target `chatgpt.com:443`, serialize
the callback record, and assert the audit JSON contains all four endpoint fields with their original
values.

- [x] **Step 2: Run the audit test and verify RED**

Run:

```bash
cargo test -p agora-sandbox tests --jobs 16
```

Expected: assertion or compilation failure because compact audit has no target fields.

- [x] **Step 3: Extend compact audit serialization**

Copy `NetworkContext::target.host` and `target.port` into `AuditRecord::Network` as the flattened
`target_host` and `target_port` fields. Do not rename or reinterpret the existing destination and
domain fields.

- [x] **Step 4: Run the sandbox audit tests and verify GREEN**

Run the same focused command and expect it to pass without warnings.

- [x] **Step 5: Write the failing Trace Viewer test**

Normalize this compact record:

```json
{"audit":{"type":"network","access_time":"t","trace_id":"root","pid":3,"destination_ip":"127.0.0.1","destination_port":1087,"domain":"chatgpt.com","target_host":"chatgpt.com","target_port":443}}
```

Assert the title is `chatgpt.com:443`, while detail still contains destination port `1087`. Preserve
the existing old-record test to prove missing target fields remain accepted.

- [x] **Step 6: Run the viewer test and verify RED**

Run:

```bash
cargo test -p agora-tools trace_viewer::audit::tests --jobs 16
```

Expected: title remains `chatgpt.com:1087`.

- [x] **Step 7: Prefer the complete logical target**

Add optional target fields to `CompactAudit::Network`. Format `target_host:target_port` only when
both are present and the host is non-empty; otherwise retain the existing domain/destination and IP
fallback rules. Keep the raw audit object unchanged as `TraceEvent::detail`.

- [x] **Step 8: Run Trace Viewer tests and verify GREEN**

Run the same focused command and expect all tests to pass without warnings.

### Task 3: Update architecture documentation and verify the workspace

**Files:**
- Modify: `spec/architecture/sandbox-network.md`
- Reference: `docs/superpowers/specs/2026-08-15-http-connect-trace-target-design.md`

**Interfaces:**
- Event schema documents actual destination separately from optional HTTP CONNECT logical target.

- [x] **Step 1: Update the network schema specification**

Document that `destination_ip` and `destination_port` remain the actual intercepted TCP endpoint;
`target_host` and `target_port` are both present only when a valid HTTP CONNECT authority is
observed; and TLS SNI never causes a target port to be inferred.

- [x] **Step 2: Format and run focused checks**

Run:

```bash
cargo fmt --all -- --check
cargo test -p agora-sandbox network --jobs 16
cargo test -p agora-tools trace_viewer --jobs 16
cargo clippy --workspace --all-targets --jobs 16 -- -D warnings
```

Expected: every command exits successfully with no warnings or errors.

- [x] **Step 3: Run workspace tests, coverage, and spec validation**

Run sequentially:

```bash
cargo test --workspace --all-targets --jobs 16
LLVM_PROFILE_FILE="$PWD/target/agora-%p-%12m.profraw" \
  cargo llvm-cov --no-clean --workspace --all-targets --jobs 16 --fail-under-lines 80
rg --files -uu -g '*.profraw' -g '!target/**'
just spec-check
git diff --check
```

Expected: tests, coverage threshold, spec check, and diff check pass; the `rg` command prints no
paths.

Validation result: tests, 90.87% line coverage, Clippy, formatting, generated-profile cleanup, and
diff checks passed. `just spec-check` was unavailable because this repository has no Justfile or
equivalent spec-check implementation and the host has no `just` binary; specification consistency
was checked directly against `spec/architecture/sandbox-network.md`.
