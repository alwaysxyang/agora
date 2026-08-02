# Sandbox TLS Defaults And Cache Implementation Plan

> Execute this plan with the current agent only. Project rules prohibit delegating work to subagents.

**Status:** Completed. The descriptions below reflect the implemented behavior.

**Goal:** Make TLS auto mode work without explicit CA paths, reuse one-day PSL-aware wildcard leaf certificates, and preserve copied executable basenames.

**Architecture:** Resolve TLS auto defaults from the configured sandbox workdir before network startup. Keep CA lifecycle in sandbox configuration/runner code, leaf identity and cache behavior in the TLS authority, and persistent executable-copy layout in the execution store. Avoid new runtime layers.

**Tech Stack:** Rust, clap, rcgen, psl, LRU-style in-memory cache, cargo test/clippy/llvm-cov.

## Task 1: Default TLS CA paths

**Files:**
- Modify: `crates/agora-sandbox/src/runner/mod.rs`
- Modify: `crates/agora-sandbox/tests/sandbox_cli.rs`

1. Add failing tests proving TLS auto accepts omitted CA paths and creates `ca/ca.crt` plus `ca/ca.key` under the configured sandbox workdir.
2. Resolve the sandbox workdir before TLS initialization.
3. Keep explicit CA paths authoritative; when omitted, reuse both default files or overwrite both when either is missing.
4. Run `cargo test -p agora-sandbox --test sandbox_cli` and the affected runner tests.

## Task 2: PSL-aware leaf certificate cache

**Files:**
- Modify: `Cargo.toml`
- Modify: `crates/agora-sandbox/Cargo.toml`
- Modify: `crates/agora-sandbox/src/network/tls/certificate.rs`

1. Add failing tests for wildcard normalization, sibling-host reuse, registrable-domain/IP preservation, and cache expiration.
2. Add the `psl` dependency and normalize DNS names using the public suffix list.
3. Cache signed certificates by normalized identity for one hour, with one-day certificate validity and existing capacity limits.
4. Serialize same-process cache misses with the existing cache mutex.
5. Run the TLS certificate tests and package tests.

## Task 3: Preserve executable paths and basenames

**Files:**
- Modify: `crates/agora-sandbox/src/execution/store.rs`
- Modify nearby sandbox integration tests if their assertions depend on the old prefixed name.

1. Add failing tests proving copied executables retain the source basename while remaining collision-safe.
2. Mirror each canonical source path beneath `<workdir>/fs`, keeping the leaf filename unchanged.
3. Reuse persistent copies only when the executable and its directory-local `checksums.json` MD5 entry remain valid.
4. Ensure failed preparation removes its temporary artifact without deleting a valid persistent cache entry.
5. Run the execution store and runner tests.

## Task 4: Full verification

1. Run `cargo fmt --all -- --check` after formatting.
2. Run `cargo test --workspace --all-targets`.
3. Run `cargo clippy --workspace --all-targets -- -D warnings`.
4. Run `just spec-check` when available.
5. Run `cargo llvm-cov --workspace --all-targets --fail-under-lines 90`.
6. Confirm code and `spec/architecture/sandbox-network.md` plus `spec/architecture/modules.md` agree.
