# Hook Module Directory Layout Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:executing-plans` to implement this plan task-by-task. This repository forbids subagent delegation. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Group macOS filesystem, network, trust, and process hooks into ownership-based directories and place global hook lifecycle at the hook root without changing behavior or exported ABI.

**Architecture:** `hook/mod.rs` owns dylib initialization, the initialized flag, exit flushing, and shared errno handling. `hook/filesystem/mod.rs`, `hook/network/mod.rs`, `hook/network/trust/mod.rs`, and `hook/process/mod.rs` own their respective domains. The crate-level `src/network/` controller remains unchanged.

**Tech Stack:** Rust 2024 modules, macOS DYLD interposition, a C variadic shim compiled by `cc`, Cargo tests, Clippy, and `cargo llvm-cov`.

## Global Constraints

- Preserve every `agora_sandbox_*` exported symbol, C signature, and `dyld_interpose!` registration.
- Preserve initialization order, release/acquire ordering, filesystem behavior, network routing, TLS trust injection, errno values, and public APIs.
- Add no dependency, feature, configuration key, compatibility layer, or generic abstraction.
- Use exact file moves plus the minimum module, build, test, and spec path updates.
- Run Cargo commands sequentially with 16 jobs and retain at least 90 percent workspace line coverage.
- Leave changes uncommitted and unpushed.

## Resulting File Map

```text
crates/agora-sandbox/src/hook/
├── mod.rs
├── config.rs
├── dyld.rs
├── tests.rs
├── process/
│   ├── mod.rs
│   └── tests.rs
├── filesystem/
│   ├── mod.rs
│   ├── filesystem_shim.c
│   ├── descriptor.rs
│   ├── metadata.rs
│   ├── namespace.rs
│   ├── open.rs
│   ├── unsupported.rs
│   ├── tests.rs
│   └── directory/
│       ├── mod.rs
│       └── fts.rs
└── network/
    ├── mod.rs
    ├── socket.rs
    ├── tests.rs
    └── trust/
        ├── mod.rs
        └── tests.rs
```

Exact moves:

```text
hook/filesystem.rs       -> hook/filesystem/mod.rs
hook/filesystem_shim.c   -> hook/filesystem/filesystem_shim.c
hook/interpose.rs        -> hook/network/mod.rs
hook/interpose/tests.rs  -> hook/network/tests.rs
hook/socket.rs           -> hook/network/socket.rs
hook/trust.rs            -> hook/network/trust/mod.rs
hook/trust/tests.rs      -> hook/network/trust/tests.rs
hook/process.rs          -> hook/process/mod.rs
```

---

### Task 1: Record the Behavior and ABI Baseline

**Files:**

- Inspect: `crates/agora-sandbox/src/hook/`
- Test: existing filesystem, network, trust, and process hook tests

**Interfaces:**

- Consumes: current hook module paths and exported symbol set.
- Produces: behavior and ABI evidence for comparison after the moves.

- [ ] **Step 1: Record exported symbols**

```bash
git grep -h -o 'agora_sandbox_[a-z0-9_]*' HEAD -- crates/agora-sandbox/src/hook \
  | sort -u > /tmp/agora-hook-symbols-before.txt
```

Expected: the list contains connect, filesystem, process, and trust hook symbols.

- [ ] **Step 2: Run the hook baseline**

```bash
cargo test -p agora-sandbox 'hook::' --jobs 16
```

Expected: every hook test passes with no warning.

- [ ] **Step 3: Verify the final directory roots are initially absent**

```bash
test -f crates/agora-sandbox/src/hook/filesystem/mod.rs
test -f crates/agora-sandbox/src/hook/network/mod.rs
test -f crates/agora-sandbox/src/hook/process/mod.rs
test -f crates/agora-sandbox/src/hook/network/trust/mod.rs
```

Expected: each check fails before its corresponding move and passes afterward. These checks are the structural RED/GREEN acceptance test for this behavior-neutral refactor.

---

### Task 2: Move Domain-Owned Files

**Files:**

- Move: every source listed in the exact move map above.
- Modify: `crates/agora-sandbox/build.rs`
- Modify: Rust imports and exact self-spawned test filters affected by nesting depth.

**Interfaces:**

- Preserves: Rust module names `hook::filesystem`, `hook::network`, `hook::network::trust`, and `hook::process`.
- Preserves: C shim symbols and all exported hook entry points.

- [ ] **Step 1: Move the Rust module roots and their tests**

Perform only the exact moves in the file map. Keep child operation files in place. Update the network self-spawn filter to:

```text
hook::network::tests::configured_hook_runtime_exercises_exported_entry_points
```

Keep trust fixture paths resolving to:

```text
crates/agora-sandbox/tests/fixtures/test-ca.der.b64
crates/agora-sandbox/tests/fixtures/test-leaf.der.b64
```

- [ ] **Step 2: Compile the C shim from its new path**

In `crates/agora-sandbox/build.rs`, use this path for both `rerun-if-changed` and `cc::Build::file`:

```text
src/hook/filesystem/filesystem_shim.c
```

- [ ] **Step 3: Preserve socket-helper visibility after nesting**

Keep `RawSocketAddress`, its `new`/`as_ptr`/`len` methods, and `socket_addr_from_raw` visible only inside `crate::hook` with `pub(in crate::hook)`. Re-export them from `network/mod.rs` only under `#[cfg(test)]`; use a private import otherwise.

- [ ] **Step 4: Format and run focused tests**

```bash
cargo fmt --all
cargo test -p agora-sandbox 'hook::' --jobs 16
```

Expected: the moved modules compile under unchanged Rust module paths and all hook tests pass.

---

### Task 3: Move Global Lifecycle to the Hook Root

**Files:**

- Modify: `crates/agora-sandbox/src/hook/mod.rs`
- Modify: `crates/agora-sandbox/src/hook/network/mod.rs`
- Modify: `crates/agora-sandbox/src/hook/filesystem/mod.rs`
- Modify: `crates/agora-sandbox/src/hook/network/tests.rs`

**Interfaces:**

- Produces: private `hook::initialized() -> bool` for filesystem and network guards.
- Preserves: the dylib initializer section and the existing config/filesystem startup sequence.

- [ ] **Step 1: Move lifecycle state and functions unchanged**

Move these items from network to `hook/mod.rs`:

```text
HOOK_INITIALIZED
EXIT_FLUSH_REGISTERED
initialized
flush_filesystem_at_exit
initialize_hook
HOOK_INITIALIZER
```

Retain `Ordering::Acquire` for reads, `Ordering::Release` for publication, and this initialization order:

```rust
config::initialize();
filesystem::initialize_process();
EXIT_FLUSH_REGISTERED.call_once(|| unsafe {
    libc::atexit(flush_filesystem_at_exit);
});
HOOK_INITIALIZED.store(true, Ordering::Release);
```

- [ ] **Step 2: Point child domains at root lifecycle**

Import `super::initialized` in `network/mod.rs`. Change the filesystem guard to call `super::initialized()`. Keep network recursion/runtime state in `network/mod.rs` and the shared `set_errno` helper in `hook/mod.rs`.

- [ ] **Step 3: Make test dependencies explicit**

In `network/tests.rs`, import lifecycle test items from the hook root and import `AtomicBool`/`Ordering` directly from the standard library. Do not add a production API or duplicate state for tests.

- [ ] **Step 4: Verify structure, behavior, and ABI**

```bash
test -f crates/agora-sandbox/src/hook/process/mod.rs
test -f crates/agora-sandbox/src/hook/network/trust/mod.rs
test ! -e crates/agora-sandbox/src/hook/process.rs
test ! -e crates/agora-sandbox/src/hook/network/trust.rs
cargo test -p agora-sandbox 'hook::' --jobs 16
diff -u /tmp/agora-hook-symbols-before.txt \
  <(rg -o --no-filename 'agora_sandbox_[a-z0-9_]+' \
      crates/agora-sandbox/src/hook -g '*.{rs,c}' | sort -u)
```

Expected: all structural checks pass, hook tests pass, and the symbol diff is empty.

---

### Task 4: Align Specifications

**Files:**

- Modify: `spec/architecture/sandbox.md`
- Modify: relevant historical implementation-plan paths that describe the current layout.

**Interfaces:**

- Produces: documentation that assigns global lifecycle to `hook/mod.rs` and domain behavior to the corresponding directory modules.

- [ ] **Step 1: Update ownership and paths**

Document these boundaries exactly:

- `hook/mod.rs`: dylib initializer, initialized state, config/filesystem startup, exit flush, shared errno.
- `hook/filesystem/mod.rs`: filesystem facade and shared runtime.
- `hook/network/mod.rs`: connect interception and network recursion/runtime state.
- `hook/network/trust/mod.rs`: Security.framework trust interception.
- `hook/process/mod.rs`: process execution interception.

- [ ] **Step 2: Check specification consistency**

```bash
rg -n 'network::initialized|hook/network/trust\.rs|hook/process\.rs' \
  spec/architecture/sandbox.md \
  spec/plans/2026-08-05-hook-module-directory-layout-design.md
git diff --check
```

Expected: the obsolete-current-layout search has no matches and the diff check passes.

---

### Task 5: Full Validation and Final Review

**Files:**

- Review: all moved and modified files from Tasks 2 through 4.

**Interfaces:**

- Produces: release-quality evidence that the refactor is behavior- and ABI-neutral.

- [ ] **Step 1: Run formatting and workspace tests**

```bash
cargo fmt --all -- --check
git diff --check
cargo test --workspace --all-targets --jobs 16
```

- [ ] **Step 2: Run lint and release validation**

```bash
cargo clippy --workspace --all-targets --all-features --jobs 16 -- -D warnings
cargo build --workspace --release --jobs 16
```

- [ ] **Step 3: Run coverage once from clean path-aware artifacts**

```bash
cargo llvm-cov clean --workspace
cargo llvm-cov --no-clean --workspace --all-targets --jobs 16 --fail-under-lines 90
```

Expected: all tests pass, lint/build emit no warnings, and workspace line coverage is at least 90 percent.

- [ ] **Step 4: Review and leave the work uncommitted**

```bash
git status --short
git diff --stat
git diff --summary
```

Confirm that source changes are limited to exact moves, module/build/test path adjustments, lifecycle/errno ownership, and matching spec updates. Do not commit or push.
