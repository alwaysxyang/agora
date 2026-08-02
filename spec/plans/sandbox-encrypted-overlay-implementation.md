# Encrypted Filesystem Overlay Implementation Plan

> **For agentic workers:** Execute this plan sequentially in the current task. Do not dispatch subagents. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the optional encrypted snapshot and plaintext executable cache with one rootless, read-through COW filesystem, plaintext by default, with explicit encrypted storage and in-place encrypted-key migration.

**Architecture:** Prepare one persistent filesystem root at `<workdir>/fs`, backed by a plaintext directory by default or an explicitly selected encrypted APFS sparse bundle. A filesystem store owns directory metadata, materialization, COW transitions, and whiteouts; the executable store publishes prepared binaries through that store. The injected dylib redirects supported path APIs into the selected tree while preserving native descriptor I/O.

**Tech Stack:** Rust, Tokio, macOS dyld interposition, APFS sparse bundles through `hdiutil`, serde JSON metadata, MD5 source checksums.

---

### Task 1: Mandatory Encrypted Volume And CLI Surface

**Files:**
- Modify: `crates/agora-sandbox/src/filesystem/apfs.rs`
- Modify: `crates/agora-sandbox/src/filesystem/apfs/tests.rs`
- Modify: `crates/agora-sandbox/src/runner/mod.rs`
- Modify: `crates/agora-sandbox/src/runner/tests.rs`
- Modify: `crates/agora-sandbox/src/main.rs`
- Modify: `crates/agora-sandbox/src/tests.rs`
- Modify: `crates/agora-sandbox/tests/cli.rs`

- [x] Add tests proving a run without a filesystem key fails validation and the CLI no longer exposes `clean`.
- [x] Change APFS storage to `filesystem/fs.sparsebundle` mounted directly at `<workdir>/fs`.
- [x] Replace source-bound snapshot metadata and `ditto` initialization with encrypted `volume.json` initialization.
- [x] Reject existing plaintext content at an unmounted `<workdir>/fs`.
- [x] Remove the `clean` subcommand and executable-cache cleaner.
- [x] Run `cargo test -p agora-sandbox --all-targets` and confirm all tests pass.

### Task 2: Directory Metadata Store

**Files:**
- Create: `crates/agora-sandbox/src/filesystem/metadata.rs`
- Create: `crates/agora-sandbox/src/filesystem/metadata/tests.rs`
- Modify: `crates/agora-sandbox/src/filesystem/mod.rs`

- [x] Add tests for metadata serialization, encoded entry names, cached/COW/whiteout transitions, unsupported versions, and malformed records.
- [x] Implement `DirectoryMetadata`, `EntryState`, and `Materializer` with directory-local logical records under `fs/.agora/metadata`.
- [x] Publish metadata atomically while holding the overlay lock.
- [x] Run the focused metadata tests and confirm they pass.

### Task 3: Read-Through And COW Store

**Files:**
- Create: `crates/agora-sandbox/src/filesystem/overlay.rs`
- Create: `crates/agora-sandbox/src/filesystem/overlay/tests.rs`
- Modify: `crates/agora-sandbox/src/filesystem/mod.rs`

- [x] Add tests for first-read materialization, unchanged reuse, MD5 refresh, write-intent copy-up, COW preservation after a host change, creation, deletion whiteouts, recreation, and reserved namespace rejection.
- [x] Implement path mapping and MD5 calculation for regular files.
- [x] Implement atomic normal-file materialization and state transitions under the overlay lock.
- [x] Implement whiteout and rename operations without writing to host paths.
- [x] Run the focused overlay tests and confirm they pass.

### Task 4: Executable Store Integration

**Files:**
- Modify: `crates/agora-sandbox/src/execution/store.rs`
- Modify: `crates/agora-sandbox/src/execution/store/tests.rs`
- Modify: `crates/agora-sandbox/src/execution/controller.rs`
- Modify: `crates/agora-sandbox/src/execution/tests.rs`

- [x] Replace `checksums.json` with shared directory metadata and test missing, matching, and changed source checksums.
- [x] Preserve architecture selection, arm64e rewriting, ad-hoc signing, permissions, and atomic publication.
- [x] Mark prepared copies as cached executable materializations rather than COW files.
- [x] Run execution store and controller tests and confirm they pass.

### Task 5: Hook Path Virtualization

**Files:**
- Create: `crates/agora-sandbox/src/hook/filesystem.rs`
- Create: `crates/agora-sandbox/src/hook/filesystem/tests.rs`
- Modify: `crates/agora-sandbox/src/hook/mod.rs`
- Modify: `crates/agora-sandbox/src/hook/config.rs`
- Modify: `crates/agora-sandbox/src/hook/config/tests.rs`
- Modify: `crates/agora-sandbox/src/runner/mod.rs`
- Modify: `crates/agora-sandbox/src/runner/tests.rs`

- [x] Add tests for filesystem-root environment parsing, relative and absolute path resolution, bypass paths, read opens, write opens, creation, deletion, and rename.
- [x] Inject the selected filesystem root into every prepared process environment.
- [x] Interpose open/create, stat/access, truncate, metadata mutation, link/copy, deletion/rename, directory, and supported `*at` entry points; route supported operations through the overlay and return `ENOTSUP` for path mutation families that cannot yet be represented safely.
- [x] Rewrite deferred `posix_spawn_file_actions_addopen` paths and commit pending COW state when spawn consumes the actions.
- [x] Preserve errno, catch hook panics, bypass recursive/internal operations, and deny unavailable virtualization.
- [x] Add merged directory enumeration with encrypted precedence, whiteout filtering, and control namespace hiding.
- [x] Run hook tests and confirm they pass.

### Task 6: In-Place Key Migration

**Files:**
- Modify: `crates/agora-sandbox/src/filesystem/apfs.rs`
- Modify: `crates/agora-sandbox/src/filesystem/apfs/tests.rs`
- Modify: `crates/agora-sandbox/src/main.rs`
- Modify: `crates/agora-sandbox/src/tests.rs`
- Modify: `crates/agora-sandbox/tests/cli.rs`

- [x] Add tests for missing images, invalid keys, identical keys, exclusive locking, successful `hdiutil chpass`, new-key verification, and key-ID update.
- [x] Add interactive `migrate-key --workdir` prompts and milestone percentage progress.
- [x] Change the passphrase in place without copying or recreating the sparse bundle.
- [x] Verify the new key and update `volume.json` only after successful migration.
- [x] Run focused APFS and CLI tests and confirm they pass.

### Task 7: End-To-End Verification And Documentation

**Files:**
- Modify: `crates/agora-sandbox/tests/runner.rs`
- Modify: `spec/architecture/sandbox.md`

- [x] Add a macOS integration test using an injected copied shell to verify host reads, encrypted writes, COW persistence, whiteouts, and unchanged host files.
- [x] Update the architecture specification to remove snapshot, plaintext cache, and clean-command behavior and document the encrypted overlay and migration command.
- [x] Run `cargo fmt --all -- --check`.
- [x] Run `cargo test -p agora-sandbox --all-targets`.
- [x] Run `cargo test --workspace --all-targets`.
- [x] Run `cargo clippy --workspace --all-targets -- -D warnings`.
- [x] Run `cargo llvm-cov --workspace --all-targets --fail-under-lines 90`.
- [ ] Run `just spec-check` when available and report the exact result.

### Task 8: Explicit Plaintext Storage Mode

**Files:**
- Create: `crates/agora-sandbox/src/filesystem/workspace.rs`
- Create: `crates/agora-sandbox/src/filesystem/workspace/tests.rs`
- Modify: `crates/agora-sandbox/src/runner/mod.rs`
- Modify: `crates/agora-sandbox/src/main.rs`
- Modify: `crates/agora-sandbox/tests/cli.rs`
- Modify: `crates/agora-sandbox/tests/runner.rs`

- [x] Keep plaintext storage as the default and require a valid key when encrypted storage is selected.
- [x] Add explicit `--filesystem plain` and `SandboxConfig::with_plain_workspace` selection without an encryption key.
- [x] Reuse the same overlay, execution preparation, and hook integration for both storage modes.
- [x] Make both modes use the same per-workdir non-blocking filesystem lock.
- [x] Verify plaintext COW persistence, unchanged host files, and same-workdir exclusion.

### Task 9: Unified File Lifecycle Audit

**Files:**
- Create: `crates/agora-sandbox/src/audit/`
- Modify: `crates/agora-sandbox/src/callback/mod.rs`
- Modify: `crates/agora-sandbox/src/hook/filesystem.rs`
- Modify: `crates/agora-sandbox/src/hook/process.rs`
- Modify: `crates/agora-sandbox/src/execution/`
- Modify: `crates/agora-sandbox/src/runner/mod.rs`
- Modify: `crates/agora-sandbox/src/main.rs`

- [x] Separate hook-originated audit delivery from executable preparation.
- [x] Add authenticated local process and file event delivery with controller-owned event metadata.
- [x] Publish logical path, structured open mode, process identity, and trace chain for `open`, `openat`, and `fopen`.
- [x] Track successful descriptors and publish corresponding `close` and `fclose` events.
- [x] Fail intercepted operations when the audit controller is unavailable and terminate the child if the controller exits.
- [x] Add protocol, callback serialization, hook lifecycle, CLI JSON, and injected-process integration coverage.
