# Filesystem Hook Modularization and VFS Deduplication Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Split the macOS filesystem hook into focused syscall-family modules and remove duplicate VFS final-path and parent-attribute work without changing observable behavior.

**Architecture:** `hook/filesystem/mod.rs` is the shared runtime and facade. Child modules own complete libc operation families, including their handlers, original-function lookup, and dyld registration. VFS keeps explicit operation APIs but reuses one final-resolution/search helper, distinguishes raw from already-resolved endpoint checks, and reuses parent attributes returned by ancestor search.

**Tech Stack:** Rust 2024, macOS libc interposition, Cargo, `cargo llvm-cov`.

## Global Constraints

- Preserve all existing C symbol names, signatures, interpose targets, errno ordering, audit behavior, overlay transaction boundaries, COW behavior, and `/dev` passthrough behavior.
- Do not add dependencies, traits, generic operation dispatch, normalized-path wrapper types, or macro-generated hook frameworks.
- Keep `FilesystemHookRuntime` and cross-family state in the parent module; widen visibility only to the narrowest module scope required.
- Use 16 Cargo jobs or test threads as configured by the project; do not run competing Cargo processes against the same target directory.
- Maintain at least 90 percent workspace line coverage.
- Do not dispatch subagents and do not create a commit; project instructions require current-agent execution and leave changes uncommitted unless the user explicitly requests a commit.

---

## File Structure

**Create:**

- `crates/agora-sandbox/src/hook/filesystem/open.rs`: open-family handlers, ABI shims, original lookups, and registrations.
- `crates/agora-sandbox/src/hook/filesystem/descriptor.rs`: descriptor/content lifecycle handlers, fcntl shim, original lookups, and registrations.
- `crates/agora-sandbox/src/hook/filesystem/metadata.rs`: metadata, access, readlink, and chmod handlers plus registrations.
- `crates/agora-sandbox/src/hook/filesystem/namespace.rs`: supported namespace mutations plus registrations.
- `crates/agora-sandbox/src/hook/filesystem/unsupported.rs`: fail-closed mutation families and native-passthrough adapters.
- `crates/agora-sandbox/src/hook/filesystem/directory/mod.rs`: current-directory and merged directory-stream handlers.
- `crates/agora-sandbox/src/hook/filesystem/directory/fts.rs`: Darwin FTS and virtual `getattrlistbulk` handling.

**Modify:**

- `crates/agora-sandbox/src/hook/filesystem/mod.rs`: retain shared runtime/facade code, declare child modules, and remove operation-family implementations.
- `crates/agora-sandbox/src/hook/filesystem/tests.rs`: adjust only imports if the root facade no longer privately re-exports every test entry point.
- `crates/agora-sandbox/src/filesystem/overlay.rs`: add test-only final-resolution instrumentation.
- `crates/agora-sandbox/src/filesystem/vfs.rs`: consolidate resolution/search and resolved endpoint checks; return reusable parent attributes from ancestor search.
- `crates/agora-sandbox/src/filesystem/vfs/tests.rs`: add resolution-count regressions.
- `spec/architecture/sandbox.md`: document internal hook module ownership and single-resolution reuse.

**Already added design inputs:**

- `spec/plans/2026-08-05-filesystem-hook-modularization-vfs-dedup-design.md`
- `spec/plans/2026-08-05-filesystem-hook-modularization-vfs-dedup-implementation.md`

---

### Task 1: Record the Green Characterization Baseline

**Files:**

- Test: `crates/agora-sandbox/src/hook/filesystem/tests.rs`
- Test: `crates/agora-sandbox/src/filesystem/vfs/tests.rs`

**Interfaces:**

- Consumes: the current monolithic hook and authorized VFS APIs.
- Produces: a verified green baseline; no source changes.

- [ ] **Step 1: Run the focused VFS suite**

Run:

```bash
cargo test -p agora-sandbox filesystem::vfs::tests --jobs 16
```

Expected: PASS with zero warnings.

- [ ] **Step 2: Run the focused hook suite**

Run:

```bash
cargo test -p agora-sandbox hook::filesystem::tests --jobs 16
```

Expected: PASS with zero warnings.

- [ ] **Step 3: Check the existing exported symbol inventory**

Run:

```bash
rg -o "agora_sandbox_[a-z0-9_]+" crates/agora-sandbox/src/hook/filesystem/mod.rs | sort -u
```

Save the output for comparison after modularization. Every name must remain present in the new parent-plus-child source tree.

---

### Task 2: Extract Directory Enumeration and FTS

**Files:**

- Create: `crates/agora-sandbox/src/hook/filesystem/directory/mod.rs`
- Create: `crates/agora-sandbox/src/hook/filesystem/directory/fts.rs`
- Modify: `crates/agora-sandbox/src/hook/filesystem/mod.rs`

**Interfaces:**

- Consumes: parent-private `FilesystemHookGuard`, `FilesystemHookRuntime`, `catch_filesystem_panic`, `fail`, `lock`, `set_errno`, and native-passthrough/runtime path helpers.
- Produces: `directory` module exports for `chdir`, `fchdir`, `getcwd`, `realpath`, directory streams, and nested FTS hooks; parent-test imports preserve existing test names.

- [ ] **Step 1: Add the child module declarations**

Add to `hook/filesystem/mod.rs` below the imports:

```rust
mod directory;
```

Add the other module declarations in the task that creates their files so every compile checkpoint remains green.

- [ ] **Step 2: Move directory stream state and handlers as one ownership unit**

Move these exact items into `filesystem/directory/mod.rs`:

```text
DirectoryCursor
directory_cursors
chdir/fchdir/getcwd/realpath function types and handlers
opendir/fdopendir/readdir/readdir_r/rewinddir/closedir function types and handlers
open_auxiliary_directory
register_directory_cursor
the corresponding extern declarations, original_* functions, no-mangle exports,
and dyld_interpose! registrations
```

Declare `mod fts;` inside `directory/mod.rs`. Keep `DirectoryCursor::new`, `include`, `source`, and `reset` private to `directory`; expose only the narrow members consumed by the nested FTS module.

- [ ] **Step 3: Move the complete FTS ownership unit**

Move these exact items into `filesystem/directory/fts.rs`:

```text
DarwinFtsEntry and FTS constants
FtsVirtualBulk and FTS thread-local state
FtsDescriptorIdentity, FtsBulkEntry, FtsBulkCursor
FtsRootMapping, PresentedFtsEntry, FtsStreamState
logical_basename and FTS presentation helpers
darwin_object_type, fts_descriptor_identity, fts_attr_record,
and fts_attributes_supported
getattrlistbulk handler
fts_open/fts_children/fts_read/fts_close handlers
the corresponding extern declarations, original_* functions, no-mangle exports,
and dyld_interpose! registrations
```

Use `super::DirectoryCursor` for merged-view filtering and `super::super::{FilesystemHookRuntime, ...}` for shared runtime helpers. Do not duplicate cursor logic.

- [ ] **Step 4: Preserve test visibility without widening the crate API**

Under `#[cfg(test)]`, privately import the existing Rust-visible hook exports and `DirectoryCursor` into the parent module so `filesystem/tests.rs` can keep using `super::{...}`. Use ordinary private `use`, not a new `pub(crate)` API.

- [ ] **Step 5: Format and run the hook characterization suite**

Run:

```bash
cargo fmt --all -- --check
cargo test -p agora-sandbox hook::filesystem::tests --jobs 16
```

Expected: PASS with zero warnings and unchanged directory/FTS behavior.

---

### Task 3: Extract Open and Descriptor Lifecycles

**Files:**

- Create: `crates/agora-sandbox/src/hook/filesystem/open.rs`
- Create: `crates/agora-sandbox/src/hook/filesystem/descriptor.rs`
- Modify: `crates/agora-sandbox/src/hook/filesystem/mod.rs`

**Interfaces:**

- Consumes: parent runtime path mapping, audit publication, descriptor registries, `OpenFile`, and shared guard/error helpers.
- Produces: unchanged open/fopen/spawn and descriptor/writeback C entry points. `descriptor::original_close` is visible only to the parent family so open failure can close a native descriptor.

- [ ] **Step 1: Move the open-family ownership unit**

Move into `filesystem/open.rs`:

```text
OpenFn, OpenAtFn, FopenFn, FreopenFn, PosixSpawnAddOpenFn
PreparedOpen, OpenRequest, intent_from_fopen_mode
sandbox_open_with_mode and sandbox_openat_with_mode
creat, fopen, freopen, and posix_spawn_file_actions_addopen handlers
agora_sandbox_call_open/agora_sandbox_call_openat extern declarations
all matching original_* functions, no-mangle exports, and interpose registrations
```

Keep the existing common `prepare_open_request` path. Do not fork open and fopen orchestration during the move.

- [ ] **Step 2: Move the descriptor/content ownership unit**

Move into `filesystem/descriptor.rs`:

```text
CloseFn, FcloseFn, DescriptorFn, Dup2Fn, TruncateFn, FtruncateFn
configure_descriptor
truncate and descriptor-mutation helpers
close/fclose/fsync/dup/dup2/fcntl handlers
agora_sandbox_fcntl_shim extern declaration
all matching original_* functions, no-mangle exports, and interpose registrations
```

Keep shared runtime methods for registration, duplication, writeback, and flush in the parent because both open handlers and process lifecycle entry points consume them.

- [ ] **Step 3: Preserve open-failure close semantics**

Expose exactly this internal interface from `descriptor.rs`:

```rust
pub(super) fn original_close() -> Option<CloseFn>
```

`open.rs` uses it only when native descriptor construction succeeded but VFS open commit failed. No direct libc close replacement is introduced.

- [ ] **Step 4: Preserve test imports and compare symbols**

Privately import test-facing exports into the parent under `#[cfg(test)]`. Then run:

```bash
rg -o "agora_sandbox_[a-z0-9_]+" crates/agora-sandbox/src/hook/filesystem/mod.rs crates/agora-sandbox/src/hook/filesystem -g '*.rs' | sed 's/.*://' | sort -u
```

Expected: the same symbol-name set recorded in Task 1.

- [ ] **Step 5: Format and run focused tests**

Run:

```bash
cargo fmt --all -- --check
cargo test -p agora-sandbox hook::filesystem::tests --jobs 16
```

Expected: PASS with zero warnings.

---

### Task 4: Extract Metadata, Namespace, and Unsupported Mutations

**Files:**

- Create: `crates/agora-sandbox/src/hook/filesystem/metadata.rs`
- Create: `crates/agora-sandbox/src/hook/filesystem/namespace.rs`
- Create: `crates/agora-sandbox/src/hook/filesystem/unsupported.rs`
- Modify: `crates/agora-sandbox/src/hook/filesystem/mod.rs`

**Interfaces:**

- Consumes: parent runtime mapping, native-passthrough classification, guard/error helpers, and VFS authorized APIs.
- Produces: complete remaining libc operation families and a parent module containing no concrete hook handler.

- [ ] **Step 1: Move metadata and permission operations**

Move into `filesystem/metadata.rs`:

```text
StatFn, FstatFn, FstatAtFn, AccessFn, FaccessAtFn
ReadlinkFn, ReadlinkAtFn, ChmodFn, FchmodFn, FchmodAtFn
mapped_stat, patch_stat, execute_access_plan
stat/lstat/fstat/fstatat handlers
access/faccessat handlers
readlink/readlinkat handlers
chmod/fchmod/fchmodat handlers
all matching original_* functions, no-mangle exports, and interpose registrations
```

- [ ] **Step 2: Move supported namespace operations**

Move into `filesystem/namespace.rs`:

```text
UnlinkFn, UnlinkAtFn, RenameFn, RenameAtFn, RenameXFn, RenameAtXFn
MkdirFn, MkdirAtFn, SymlinkFn, SymlinkAtFn
mkdir/mkdirat, symlink/symlinkat
unlink/unlinkat/rmdir
rename/renameat/renamex_np/renameatx_np
all matching original_* functions, no-mangle exports, and interpose registrations
```

- [ ] **Step 3: Move fail-closed mutation families**

Move into `filesystem/unsupported.rs`:

```text
timestamp, flag, xattr, ownership, hard-link, clone, and copy function types
sandbox_unsupported_path_mutation
sandbox_unsupported_descriptor_mutation
sandbox_unsupported_pair_mutation
all handlers, original_* functions, no-mangle exports, and interpose registrations for those families
```

Keep `/dev` checks before `ENOTSUP`, exactly as in the existing handlers.

- [ ] **Step 4: Remove stale parent imports and preserve tests**

Run `cargo fmt --all`, remove only imports proven unused by the compiler, and add `#[cfg(test)]` private imports for helper functions that existing tests call directly.

- [ ] **Step 5: Verify the complete modularized hook**

Run:

```bash
cargo test -p agora-sandbox hook::filesystem::tests --jobs 16
cargo check -p agora-sandbox --all-targets --jobs 16
```

Expected: PASS with zero warnings. `hook/filesystem/mod.rs` contains no `unsafe fn sandbox_*` libc handler and no `dyld_interpose!` registration.

---

### Task 5: Add Failing Final-Resolution Regressions

**Files:**

- Modify: `crates/agora-sandbox/src/filesystem/overlay.rs`
- Modify: `crates/agora-sandbox/src/filesystem/vfs.rs`
- Modify: `crates/agora-sandbox/src/filesystem/vfs/tests.rs`

**Interfaces:**

- Produces: `#[cfg(test)] OverlayStore::resolution_count_for_test() -> usize` and the matching private VFS adapter.
- Consumes: real overlay transactions and real VFS operations; no mocks.

- [ ] **Step 1: Add test-only instrumentation**

Add a `#[cfg(test)] resolution_count: AtomicUsize` field to `OverlayStore`, initialize it to zero, increment it at the start of `resolve_final_locked`, and expose:

```rust
#[cfg(test)]
pub(super) fn resolution_count_for_test(&self) -> usize {
    self.resolution_count.load(Ordering::Relaxed)
}
```

Add the corresponding private VFS adapter:

```rust
#[cfg(test)]
fn resolution_count_for_test(&self) -> usize {
    self.overlay.resolution_count_for_test()
}
```

- [ ] **Step 2: Write tests that name the duplicate-resolution bug**

Add real-operation tests with these contracts:

```rust
#[test]
fn authorized_open_resolves_an_existing_endpoint_once() {
    // Create a real lower file and an explicit logical attribute override so
    // the operation takes the full VFS path rather than native passthrough.
    // Expected resolution calls are one per searchable ancestor plus one for
    // the endpoint. The old hidden effective_attributes_in resolution adds one.
}

#[test]
fn change_directory_resolves_the_endpoint_once() {
    // Create a real directory. Expected calls are one per searchable ancestor
    // plus one endpoint resolution; the old access helper adds one extra.
}

#[test]
fn directory_creation_reuses_the_parent_resolution_from_search() {
    // Create a missing child directory below a writable parent. Search resolves
    // each ancestor, including the parent, exactly once; the later parent write
    // check must reuse those attributes instead of resolving the parent again.
}
```

Derive the expected ancestor count from the fixture path's standard-library `ancestors()` iterator, not from a VFS helper. Assert the literal extra endpoint count separately so the test fails if production resolution is duplicated.

- [ ] **Step 3: Run the three tests and observe RED**

Run:

```bash
cargo test -p agora-sandbox filesystem::vfs::tests::authorized_open_resolves_an_existing_endpoint_once --jobs 16
cargo test -p agora-sandbox filesystem::vfs::tests::change_directory_resolves_the_endpoint_once --jobs 16
cargo test -p agora-sandbox filesystem::vfs::tests::directory_creation_reuses_the_parent_resolution_from_search --jobs 16
```

Expected: each test compiles and fails because the observed count is exactly one greater than the hand-derived expectation.

---

### Task 6: Reuse Search, Resolution, and Endpoint Attributes

**Files:**

- Modify: `crates/agora-sandbox/src/filesystem/vfs.rs`
- Test: `crates/agora-sandbox/src/filesystem/vfs/tests.rs`

**Interfaces:**

- Produces: private `resolve_final_with_search_in`, resolved/raw endpoint-access helpers, and parent attributes returned by `require_search_in`.
- Consumes: unchanged `OverlayTransaction`, `Credentials`, `AccessRequest`, and explicit authorized VFS operation APIs.

- [ ] **Step 1: Split raw and resolved endpoint access**

Replace hidden resolution through `effective_attributes_in` with explicit helpers equivalent to:

```rust
fn require_resolved_entry_access_in(
    transaction: &OverlayTransaction<'_>,
    logical: &Path,
    request: AccessRequest,
    credentials: &Credentials,
) -> Result<()> {
    let attributes = Self::entry_attributes_in(transaction, logical)?;
    Self::require_attributes_access(&attributes, request, credentials)
}

fn require_entry_access_in(
    transaction: &OverlayTransaction<'_>,
    path: &Path,
    request: AccessRequest,
    credentials: &Credentials,
) -> Result<()> {
    let logical = transaction.resolve_final(path, false)?;
    Self::require_resolved_entry_access_in(transaction, &logical, request, credentials)
}
```

Use a private `require_attributes_access` helper for the existing `credentials.allows` plus `EACCES` mapping. Delete `effective_attributes_in`.

- [ ] **Step 2: Return reusable parent attributes from ancestor search**

Change:

```rust
fn require_search_in(...) -> Result<()>
```

to:

```rust
fn require_search_in(...) -> Result<Option<FileAttributes>>
```

The returned value is the already-checked effective attributes of the immediate parent, or `None` when the path has no parent. Preserve the existing root-to-parent resolution, batched records, and execute checks exactly.

Update parent mutation checks to request only the remaining write permission from those returned attributes; execute was already checked by search. For create/open flows, retain the parent attributes until existence and errno ordering establish that a parent write check is required.

- [ ] **Step 3: Consolidate the final-follow sequence**

Add:

```rust
fn resolve_final_with_search_in(
    transaction: &OverlayTransaction<'_>,
    path: &Path,
    allow_missing: bool,
    credentials: &Credentials,
) -> Result<(PathBuf, Option<FileAttributes>)>
```

The second tuple item is the searched parent attributes for the returned logical path. The helper performs requested-path search, one `resolve_final`, and resolved-target search only when the logical path differs.

Use it in authorized open, followed access, followed metadata, change-directory preparation, and followed chmod. Keep no-follow paths, canonicalization presentation, and raw directory-view presentation unchanged.

- [ ] **Step 4: Run the RED tests and the complete VFS suite**

Run:

```bash
cargo test -p agora-sandbox filesystem::vfs::tests::authorized_open_resolves_an_existing_endpoint_once --jobs 16
cargo test -p agora-sandbox filesystem::vfs::tests::change_directory_resolves_the_endpoint_once --jobs 16
cargo test -p agora-sandbox filesystem::vfs::tests::directory_creation_reuses_the_parent_resolution_from_search --jobs 16
cargo test -p agora-sandbox filesystem::vfs::tests --jobs 16
```

Expected: PASS with zero warnings.

- [ ] **Step 5: Run Hook and process-level filesystem regressions**

Run:

```bash
cargo test -p agora-sandbox hook::filesystem::tests --jobs 16
cargo test -p agora-sandbox --test runner filesystem --jobs 16
cargo test -p agora-sandbox --test runner permission --jobs 16
```

Expected: PASS with unchanged errno and side-effect behavior.

---

### Task 7: Update Architecture and Perform Full Validation

**Files:**

- Modify: `spec/architecture/sandbox.md`
- Review: all files listed above.

**Interfaces:**

- Consumes: completed module split and VFS deduplication.
- Produces: code/spec consistency and release-quality validation evidence.

- [ ] **Step 1: Update the architecture document**

Add a concise internal-ownership paragraph stating that:

```text
filesystem/mod.rs owns shared hook runtime and process/descriptor coordination;
operation modules own complete libc function families including lookup and registration;
directory/fts is nested under merged directory enumeration;
authorized VFS operations reuse one resolved endpoint and searched parent attributes.
```

Do not claim any external semantic change.

- [ ] **Step 2: Run formatting and structural checks**

Run:

```bash
cargo fmt --all
cargo fmt --all -- --check
git diff --check
rg -n "effective_attributes_in" crates/agora-sandbox/src
rg -n "unsafe fn sandbox_|dyld_interpose!" crates/agora-sandbox/src/hook/filesystem/mod.rs
```

Expected: formatting and diff checks pass; both structural searches return no matches.

- [ ] **Step 3: Run affected-crate tests and Clippy**

Run:

```bash
cargo test -p agora-sandbox --all-targets --jobs 16
cargo clippy -p agora-sandbox --all-targets --all-features --jobs 16 -- -D warnings
```

Expected: PASS with zero warnings and errors.

- [ ] **Step 4: Run workspace tests, Clippy, and release build**

Run sequentially:

```bash
cargo test --workspace --all-targets --jobs 16
cargo clippy --workspace --all-targets --all-features --jobs 16 -- -D warnings
cargo build --workspace --release --jobs 16
```

Expected: PASS with zero warnings and errors.

- [ ] **Step 5: Run specification check when available**

Run:

```bash
just spec-check
```

Expected: PASS. If the repository has no `spec-check` recipe, report that fact accurately and manually compare the changed code with the two design documents and `spec/architecture/sandbox.md`.

- [ ] **Step 6: Run workspace coverage once**

Run:

```bash
cargo llvm-cov --no-clean --workspace --all-targets --jobs 16 --fail-under-lines 90
```

Expected: PASS with at least 90 percent line coverage.

- [ ] **Step 7: Review the final diff and status**

Run:

```bash
git status --short
git diff --stat
git diff -- crates/agora-sandbox/src/filesystem/vfs.rs spec/architecture/sandbox.md
```

Confirm the diff contains only the approved hook split, VFS deduplication, tests, and specification updates. Leave all changes uncommitted.
