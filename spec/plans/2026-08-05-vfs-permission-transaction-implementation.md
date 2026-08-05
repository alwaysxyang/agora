# VFS Permission Transaction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:executing-plans` to implement this plan task-by-task. This repository forbids subagent delegation. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace split permission validation and mutation paths with explicit VFS operations that authorize and stage against one overlay transaction while preserving existing POSIX behavior.

**Architecture:** The hook converts libc inputs and selects credentials, the VFS owns operation-specific authorization, and a scoped `OverlayTransaction` owns one `.vfs.lock` snapshot. Pure mode-bit rules move into `permissions.rs`; existing VFS, overlay, and metadata boundaries remain intact.

**Tech Stack:** Rust, macOS libc interposition, `flock`, copy-on-write overlay metadata, AES-256-GCM encrypted upper files, Cargo test/Clippy/llvm-cov.

## Global Constraints

- Preserve existing CLI, configuration, metadata version 3, encrypted filename format, audit schema, errno ordering, and POSIX mode behavior.
- Keep `/dev` as the only compile-time native-passthrough root and preserve kernel permission handling there.
- Do not add dependencies, traits, a generic authorization engine, or a catch-all filesystem-operation enum.
- Do not hold the permission transaction across native descriptor construction, open-time decryption, or ordinary descriptor I/O.
- Do not change encrypted writeback publication or lease semantics.
- Keep every production mutation reachable from the hook behind a credential-requiring authorized VFS API.
- Run Cargo jobs/tests with the repository default of 16 workers or threads.
- Maintain at least 90 percent workspace line coverage.
- Leave changes uncommitted unless the user separately requests a commit.

---

## File Map

- Create `crates/agora-sandbox/src/filesystem/permissions.rs`: pure credentials and mode-bit policy.
- Modify `crates/agora-sandbox/src/filesystem/mod.rs`: register and re-export permission value types.
- Modify `crates/agora-sandbox/src/filesystem/overlay.rs`: add the scoped transaction and locked storage primitives.
- Modify `crates/agora-sandbox/src/filesystem/overlay/tests.rs`: transaction and lock-count regression tests.
- Modify `crates/agora-sandbox/src/filesystem/vfs.rs`: explicit authorized operation APIs and shared open intent.
- Modify `crates/agora-sandbox/src/filesystem/vfs/tests.rs`: policy integration, transaction, errno, and no-side-effect tests.
- Modify `crates/agora-sandbox/src/hook/filesystem.rs`: use authorized VFS plans and collapse duplicated adapters.
- Modify `crates/agora-sandbox/src/hook/filesystem/tests.rs`: open/fopen and access/faccessat parity tests.
- Modify `crates/agora-sandbox/tests/runner.rs`: process-level logical permission regressions in plain and encrypted modes.
- Modify `spec/architecture/sandbox.md`: document the operation-level transaction boundary.

---

### Task 1: Pure Permission Policy

**Files:**
- Create: `crates/agora-sandbox/src/filesystem/permissions.rs`
- Modify: `crates/agora-sandbox/src/filesystem/mod.rs`
- Modify: `crates/agora-sandbox/src/filesystem/vfs.rs`

**Interfaces:**
- Produces: `Credentials::real()`, `Credentials::effective()`, `AccessRequest`, `AccessRequest::from_open_flags`, `AccessRequest::from_access_mode`, `Credentials::allows`, and `Credentials::can_chmod`.
- Consumes: `FileAttributes` from `filesystem::metadata`.

- [ ] **Step 1: Add failing table-driven policy tests**

Place tests beside the new module. Cover owner, primary group, supplementary group, other, UID 0, execute-only root behavior, invalid access bits, and chmod ownership. Use representative assertions such as:

```rust
fn attributes(mode: u32, uid: u32, gid: u32) -> FileAttributes {
    FileAttributes {
        mode,
        uid,
        gid,
        atime: 0,
        atime_nsec: 0,
        mtime: 0,
        mtime_nsec: 0,
    }
}

let attributes = attributes(0o100640, 501, 20);
assert!(Credentials::for_test(501, 99, &[])
    .allows(&attributes, AccessRequest::READ_WRITE));
assert!(!Credentials::for_test(502, 99, &[])
    .allows(&attributes, AccessRequest::WRITE));
assert!(Credentials::for_test(502, 99, &[20])
    .allows(&attributes, AccessRequest::READ));
assert_eq!(AccessRequest::from_access_mode(libc::R_OK | 0x100)
    .unwrap_err().raw_os_error(), Some(libc::EINVAL));
```

- [ ] **Step 2: Run the tests and observe RED**

Run:

```bash
cargo test -p agora-sandbox filesystem::permissions::tests --jobs 16
```

Expected: compilation fails because `permissions` and `AccessRequest` do not exist.

- [ ] **Step 3: Implement the pure policy types**

Use a value type rather than raw permission integers throughout VFS internals:

```rust
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct AccessRequest {
    pub(crate) read: bool,
    pub(crate) write: bool,
    pub(crate) execute: bool,
}

impl AccessRequest {
    pub(crate) const READ: Self = Self { read: true, write: false, execute: false };
    pub(crate) const WRITE: Self = Self { read: false, write: true, execute: false };
    pub(crate) const EXECUTE: Self = Self { read: false, write: false, execute: true };
    pub(crate) const READ_WRITE: Self = Self { read: true, write: true, execute: false };

    pub(crate) fn from_open_flags(flags: libc::c_int) -> Self;
    pub(crate) fn from_access_mode(mode: libc::c_int) -> std::io::Result<Self>;
}
```

Move `Credentials` and its group loading from `vfs.rs`. Preserve UID 0 behavior: read/write are allowed, while execute requires at least one execute bit. Make `can_chmod` `pub(crate)` only because VFS operation code consumes it.

Keep `Credentials::for_test` as `#[cfg(test)] pub(crate)` so VFS and hook tests can construct identities without changing process credentials. Move the existing credential matrix test out of `vfs/tests.rs` instead of duplicating it.

- [ ] **Step 4: Run policy and VFS tests GREEN**

```bash
cargo test -p agora-sandbox filesystem::permissions::tests --jobs 16
cargo test -p agora-sandbox filesystem::vfs::tests --jobs 16
```

- [ ] **Step 5: Review checkpoint without committing**

Run `git diff --check` and verify `Credentials::allows` no longer exists in `vfs.rs`.

---

### Task 2: Scoped Overlay Transaction

**Files:**
- Modify: `crates/agora-sandbox/src/filesystem/overlay.rs`
- Modify: `crates/agora-sandbox/src/filesystem/overlay/tests.rs`

**Interfaces:**
- Produces: `OverlayStore::transaction`, `OverlayTransaction<'_>`, and locked transaction methods used by VFS.
- Consumes: existing `*_locked` helpers and `MetadataStore::records`.

- [ ] **Step 1: Add failing transaction-count and snapshot tests**

Add test-only transaction-entry counting, then write a test that performs resolution, existence, attributes, and staging through one transaction and requires a delta of one:

```rust
let before = overlay.transaction_count_for_test();
overlay.transaction(|transaction| {
    assert!(transaction.visible_exists(&logical)?);
    let resolved = transaction.resolve_final(&logical, false)?;
    let _ = transaction.attributes(&resolved)?;
    Ok(())
})?;
assert_eq!(overlay.transaction_count_for_test() - before, 1);
```

Add a second test proving a transaction can read multiple ancestor records from one generation snapshot without recursively entering `with_lock`.

Add a two-store exclusion test using two `OverlayStore` instances on the same workdir. The first thread enters `transaction`, signals an `mpsc` channel, and waits on a second channel. Start the second transaction only after the first signal; assert with `recv_timeout` that it cannot complete until the first thread receives its release signal. This proves all transaction users share the file lock across instances without adding a callback to production operation code.

- [ ] **Step 2: Run the focused tests and observe RED**

```bash
cargo test -p agora-sandbox filesystem::overlay::tests::overlay_transaction --jobs 16
```

Expected: compilation fails because the transaction API and counter do not exist.

- [ ] **Step 3: Implement the transaction boundary**

Add a filesystem-internal transaction type:

```rust
pub(super) struct OverlayTransaction<'a> {
    store: &'a OverlayStore,
}

impl OverlayStore {
    pub(super) fn transaction<T>(
        &self,
        operation: impl FnOnce(&OverlayTransaction<'_>) -> Result<T>,
    ) -> Result<T> {
        self.with_lock(|| operation(&OverlayTransaction { store: self }))
    }
}
```

Expose transaction methods for `resolve_final`, `visible_exists`, `prepare_read`, `attributes`, batched `records`, `stage_file_open`, `prepare_directory`, `directory_view`, `set_attributes`, `create_directory`, `create_symlink`, `remove`, and `rename`. Each method delegates to one private locked implementation and never calls a public wrapper that acquires the lock again.

The VFS-facing query and open primitives use these exact shapes:

```rust
pub(super) fn records(
    &self,
    paths: &[&Path],
) -> Result<Vec<(Option<EntryState>, Option<FileAttributes>)>>;
pub(super) fn resolve_final(&self, path: &Path, allow_missing: bool) -> Result<PathBuf>;
pub(super) fn visible_exists(&self, path: &Path) -> Result<bool>;
pub(super) fn prepare_read(&self, path: &Path) -> Result<PathBuf>;
pub(super) fn stage_file_open(
    &self,
    path: &Path,
    create: bool,
    exclusive: bool,
) -> Result<(StagedWrite, bool, Option<File>)>;
```

Extract locked implementations from closure bodies where necessary. Keep public read/storage wrappers only for non-authorized internal consumers and tests; production mutations will be restricted after VFS migration.

Increment a `#[cfg(test)] AtomicUsize` at the start of `with_lock`. Do not expose the counter in production.

Add `#[cfg(test)] OverlayStore::has_upper_object_for_test(&Path) -> Result<bool>` using the same transaction and physical-name lookup as reconciliation. VFS tests use a thin test-only wrapper; production code must not gain a physical-path inspection API.

- [ ] **Step 4: Run overlay tests GREEN**

```bash
cargo test -p agora-sandbox filesystem::overlay::tests --jobs 16
```

- [ ] **Step 5: Review checkpoint without committing**

Run `rg -n "transaction\(|with_lock" crates/agora-sandbox/src/filesystem/overlay.rs` and verify transaction methods do not call public lock-taking wrappers.

---

### Task 3: Authorized Open and Shared Open Intent

**Files:**
- Modify: `crates/agora-sandbox/src/filesystem/vfs.rs`
- Modify: `crates/agora-sandbox/src/filesystem/vfs/tests.rs`

**Interfaces:**
- Produces: `OpenIntent`, `OpenPlan`, and `VirtualFilesystem::prepare_authorized_open`.
- Consumes: `AccessRequest`, `Credentials`, and `OverlayTransaction`.

- [ ] **Step 1: Add failing open-transaction tests**

Cover these cases in both plain and encrypted fixtures:

```rust
let intent = OpenIntent::new(libc::O_WRONLY | libc::O_TRUNC, 0o666)?;
let before = filesystem.transaction_count_for_test();
let error = filesystem
    .prepare_authorized_open(&logical, intent, &credentials_without_write)
    .unwrap_err();
assert_eq!(errno(&error), Some(libc::EACCES));
assert_eq!(filesystem.transaction_count_for_test() - before, 1);
assert_eq!(filesystem.state_for_test(&logical)?, None);
assert!(!filesystem.has_upper_object_for_test(&logical)?);
```

Also test `O_CREAT|O_EXCL` ordering, `O_NOFOLLOW`, `O_TRUNC|O_RDONLY` requiring write, creation under a non-writable parent, and successful staging from one transaction snapshot. Force native descriptor construction to fail after staging and assert that no COW state is published; for encrypted exclusive creation, also assert the filename reservation is removed, while an ordinary cached copy-up may remain non-authoritative.

- [ ] **Step 2: Run VFS open tests and observe RED**

```bash
cargo test -p agora-sandbox filesystem::vfs::tests::authorized_open --jobs 16
```

- [ ] **Step 3: Implement `OpenIntent` and operation-local authorization**

Define:

```rust
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OpenIntent {
    flags: libc::c_int,
    mode: u32,
    access: AccessRequest,
}

pub(crate) struct OpenPlan {
    logical: PathBuf,
    prepared: PreparedFile,
}
```

Provide `OpenIntent::flags()`, `OpenIntent::mode()`, and `OpenIntent::access()` for adapter/audit use. Provide `OpenPlan::logical()` and `OpenPlan::into_parts() -> (PathBuf, PreparedFile)` so the hook does not inspect fields directly. Add a `#[cfg(test)] VirtualFilesystem::transaction_count_for_test()` wrapper over the overlay counter for VFS assertions.

`OpenIntent::new` validates unsupported flags once and derives target access once, including write permission for `O_TRUNC`. `prepare_authorized_open` performs native-lower fast-path classification, final-symlink resolution, private-path rejection, ancestor checks, endpoint/parent checks, and `stage_file_open` inside one `OverlayTransaction`.

Return lower native reads as `OpenTarget::Path` without COW. Build encrypted anonymous descriptors after the transaction. Preserve the existing second-phase `commit_open` and write-lease behavior.

Implement private transaction-aware helpers:

```rust
fn require_entry_access(
    transaction: &OverlayTransaction<'_>,
    path: &Path,
    request: AccessRequest,
    credentials: &Credentials,
) -> Result<()>;

fn require_search(
    transaction: &OverlayTransaction<'_>,
    path: &Path,
    credentials: &Credentials,
) -> Result<()>;
```

Batch ancestor attributes through transaction records. Do not retain the old public `validate_open_permissions` entry point after hook migration.

- [ ] **Step 4: Run VFS tests GREEN**

```bash
cargo test -p agora-sandbox filesystem::vfs::tests --jobs 16
```

- [ ] **Step 5: Review checkpoint without committing**

Run `git diff --check`; inspect the open flow and confirm authorization failure precedes `stage_file_open`.

---

### Task 4: Authorized Mutation Operations

**Files:**
- Modify: `crates/agora-sandbox/src/filesystem/vfs.rs`
- Modify: `crates/agora-sandbox/src/filesystem/vfs/tests.rs`
- Modify: `crates/agora-sandbox/src/filesystem/overlay.rs`

**Interfaces:**
- Produces: credential-requiring `create_directory_authorized`, `create_symlink_authorized`, `remove_authorized`, `rename_authorized`, and `chmod_authorized` VFS methods.
- Consumes: private transaction-aware permission helpers and locked overlay mutations.

- [ ] **Step 1: Add failing mutation atomicity tests**

For each operation, record the transaction counter before the call and require one transaction for authorization plus mutation. Cover:

- denied mkdir leaves no marker or upper directory;
- denied symlink leaves no upper link or metadata;
- removal of a read-only entry succeeds when its parent is writable and searchable;
- denied removal leaves the existing entry and no whiteout;
- rename requires both parents and leaves source/target unchanged on denial;
- chmod requires owner or UID 0 and changes only logical attributes.

Use the one-transaction counter assertion together with Task 2's two-store exclusion test to prove another publisher cannot interleave between authorization and mutation. Do not add a production or test-only callback to VFS operation code.

- [ ] **Step 2: Run mutation tests and observe RED**

```bash
cargo test -p agora-sandbox filesystem::vfs::tests::authorized_mutation --jobs 16
```

- [ ] **Step 3: Implement explicit authorized mutations**

Change production signatures to require credentials:

```rust
pub(crate) fn create_directory_authorized(
    &self, path: &Path, mode: u32, credentials: &Credentials,
) -> Result<PathBuf>;
pub(crate) fn create_symlink_authorized(
    &self, path: &Path, target: &Path, credentials: &Credentials,
) -> Result<PathBuf>;
pub(crate) fn remove_authorized(
    &self, path: &Path, directory: bool, credentials: &Credentials,
) -> Result<()>;
pub(crate) fn rename_authorized(
    &self, from: &Path, to: &Path, credentials: &Credentials,
) -> Result<()>;
pub(crate) fn chmod_authorized(
    &self, path: &Path, mode: u32, follow_final: bool,
    credentials: &Credentials,
) -> Result<()>;
```

Move chmod search, resolution, ownership check, and attribute publication into one transaction. Preserve mkdir's `EEXIST` ordering and rename's existing validation/materialization order. Keep the old methods only until Task 6 migrates all hook call sites, then delete them.

Make overlay production mutation methods accessible only through `OverlayTransaction`; retain direct helpers only under `#[cfg(test)]` when a storage-level test needs them.

- [ ] **Step 4: Run VFS and overlay tests GREEN**

```bash
cargo test -p agora-sandbox filesystem::vfs::tests --jobs 16
cargo test -p agora-sandbox filesystem::overlay::tests --jobs 16
```

- [ ] **Step 5: Review checkpoint without committing**

Use `rg` to verify every production VFS mutation signature requires `&Credentials` and there is no public unauthorised overlay mutation path used by the hook.

---

### Task 5: Authorized Query and Directory Plans

**Files:**
- Modify: `crates/agora-sandbox/src/filesystem/vfs.rs`
- Modify: `crates/agora-sandbox/src/filesystem/vfs/tests.rs`

**Interfaces:**
- Produces: `AccessPlan`, authorized metadata preparation, canonicalization, directory view, and change-directory preparation.
- Consumes: `OverlayTransaction`, `AccessRequest`, and `Credentials`.

- [ ] **Step 1: Add failing query-path tests**

Cover logical and native plans:

```rust
assert!(matches!(
    filesystem.check_access(&untouched_lower, true, AccessRequest::READ, &credentials)?,
    AccessPlan::Native(path) if path == untouched_lower
));
filesystem.chmod_authorized(&logical, 0o000, true, &owner)?;
assert_eq!(
    errno(&filesystem.check_access(
        &logical, true, AccessRequest::READ, &owner,
    ).unwrap_err()),
    Some(libc::EACCES),
);
```

Add cases for stat on an unsearchable ancestor, logical final attributes, symlink follow/no-follow, canonicalization, directory read/search permissions, and descriptor-based chdir endpoint execute permission.

- [ ] **Step 2: Run query tests and observe RED**

```bash
cargo test -p agora-sandbox filesystem::vfs::tests::authorized_query --jobs 16
```

- [ ] **Step 3: Implement explicit VFS query plans**

Add:

```rust
pub(crate) enum AccessPlan { Allowed, Native(PathBuf) }
pub(crate) struct MetadataPlan {
    pub(crate) mapped: PathBuf,
    pub(crate) plaintext_size: Option<u64>,
    pub(crate) attributes: Option<FileAttributes>,
}
pub(crate) fn check_access(
    &self, path: &Path, follow_final: bool, request: AccessRequest,
    credentials: &Credentials,
) -> Result<AccessPlan>;
pub(crate) fn prepare_authorized_metadata(
    &self, path: &Path, follow_final: bool, credentials: &Credentials,
) -> Result<MetadataPlan>;
pub(crate) fn canonicalize_authorized(
    &self, path: &Path, credentials: &Credentials,
) -> Result<PathBuf>;
pub(crate) fn prepare_change_directory(
    &self, path: &Path, credentials: &Credentials,
) -> Result<(PathBuf, PathBuf)>;
pub(crate) fn directory_view_authorized(
    &self, path: &Path, credentials: &Credentials,
) -> Result<DirectoryView>;
pub(crate) fn require_descriptor_access(
    &self, path: &Path, request: AccessRequest, credentials: &Credentials,
) -> Result<()>;
```

Move the current hook-side combinations of `native_metadata_passthrough`, `require_search`, `prepare_metadata`, `attributes`, `canonicalize`, `prepare_directory`, and `directory_view` into explicit VFS methods. Each method owns its operation's search/endpoint ordering and returns a path/data plan that the hook can convert to C types.

Keep permission primitives private. A descriptor-based chdir check may call an explicit VFS entry-access method because an already-open descriptor does not repeat path traversal.

- [ ] **Step 4: Run VFS tests GREEN**

```bash
cargo test -p agora-sandbox filesystem::vfs::tests --jobs 16
```

- [ ] **Step 5: Review checkpoint without committing**

Verify VFS query methods use one transaction and the untouched-lower native fast path remains active.

---

### Task 6: Hook Consolidation and Old-Path Removal

**Files:**
- Modify: `crates/agora-sandbox/src/hook/filesystem.rs`
- Modify: `crates/agora-sandbox/src/hook/filesystem/tests.rs`
- Modify: `crates/agora-sandbox/src/filesystem/vfs.rs`
- Modify: `crates/agora-sandbox/src/filesystem/mod.rs`

**Interfaces:**
- Consumes: `OpenIntent`, `OpenPlan`, `AccessPlan`, authorized VFS mutation/query methods.
- Produces: one common open request path and one common access execution path.

- [ ] **Step 1: Add failing adapter-parity tests**

Use table-driven cases mapping `fopen` modes to native flags and compare the resulting intent/audit mode with equivalent `open` calls:

```rust
for (mode, flags) in [
    (b"r".as_slice(), libc::O_RDONLY),
    (b"r+".as_slice(), libc::O_RDWR),
    (b"w".as_slice(), libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC),
    (b"a+".as_slice(), libc::O_RDWR | libc::O_CREAT | libc::O_APPEND),
] {
    assert_eq!(intent_from_fopen_mode(mode)?, OpenIntent::new(flags, 0o666)?);
}
```

Add access/faccessat parity cases for real credentials, `AT_EACCESS`, no-follow, invalid mode bits, logical denial, and native lower delegation.

- [ ] **Step 2: Run hook tests and observe RED**

```bash
cargo test -p agora-sandbox hook::filesystem::tests::open_intent --jobs 16
cargo test -p agora-sandbox hook::filesystem::tests::access_plan --jobs 16
```

- [ ] **Step 3: Route Hook operations through authorized VFS APIs**

Create one private `prepare_open_request` that accepts `OpenIntent`; make both raw open flags and parsed fopen modes call it. Preserve audit fields by deriving them from the intent rather than recomputing them.

Create one private access executor that takes selected credentials and follow mode, calls `check_access`, returns success for `AccessPlan::Allowed`, and calls original libc for `AccessPlan::Native`.

Update metadata/stat, canonicalization, chdir, directory enumeration, mkdir, symlink, remove, rename, and chmod adapters to use the corresponding authorized VFS operation. Keep native `/dev` routing before VFS entry.

Delete `FilesystemHookRuntime::resolve_final_path` if no caller remains. Delete VFS `validate_open_permissions`, `validate_create_directory`, public `require_search`, public `require_access`, and public `require_parent_mutation`; retain only private transaction-aware primitives.

- [ ] **Step 4: Run all library and runner tests GREEN**

```bash
cargo test -p agora-sandbox --lib --jobs 16
cargo test -p agora-sandbox --test runner --jobs 16
```

- [ ] **Step 5: Prove old orchestration is gone**

```bash
! rg -n "validate_open_permissions|validate_create_directory|\.require_search\(|\.require_parent_mutation\(" \
  crates/agora-sandbox/src/hook crates/agora-sandbox/src/filesystem/vfs.rs
```

Review remaining `require_access` occurrences: each must be a private VFS helper or an explicit descriptor-entry operation, never hook-side mutation orchestration.

---

### Task 7: Process Regressions, Specs, and Full Validation

**Files:**
- Modify: `crates/agora-sandbox/tests/runner.rs`
- Modify: `spec/architecture/sandbox.md`
- Modify: `spec/plans/2026-08-05-vfs-permission-transaction-design.md` only if implementation details require a clarified statement.

**Interfaces:**
- Consumes: completed authorized VFS architecture.
- Produces: process-level evidence and consistent project specification.

- [ ] **Step 1: Add process-level permission regressions**

Run the same scenarios through plain and encrypted sandbox configurations:

1. Host lower file mode `0444`; sandbox write returns `EACCES`; no authoritative upper entry exists.
2. Owner performs logical `chmod 0644`, then writes; sandbox sees upper contents while host mode and contents remain unchanged.
3. A read-only file in a writable searchable directory can be removed.
4. A directory with logical mode `0000` denies traversal, open, stat-family logical handling, and child mutation.
5. `/dev/null` remains native, writable, unaudited, and absent from upper metadata.

- [ ] **Step 2: Run runner characterization regressions GREEN**

These process tests preserve existing external behavior and may already pass before the refactor. RED evidence comes from the new API, transaction-count, and structural tests in Tasks 1 through 6. Run:

```bash
cargo test -p agora-sandbox --test runner permission --jobs 16
```

- [ ] **Step 3: Update architecture specification**

Update `spec/architecture/sandbox.md` to state:

- Hook selects credentials and adapts libc only.
- VFS authorization and overlay staging share one `.vfs.lock` snapshot.
- Immediate mutations authorize and publish in one transaction.
- Open retains staged two-phase publication and does not hold the permission transaction across descriptor construction or open-time decryption.
- Permission failures publish no COW state; an ordinary failed-open cache may remain non-authoritative.

- [ ] **Step 4: Run focused formatting and validation**

```bash
cargo fmt --all -- --check
git diff --check
cargo test -p agora-sandbox --all-targets --jobs 16
```

- [ ] **Step 5: Run workspace validation**

Run sequentially, never concurrently against the same target directory:

```bash
cargo test --workspace --all-targets --jobs 16
cargo clippy --workspace --all-targets --all-features --jobs 16 -- -D warnings
cargo build --release --workspace --jobs 16
cargo llvm-cov --no-clean --workspace --all-targets --jobs 16 --fail-under-lines 90
```

Expected: every command exits zero, Clippy reports no warnings, and total line coverage is at least 90 percent.

- [ ] **Step 6: Run architecture and regression acceptance checks**

```bash
! rg -n "validate_open_permissions|validate_create_directory" crates/agora-sandbox/src
! rg -n -i "seatbelt|sandbox_init|native_sandbox" . --glob '!target/**' --glob '!.git/**'
```

Run a fresh encrypted Codex smoke test and verify the prior Bash, arg0, PATH-alias, MCP startup, rm/ls, and Lark export acceptance path remains unchanged. Do not persist private document URLs or titles in repository fixtures, specs, audit files, or command logs.

- [ ] **Step 7: Final review checkpoint without committing**

Inspect `git status --short`, `git diff --stat`, and the complete diff. Confirm no unrelated files changed and report the work as uncommitted.
