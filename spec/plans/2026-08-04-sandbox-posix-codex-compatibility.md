# Sandbox POSIX And Codex Compatibility Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. This repository forbids subagent delegation and requires changes to remain uncommitted unless the user explicitly requests a commit.

**Goal:** Restore POSIX-compatible deletion and symlink behavior so macOS system tools and Codex observe the same filesystem view inside Agora as outside, while removing the debug-build checksum bottleneck.

**Architecture:** Keep overlay policy in `filesystem`, libc adaptation in `hook`, and executable preparation in `execution`. Encrypted unlink detaches the namespace from open anonymous snapshots and suppresses stale writeback; FTS adapters hide whiteouted lower entries from macOS system traversal; symlink creation maps physical cached-executable targets back to logical paths.

**Tech Stack:** Rust 2024, macOS libc/DYLD interposition, Tokio integration tests, Cargo profiles, `cargo llvm-cov`.

---

### Task 1: POSIX unlink for encrypted writable snapshots

**Files:**
- Modify: `crates/agora-sandbox/src/filesystem/vfs/tests.rs`
- Modify: `crates/agora-sandbox/tests/runner.rs`
- Modify: `crates/agora-sandbox/src/filesystem/vfs.rs`
- Modify: `crates/agora-sandbox/src/filesystem/overlay.rs`

- [ ] **Step 1: Write failing VFS and runner tests**

Add a VFS test that opens an encrypted file for writing, unlinks it from a second VFS, commits the old descriptor, and verifies the path stays absent. Add a runner test that executes `/bin/rm -rf` against a lower directory tree and verifies `test ! -e` succeeds inside the encrypted view.

```rust
second_filesystem.remove(logical, false).unwrap();
first_filesystem.commit_writeback(writeback.as_ref().unwrap()).unwrap();
assert!(!second_filesystem.exists(logical).unwrap());
```

- [ ] **Step 2: Verify the tests fail for the observed reasons**

Run:

```bash
cargo test -p agora-sandbox encrypted_unlink_detaches_live_writable_snapshot --jobs 16 -- --exact
cargo test -p agora-sandbox --test runner system_rm_rf_removes_a_lower_tree --jobs 16 -- --exact
```

Expected: the unit test reports `EBUSY`; the runner reports `Directory not empty`.

- [ ] **Step 3: Implement detached writeback**

Store the logical path in `Writeback`, remove the exclusive namespace-lease check from unlink, remove obsolete lease sidecars with the namespace entry, and publish encrypted bytes only while metadata still maps that logical path to the same backing destination.

```rust
pub(crate) struct Writeback {
    logical: PathBuf,
    destination: PathBuf,
    plaintext: Mutex<File>,
    _lease: File,
}

pub(crate) fn publish_encrypted(
    &self,
    logical: &Path,
    plaintext: &mut File,
    destination: &Path,
) -> Result<()> {
    self.with_lock(|| {
        let current = self.destination(logical)?;
        if !matches!(self.metadata.state(logical)?, Some(EntryState::Cow))
            || current != destination
        {
            return Ok(());
        }
        self.cipher.as_ref().context("encrypted writeback requires a filesystem cipher")?
            .encrypt(plaintext, destination)
    })
}
```

- [ ] **Step 4: Re-run both focused tests and the VFS test module**

```bash
cargo test -p agora-sandbox filesystem::vfs::tests --jobs 16
cargo test -p agora-sandbox --test runner system_rm_rf_removes_a_lower_tree --jobs 16 -- --exact
```

Expected: PASS with no warnings.

### Task 2: Symlink creation for Codex PATH aliases

**Files:**
- Modify: `crates/agora-sandbox/src/filesystem/overlay/tests.rs`
- Modify: `crates/agora-sandbox/src/hook/filesystem/tests.rs`
- Modify: `crates/agora-sandbox/tests/runner.rs`
- Modify: `crates/agora-sandbox/src/filesystem/overlay.rs`
- Modify: `crates/agora-sandbox/src/filesystem/vfs.rs`
- Modify: `crates/agora-sandbox/src/hook/filesystem.rs`

- [ ] **Step 1: Write failing symlink tests**

Cover relative and absolute targets, directly encrypted physical leaf names, `readlink`, duplicate creation (`EEXIST`), and execution through a newly created alias. Include the Codex pattern where the requested target is a physical prepared executable inside `<workdir>/fs` and must be stored as its logical host path.

```rust
assert_eq!(filesystem.create_symlink(Path::new("/bin/sh"), &link).unwrap(), link_backing);
assert_eq!(filesystem.read_link(&link).unwrap(), Path::new("/bin/sh"));
```

- [ ] **Step 2: Verify `ENOTSUP` failures**

```bash
cargo test -p agora-sandbox hook::filesystem::tests::symlink_creation_uses_the_overlay --jobs 16 -- --exact
cargo test -p agora-sandbox --test runner created_symlink_alias_can_execute --jobs 16 -- --exact
```

Expected: FAIL because `symlink`/`symlinkat` currently return `ENOTSUP`.

- [ ] **Step 3: Implement overlay-backed symlink creation**

Add `OverlayStore::create_symlink`, expose it through `VirtualFilesystem`, replace the unsupported hooks, enforce parent mutation permission, and translate an absolute internal target with `logical_path` before persisting it.

```rust
fn create_symlink(&self, target: &Path, link: &Path) -> Result<()> {
    let link = self.normalize(link)?;
    self.with_lock(|| {
        if self.visible_exists_locked(&link)? {
            return Err(std::io::Error::from_raw_os_error(libc::EEXIST).into());
        }
        self.ensure_parent_locked(&link)?;
        let destination = self.file_destination(&link, true)?;
        std::os::unix::fs::symlink(target, &destination)?;
        let attributes = FileAttributes::from_metadata(&destination.symlink_metadata()?);
        self.metadata.set_with_attributes(&link, EntryState::Cow, Some(attributes))
    })
}
```

- [ ] **Step 4: Re-run focused symlink tests**

Run the two commands from Step 2 and the filesystem hook test module. Expected: PASS.

### Task 3: macOS FTS whiteout filtering for `ls`

**Files:**
- Modify: `crates/agora-sandbox/tests/runner.rs`
- Modify: `crates/agora-sandbox/src/hook/filesystem.rs`

- [ ] **Step 1: Write a failing system-`ls` regression test**

Create a lower file, unlink it inside the sandbox, and assert `/bin/ls -A` does not emit its name.

```rust
let script = "rm -f removed; case \"$(/bin/ls -A)\" in *removed*) exit 1;; esac";
```

- [ ] **Step 2: Verify the test fails because FTS exposes the lower entry**

```bash
cargo test -p agora-sandbox --test runner system_ls_hides_whiteouted_lower_entries --jobs 16 -- --exact
```

Expected: FAIL with exit status 1.

- [ ] **Step 3: Interpose `fts_children` and `fts_read`**

Define the Darwin `FTSENT` prefix layout, resolve the original functions with `RTLD_NEXT`, filter entries for which the logical VFS path no longer exists, and set `FTS_SKIP` for hidden preorder directories.

```rust
while !entry.is_null() {
    let next = unsafe { (*entry).link };
    if runtime.fts_entry_visible(entry)? {
        previous = entry;
    } else if previous.is_null() {
        head = next;
    } else {
        unsafe { (*previous).link = next };
    }
    entry = next;
}
```

- [ ] **Step 4: Re-run the focused `ls` and recursive `rm` tests**

Expected: both PASS without exposing control files.

### Task 4: Pass through writable special files

**Files:**
- Modify: `crates/agora-sandbox/src/filesystem/vfs/tests.rs`
- Modify: `crates/agora-sandbox/src/filesystem/vfs.rs`
- Modify: `crates/agora-sandbox/src/filesystem/overlay.rs`

- [ ] **Step 1: Write a failing `/dev/null` preparation test**

```rust
let prepared = filesystem.prepare_open(Path::new("/dev/null"), libc::O_WRONLY, 0).unwrap();
assert!(matches!(prepared.target(), OpenTarget::Path(path) if path == Path::new("/dev/null")));
assert!(prepared.writeback().is_none());
```

- [ ] **Step 2: Verify the test detects staged COW state**

Run the exact test and confirm a subsequent `/dev/null` open fails or the overlay state is incorrectly `Cow`.

- [ ] **Step 3: Return external non-regular nodes as unstaged passthrough targets**

Before staging a write, inspect the visible lower node. For character devices, FIFOs, sockets, and directories outside the backing root, return a lower `OpenTarget::Path` with no staged metadata.

- [ ] **Step 4: Re-run VFS and shell startup tests**

Expected: `/dev/null` remains usable across repeated writes and no COW metadata is created.

### Task 5: Remove debug checksum bottleneck

**Files:**
- Modify: `Cargo.toml`

- [ ] **Step 1: Record the existing repeated-start benchmark**

Run `codex --version` twice in one persistent encrypted workdir and retain the baseline: approximately 6 seconds on the second debug run, with sampling dominated by `md5::compress::soft`.

- [ ] **Step 2: Optimize only the MD5 dependency in dev builds**

```toml
[profile.dev.package.md-5]
opt-level = 3
```

- [ ] **Step 3: Rebuild and repeat the benchmark**

Expected: repeated startup no longer spends multiple seconds in the checksum loop; persistent checksum validation remains enabled.

### Task 6: Specification and full validation

**Files:**
- Modify: `spec/architecture/sandbox.md`
- Modify: `spec/plans/2026-08-04-sandbox-posix-codex-compatibility.md`

- [ ] **Step 1: Update documented behavior**

Document POSIX unlink detachment, stale encrypted writeback suppression, symlink creation, FTS whiteout filtering, and writable lower special-node passthrough. Remove statements that symlink creation always returns `ENOTSUP` or unlink always returns `EBUSY` for a writable snapshot.

- [ ] **Step 2: Run formatting and focused validation**

```bash
cargo fmt --all -- --check
cargo test -p agora-sandbox --jobs 16
cargo clippy -p agora-sandbox --all-targets --jobs 16 -- -D warnings
```

- [ ] **Step 3: Run workspace validation and coverage sequentially**

```bash
cargo test --workspace --all-targets --jobs 16
cargo clippy --workspace --all-targets --jobs 16 -- -D warnings
cargo llvm-cov --no-clean --workspace --all-targets --jobs 16 --fail-under-lines 90
just spec-check
```

Expected: every command exits 0 with zero warnings; line coverage is at least 90%.

- [ ] **Step 4: Run the exact Codex/lark-cli acceptance prompt**

Start Codex inside an encrypted Agora workdir and submit exactly:

```text
帮我用lark-cli 看下https://example.invalid/wiki/WIKI_TOKEN 这个文档，给下lark-cli的命令行，然后下载到~/目录
```

Verify there are no arg0/PATH alias warnings, no `/bin/bash` `ENOENT`, the lark-cli command exits successfully, and the expected exported file exists in the sandbox-visible home directory while the host home remains isolated.
