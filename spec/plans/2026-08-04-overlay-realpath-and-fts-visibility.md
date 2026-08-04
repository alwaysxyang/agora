# Overlay Realpath And FTS Visibility Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Project policy requires inline execution with the current agent and leaves changes uncommitted unless the user explicitly requests a commit.

**Goal:** Hide encrypted business filenames from both metadata and physical storage, make upper-only Overlay paths canonicalizable and visible to macOS system directory tools, and restore POSIX `mkdir -p` behavior.

**Architecture:** Metadata version 3 directly encrypts each encrypted logical leaf into the ciphertext token used as both its record key and physical filename, while plain entries remain literal and versions 1/2 migrate on startup. The existing VFS and macOS filesystem hook then gain logical canonicalization, correct directory-create ordering, and scoped synthetic `getattrlistbulk` records sourced from the merged directory view.

**Tech Stack:** Rust, macOS dyld interposition, libc FTS/getattrlistbulk/realpath APIs, Tokio integration tests, cargo-llvm-cov.

---

## File Map

- Modify `crates/agora-sandbox/tests/runner.rs`: add end-to-end regressions for upper-only `/bin/ls`, `std::fs::canonicalize`, and BSD `mkdir -p`.
- Modify `crates/agora-sandbox/src/hook/filesystem/tests.rs`: add direct hook tests for `realpath`, existing-directory `mkdir`, and scoped FTS virtual-bulk state.
- Modify `crates/agora-sandbox/src/filesystem/crypto.rs`: add authenticated encryption for logical filename bytes under a distinct domain.
- Modify `crates/agora-sandbox/src/filesystem/crypto/tests.rs`: verify filename encryption round trips and authentication failures.
- Modify `crates/agora-sandbox/src/filesystem/metadata.rs`: implement version-3 record persistence and v1/v2 migration without a persisted `backing_names` map.
- Modify `crates/agora-sandbox/src/filesystem/metadata/tests.rs`: verify encrypted and plain schemas, migration, validation, and ciphertext-name reservation.
- Modify `crates/agora-sandbox/src/filesystem/overlay.rs`: pass the optional cipher to metadata and retain opaque ciphertext names for encrypted file whiteouts.
- Modify `crates/agora-sandbox/src/filesystem/overlay/tests.rs`: verify metadata-key/physical-name equality and reopen behavior.
- Modify `crates/agora-sandbox/src/filesystem/vfs.rs`: expose visible logical canonicalization and POSIX directory-create validation.
- Modify `crates/agora-sandbox/src/hook/filesystem.rs`: interpose `realpath` and `getattrlistbulk`, scope virtual FTS enumeration, and adapt `mkdir` ordering.
- Modify `spec/architecture/sandbox.md`: document the new public runtime behavior and storage invariants.

### Task 1: Capture encrypted metadata version 3

**Files:**
- Modify: `crates/agora-sandbox/src/filesystem/crypto/tests.rs`
- Modify: `crates/agora-sandbox/src/filesystem/metadata/tests.rs`
- Modify: `crates/agora-sandbox/src/filesystem/overlay/tests.rs`
- Modify: `crates/agora-sandbox/tests/runner.rs`

- [ ] **Step 1: Add filename-crypto tests**

Derive two ciphers and assert that sealing then opening arbitrary `OsStr` bytes round-trips, two seals of the same bytes differ, a different key cannot open the payload, and truncated or modified payloads fail authentication.

- [ ] **Step 2: Add encrypted metadata schema tests**

Create an encrypted metadata store, reserve the encrypted name, store COW state and attributes, then inspect JSON. Require version 3, no `backing_names` or `name` field, no plaintext logical name anywhere in the bytes, and one `enc_` ciphertext record key that is also the physical filename. Reopen the store and require logical state, attributes, and directory enumeration to round-trip.

```rust
assert_eq!(metadata["version"], 3);
assert!(metadata.get("backing_names").is_none());
assert!(!contents.windows(b"secret.docx".len()).any(|part| part == b"secret.docx"));
assert_eq!(record_key, physical_name);
```

- [ ] **Step 3: Add plain schema and migration tests**

Require a plain store to use the literal key, losslessly escaping reserved `base64:` and `enc_` prefixes. Seed version-1 and version-2 files, including a version-2 alias, open the corresponding Overlay store, and require atomic version-3 output after renaming the old physical file to a direct encrypted-filename ciphertext.

- [ ] **Step 4: Add an end-to-end physical-name test**

Write a Unicode DOCX-style name in an encrypted sandbox, then assert outside the sandbox that the sole encrypted physical business filename equals the `.metadata` record key and decrypts to the original leaf, file contents are ciphertext, the JSON contains neither the logical filename, `name`, nor `backing_names`, and reopening still exposes the logical name.

- [ ] **Step 5: Run focused tests and record RED failures**

Run:

```bash
cargo test -p agora-sandbox filesystem::crypto::tests::filename -- --nocapture
cargo test -p agora-sandbox filesystem::metadata::tests::encrypted_metadata -- --nocapture
cargo test -p agora-sandbox filesystem::overlay::tests::encrypted_metadata -- --nocapture
cargo test -p agora-sandbox --test runner encrypted_file_leaf_names_are_not_stored_as_plaintext -- --exact --nocapture
```

Expected: new APIs/schema assertions fail because version 2 still persists readable logical keys and unrelated aliases in `backing_names`.

### Task 2: Implement encrypted metadata version 3

**Files:**
- Modify: `crates/agora-sandbox/src/filesystem/crypto.rs`
- Modify: `crates/agora-sandbox/src/filesystem/metadata.rs`
- Modify: `crates/agora-sandbox/src/filesystem/overlay.rs`
- Test: `crates/agora-sandbox/src/filesystem/crypto/tests.rs`
- Test: `crates/agora-sandbox/src/filesystem/metadata/tests.rs`
- Test: `crates/agora-sandbox/src/filesystem/overlay/tests.rs`
- Test: `crates/agora-sandbox/tests/runner.rs`

- [ ] **Step 1: Add authenticated filename encryption**

Add `FileCipher::encrypt_name(&[u8]) -> Result<String>` and `decrypt_name(&str) -> Result<Vec<u8>>`. Use a random 96-bit nonce, AES-256-GCM, a fixed versioned filename AAD distinct from file-content records, and URL-safe unpadded Base64 over nonce plus ciphertext plus tag.

- [ ] **Step 2: Add stored version-3 record types**

Keep `DirectoryMetadata` as canonical in-memory logical maps, but serialize the union of entry state, attributes, and encrypted-name reservations into records. An encrypted record is keyed directly by the validated `enc_` ciphertext of its logical leaf; a plain record uses the encoded logical key. Do not serialize `backing_names` or a separate encrypted `name` field.

- [ ] **Step 3: Load and validate version-3 records**

Inspect `version` before decoding. Keep version-1/2 readers, add a version-3 reader that decrypts encrypted record keys, rejects missing ciphers, malformed ciphertext, invalid logical leaves, duplicate logical names, and duplicate physical keys, and reconstructs the canonical logical maps used by Overlay. Plain names beginning with the reserved `enc_` prefix must be Base64-escaped so they cannot be misclassified.

- [ ] **Step 4: Migrate old metadata at startup**

Change recursive migration to rewrite both version 1 and version 2 under the VFS lock. For each existing version-2 alias, encrypt the corresponding logical key, duplicate the old physical file under that ciphertext name, atomically publish version-3 metadata keyed by the same ciphertext, and then remove the old alias. Preserve cached executable and directory records as literal non-encrypted physical names.

- [ ] **Step 5: Preserve encrypted ciphertext names through file whiteout**

Do not drop an encrypted file's ciphertext-name reservation when its state becomes whiteout. Encrypt the logical leaf before whiteouting a lower regular file so deletion does not expose its name, and ensure directory recreation clears any nonphysical encrypted-name reservation before creating a literal backing directory.

- [ ] **Step 6: Run all focused metadata tests**

Run the crypto, metadata, overlay, and runner tests from Task 1. Expected: PASS; encrypted metadata has no readable business filename, `name`, or `backing_names`, the record key equals the physical ciphertext name, and logical reopen behavior is unchanged.

### Task 3: Capture the three POSIX regressions

**Files:**
- Modify: `crates/agora-sandbox/tests/runner.rs`
- Modify: `crates/agora-sandbox/src/hook/filesystem/tests.rs`

- [ ] **Step 1: Add an upper-only system-ls regression**

Create an encrypted sandbox over a lower directory containing `lower.txt`; inside `/bin/sh`, create `upper.txt` and `upper-dir`, then require `/bin/ls -1` to include all three names. Also whiteout a lower `hidden.txt` and require it to remain absent. After the child exits, assert the host lower tree still contains only the original lower files.

```rust
let script = "printf upper > upper.txt && mkdir upper-dir && rm hidden.txt && \
              /bin/ls -1 | grep -qx upper.txt && \
              /bin/ls -1 | grep -qx upper-dir && \
              /bin/ls -1 | grep -qx lower.txt && \
              test -z \"$(/bin/ls -1 | grep '^hidden\\.txt$')\"";
```

- [ ] **Step 2: Add an upper-only canonicalize child regression**

Add a guarded libtest child that creates `canonical/child`, calls `std::fs::canonicalize("canonical/child")`, and asserts that the result equals the logical absolute path and contains no `<workdir>/fs` prefix. Run that exact child test through `SandboxCommand` in an encrypted sandbox.

```rust
let expected = std::env::current_dir().unwrap().join("canonical/child");
std::fs::create_dir_all(&expected).unwrap();
assert_eq!(std::fs::canonicalize(&expected).unwrap(), expected);
```

- [ ] **Step 3: Add a BSD mkdir-p regression**

Run `/bin/mkdir -p` on a unique absolute path whose existing prefixes are not writable by the child but whose final sandbox location is allowed by the logical parent policy. Require the child to see the final directory and assert that no lower-host directory was created.

- [ ] **Step 4: Add focused hook tests**

Cover caller-owned and libc-allocated `realpath` buffers, lower and upper-only paths, missing/whiteout errors, existing-directory `mkdir` returning `EEXIST`, and the FTS virtual-bulk scope remaining inactive outside managed traversal.

- [ ] **Step 5: Run focused tests and record RED failures**

Run:

```bash
cargo test -p agora-sandbox --test runner upper_only_entries_are_visible_to_system_ls -- --exact --nocapture
cargo test -p agora-sandbox --test runner upper_only_paths_can_be_canonicalized -- --exact --nocapture
cargo test -p agora-sandbox --test runner mkdir_p_accepts_existing_read_only_prefixes -- --exact --nocapture
cargo test -p agora-sandbox hook::filesystem::tests::realpath -- --nocapture
```

Expected: the ls test omits upper names, canonicalize returns `ENOENT`, mkdir-p stops at an existing prefix with `EACCES`, and realpath hook tests cannot compile until the new adapter is introduced.

### Task 4: Restore POSIX directory creation ordering

**Files:**
- Modify: `crates/agora-sandbox/src/filesystem/vfs.rs`
- Modify: `crates/agora-sandbox/src/hook/filesystem.rs`
- Test: `crates/agora-sandbox/src/hook/filesystem/tests.rs`
- Test: `crates/agora-sandbox/tests/runner.rs`

- [ ] **Step 1: Add a VFS directory-create validator**

Resolve ancestor search permissions, return `EEXIST` when the final visible path exists, and call `require_parent_mutation` only for a missing final component.

```rust
pub(crate) fn validate_create_directory(
    &self,
    path: &Path,
    credentials: &Credentials,
) -> Result<()> {
    self.require_search(path, credentials)?;
    if self.exists(path)? {
        return Err(std::io::Error::from_raw_os_error(libc::EEXIST).into());
    }
    self.require_parent_mutation(path, credentials)
}
```

- [ ] **Step 2: Use the validator from the hook**

Replace the unconditional parent mutation check in `FilesystemHookRuntime::create_directory` with `validate_create_directory`, leaving actual creation in `VirtualFilesystem::create_directory`.

- [ ] **Step 3: Run the focused mkdir tests**

Run the hook test and `mkdir_p_accepts_existing_read_only_prefixes`; expected: PASS with no host lower mutation.

### Task 5: Add logical realpath support

**Files:**
- Modify: `crates/agora-sandbox/src/filesystem/vfs.rs`
- Modify: `crates/agora-sandbox/src/hook/filesystem.rs`
- Test: `crates/agora-sandbox/src/hook/filesystem/tests.rs`
- Test: `crates/agora-sandbox/tests/runner.rs`

- [ ] **Step 1: Expose VFS canonicalization**

Normalize the logical input, resolve visible final symlinks through Overlay state, require the resolved entry to exist, and return the logical path rather than the private backing path.

```rust
pub(crate) fn canonicalize(&self, path: &Path) -> Result<PathBuf> {
    let logical = self.overlay.resolve_final(path, false)?;
    self.overlay.prepare_read(&logical)?;
    Ok(logical)
}
```

Resolve every path component from the root, replacing a visible symlink component with its absolute or parent-relative target and restarting normalized traversal. Cap the total followed links at 40 and return `ELOOP` beyond that limit; reject a missing or whiteouted component immediately.

- [ ] **Step 2: Implement the `realpath` adapter**

Add `RealpathFn`, resolve the input using tracked logical cwd, require logical search permission, call VFS canonicalization, convert to a NUL-terminated byte sequence, and either copy into the caller buffer or allocate `len + 1` bytes with `libc::malloc`. Return `EFAULT`, `ENOENT`, `ENAMETOOLONG`, or `ENOMEM` through the existing `fail`/`set_errno` conventions; never return `<workdir>/fs`.

```rust
type RealpathFn = unsafe extern "C" fn(
    *const libc::c_char,
    *mut libc::c_char,
) -> *mut libc::c_char;
```

- [ ] **Step 3: Register the dyld interposer and original lookup**

Add `original_realpath()` and one `dyld_interpose!` entry next to `getcwd`, then export `agora_sandbox_realpath` for direct tests.

- [ ] **Step 4: Run realpath tests**

Run direct hook tests followed by `upper_only_paths_can_be_canonicalized`; expected: both caller-buffer forms succeed, missing/whiteout paths return `ENOENT`, and the child receives its logical absolute path.

### Task 6: Route FTS through merged directory enumeration

**Files:**
- Modify: `crates/agora-sandbox/src/hook/filesystem.rs`
- Test: `crates/agora-sandbox/src/hook/filesystem/tests.rs`
- Test: `crates/agora-sandbox/tests/runner.rs`

- [ ] **Step 1: Add a nest-safe thread-local FTS virtual-bulk scope**

Use a depth counter rather than a boolean so nested `fts_read`/`fts_children` activity restores prior state on drop.

```rust
thread_local! {
    static FTS_VIRTUAL_BULK_DEPTH: Cell<u32> = const { Cell::new(0) };
}

struct FtsVirtualBulk;
```

- [ ] **Step 2: Interpose `getattrlistbulk` only for that scope**

Declare the exact Darwin signature from the SDK headers. When the virtual-bulk depth is nonzero, the requested attribute set is supported, and a filesystem runtime is active, emit native-compatible attribute records for the merged upper/lower directory cursor. Delegate unsupported requests and calls outside the scope to the original function unchanged.

- [ ] **Step 3: Present managed FTS streams logically**

Map FTS roots through the Overlay and force `FTS_NOCHDIR` for managed streams. In `sandbox_fts_children` and each `sandbox_fts_read` iteration, establish the virtual-bulk scope and call original libc without holding `FilesystemHookGuard`, then filter whiteouts, repair `FTS_NS` metadata for virtual entries, and temporarily replace backing paths with logical paths. Preserve child `fts_name` values when translating the parent root, and only resynchronize current directory for untracked native streams.

- [ ] **Step 4: Run FTS and ls regressions**

Run the virtual-bulk hook test, `upper_only_entries_are_visible_to_system_ls`, `system_ls_hides_encrypted_whiteouts`, `system_rm_removes_lower_entries_from_an_encrypted_workspace`, `system_ls_traverses_lower_directories_without_fts_errors`, and the upper-only symlink regression. Expected: upper and lower names are present, whiteouts and controls are absent, logical child names survive root translation, and recursive removal succeeds.

### Task 7: Document and validate the complete behavior

**Files:**
- Modify: `spec/architecture/sandbox.md`

- [ ] **Step 1: Update architecture behavior**

Document metadata version 3 and v1/v2 migration, direct encrypted record-key/physical-name equality without `backing_names` or an encrypted `name` field, `realpath` logical output and allocation forms, `mkdir`'s existing-entry ordering, and FTS's scoped synthetic `getattrlistbulk` merged view.

- [ ] **Step 2: Build release artifacts and run manual sandbox acceptance**

Build the release binary and dylib. In a fresh encrypted sandbox and a clone of the user's persistent workdir, create a file and directory, verify `/bin/ls`, `cat`, and `std::fs::canonicalize`, run bare `codex`, and confirm no stale-arg0/PATH-alias warnings or startup `ENOENT` remain.

- [ ] **Step 3: Run the exact Lark export from home**

Run:

```bash
cd ~
lark-cli drive +export \
  --url 'https://example.invalid/wiki/WIKI_TOKEN' \
  --file-extension docx \
  --file-name 'example.docx' \
  --output-dir . \
  --as user \
  --format json
```

Inside the sandbox, require `ls`, `test -f`, `file`, and `unzip -tq` to see a valid OOXML document. Outside, inspect metadata and confirm its opaque record key equals the physical encrypted filename and decrypts to the original leaf, there is no plaintext filename, `name`, or `backing_names` field, and no host plaintext logical file exists.

- [ ] **Step 4: Run complete project validation sequentially**

Run:

```bash
cargo fmt --all -- --check
git diff --check
cargo test --workspace --all-targets --jobs 16
cargo clippy --workspace --all-targets --jobs 16 -- -D warnings
cargo llvm-cov --no-clean --workspace --all-targets --jobs 16 --fail-under-lines 90
```

Expected: every command exits zero, Clippy emits no warnings, and workspace line coverage is at least 90%. Run `just spec-check` only if a Justfile exists; otherwise report that the project provides no spec-check command.
