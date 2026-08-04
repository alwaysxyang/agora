# `/dev`, Keychain, And Lark Compatibility Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `/dev` a compile-time transparent filesystem allowlist, deny host Keychain access for the complete sandbox process tree, and verify the supplied Codex/Lark export prompt end to end.

**Architecture:** The filesystem hook owns a component-safe static passthrough classifier and skips VFS, descriptor tracking, and audit for matching device paths. The runner installs a minimal fail-closed macOS Seatbelt profile immediately before the root child `exec`; descendants inherit denial of Keychain Mach services while Lark uses its existing file-backed master key through encrypted COW.

**Tech Stack:** Rust 2024, macOS libc/DYLD interposition, macOS Seatbelt `sandbox_init`, Tokio process management, Cargo tests, `cargo llvm-cov`.

**Execution constraint:** `AGENTS.md` forbids subagents, and the current workspace contains active uncommitted compatibility work. Execute inline in the current `dev` workspace, preserve all existing changes, and leave the result uncommitted unless the user explicitly requests a commit.

---

### Task 1: Component-Safe Native Filesystem Allowlist

**Files:**
- Modify: `crates/agora-sandbox/src/hook/filesystem.rs`
- Modify: `crates/agora-sandbox/src/hook/filesystem/tests.rs`

- [ ] **Step 1: Write classifier tests that fail before the allowlist exists**

Add tests which call the intended private API and require normalized, component-safe matching:

```rust
#[test]
fn native_passthrough_roots_are_normalized_and_component_safe() {
    let fixture = Fixture::new();
    assert_eq!(
        fixture
            .runtime
            .native_passthrough_path(Path::new("/dev/./null"))
            .unwrap(),
        Some(PathBuf::from("/dev/null"))
    );
    assert_eq!(
        fixture
            .runtime
            .native_passthrough_path(Path::new("/dev/../private/file"))
            .unwrap(),
        None
    );
    assert_eq!(
        fixture
            .runtime
            .native_passthrough_path(Path::new("/developer"))
            .unwrap(),
        None
    );
}
```

- [ ] **Step 2: Run the exact classifier test and confirm RED**

Run:

```bash
cargo test -p agora-sandbox hook::filesystem::tests::native_passthrough_roots_are_normalized_and_component_safe -- --exact --nocapture
```

Expected: compilation fails because `native_passthrough_path` does not exist.

- [ ] **Step 3: Implement the compile-time path list and normalizer**

Add one central constant and a helper on `FilesystemHookRuntime`:

```rust
const NATIVE_PASSTHROUGH_ROOTS: &[&str] = &["/dev"];

fn normalize_absolute(path: &Path) -> Result<PathBuf> {
    if !path.is_absolute() {
        bail!("filesystem path is not absolute: {}", path.display());
    }
    let mut normalized = PathBuf::from("/");
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Normal(value) => normalized.push(value),
            Component::Prefix(_) => bail!("unsupported filesystem path: {}", path.display()),
        }
    }
    Ok(normalized)
}

fn native_passthrough_path(&self, path: &Path) -> Result<Option<PathBuf>> {
    let normalized = normalize_absolute(path)?;
    Ok(NATIVE_PASSTHROUGH_ROOTS
        .iter()
        .map(Path::new)
        .any(|root| normalized.starts_with(root))
        .then_some(normalized))
}
```

Use `Path::starts_with` only after normalization so matching is component-based and traversal-safe.

- [ ] **Step 4: Run the classifier test and confirm GREEN**

Run the Step 2 command. Expected: one test passes with no warnings.

### Task 2: Native `/dev` Opens Without Audit Or Descriptor Tracking

**Files:**
- Modify: `crates/agora-sandbox/src/hook/filesystem.rs`
- Modify: `crates/agora-sandbox/src/hook/filesystem/tests.rs`
- Modify: `crates/agora-sandbox/tests/runner.rs`

- [ ] **Step 1: Write failing hook tests for `open`, `openat`, and `fopen`**

Create an `AuditClient` whose loopback listener has already been dropped. Install it on a fixture,
then require write opens of `/dev/null` to succeed. A mistakenly audited operation will fail closed,
so the tests prove absence of both open and close publication. Also assert the returned descriptors
are not registered:

```rust
#[test]
fn allowlisted_device_opens_bypass_audit_and_tracking() {
    let mut fixture = Fixture::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    fixture.runtime.audit = Some(AuditClient::new(address, "audit-token"));

    with_test_runtime(&fixture.runtime, || unsafe {
        let descriptor = sandbox_open_with_mode(c"/dev/null".as_ptr(), libc::O_WRONLY, 0);
        assert!(descriptor >= 0);
        assert!(fixture.runtime.tracked_open(descriptor).is_none());
        assert_eq!(libc::write(descriptor, b"x".as_ptr().cast(), 1), 1);
        assert_eq!(sandbox_close(descriptor), 0);

        let directory = libc::open(c"/dev".as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY);
        assert!(directory >= 0);
        let relative = sandbox_openat_with_mode(directory, c"null".as_ptr(), libc::O_WRONLY, 0);
        assert!(relative >= 0);
        assert!(fixture.runtime.tracked_open(relative).is_none());
        assert_eq!(sandbox_close(relative), 0);
        assert_eq!(libc::close(directory), 0);

        let stream = sandbox_fopen(c"/dev/null".as_ptr(), c"w".as_ptr());
        assert!(!stream.is_null());
        assert!(fixture.runtime.tracked_open(libc::fileno(stream)).is_none());
        assert_eq!(sandbox_fclose(stream), 0);
    });
}
```

- [ ] **Step 2: Run the hook test and confirm RED**

Run:

```bash
cargo test -p agora-sandbox hook::filesystem::tests::allowlisted_device_opens_bypass_audit_and_tracking -- --exact --nocapture
```

Expected: `/dev/null` open fails because the current code tries to publish to the unavailable audit controller.

- [ ] **Step 3: Route allowlisted opens directly to native libc**

Extend `OpenRequest` with an accessor:

```rust
fn is_native_passthrough(&self) -> bool {
    self.native_passthrough
}
```

In `prepare_open` and `prepare_fopen`, check `native_passthrough_path` before VFS resolution and
return the normalized native path for every access mode. In the `open`, `openat`, and `fopen`
interposers, branch before audit publication and call the original libc function directly. Do not
call `map_open`, `commit_open`, or `register` on this branch. Apply the same branch to
`posix_spawn_file_actions_addopen`, including write-mode device opens.

- [ ] **Step 4: Run the hook test and existing audit tests**

Run:

```bash
cargo test -p agora-sandbox hook::filesystem::tests::allowlisted_device_opens_bypass_audit_and_tracking -- --exact --nocapture
cargo test -p agora-sandbox hook::filesystem::tests::filesystem_interposers_publish_open_and_close_audit_events -- --exact --nocapture
cargo test -p agora-sandbox hook::filesystem::tests::filesystem_interposers_fail_closed_when_audit_rejects_an_operation -- --exact --nocapture
```

Expected: all commands pass; ordinary paths remain audited and fail closed.

- [ ] **Step 5: Write and run an end-to-end no-`/dev`-audit regression test**

Add a runner test with an `Arc<Mutex<Vec<FileEvent>>>` callback. Run `/bin/sh -c
"printf device-output >/dev/null"`, assert success, and assert no collected file event path equals
`/dev` or starts with `/dev/`. Run:

```bash
cargo test -p agora-sandbox --test runner device_paths_are_native_and_absent_from_filesystem_audit -- --exact --nocapture
```

Expected before implementation: FAIL with `/dev/null` events. Expected after implementation: PASS.

### Task 3: Native macOS Keychain Service Isolation

**Files:**
- Create: `crates/agora-sandbox/src/runner/native_sandbox.rs`
- Modify: `crates/agora-sandbox/src/runner/mod.rs`
- Modify: `crates/agora-sandbox/tests/runner.rs`

- [ ] **Step 1: Write a child-side Keychain Mach lookup probe**

In the macOS integration test, declare `bootstrap_port` and `bootstrap_look_up` from libSystem. Add
an exact child test selected by an environment marker; it exits successfully only when lookup of
`com.apple.SecurityServer` is denied. Add a parent runner test that executes that exact child test
inside `Sandbox`.

```rust
#[cfg(target_os = "macos")]
unsafe extern "C" {
    static bootstrap_port: libc::mach_port_t;
    fn bootstrap_look_up(
        bootstrap_port: libc::mach_port_t,
        service_name: *const libc::c_char,
        service_port: *mut libc::mach_port_t,
    ) -> libc::kern_return_t;
}

#[test]
fn keychain_lookup_probe_child_process() {
    if std::env::var_os("AGORA_SANDBOX_TEST_KEYCHAIN_LOOKUP").is_none() {
        return;
    }
    let mut port = 0;
    let result = unsafe {
        bootstrap_look_up(
            bootstrap_port,
            c"com.apple.SecurityServer".as_ptr(),
            &mut port,
        )
    };
    assert_ne!(result, libc::KERN_SUCCESS);
}
```

- [ ] **Step 2: Run the parent test and confirm RED**

Run:

```bash
cargo test -p agora-sandbox --test runner sandbox_denies_host_keychain_mach_lookup -- --exact --nocapture
```

Expected: FAIL because the child can currently resolve the host Keychain service.

- [ ] **Step 3: Implement the fail-closed Seatbelt profile**

Create a focused module with the static profile and FFI:

```rust
const KEYCHAIN_PROFILE: &CStr = c"(version 1)\
(allow default)\
(deny mach-lookup (global-name \"com.apple.SecurityServer\"))\
(deny mach-lookup (global-name \"com.apple.securityd\"))\
(deny mach-lookup (global-name \"com.apple.securityd.xpc\"))\
(deny mach-lookup (global-name \"com.apple.securityd.general\"))\
(deny mach-lookup (global-name \"com.apple.securityd.systemkeychain\"))";

#[link(name = "sandbox")]
unsafe extern "C" {
    fn sandbox_init(
        profile: *const libc::c_char,
        flags: u64,
        error_buffer: *mut *mut libc::c_char,
    ) -> libc::c_int;
    fn sandbox_free_error(error_buffer: *mut libc::c_char);
}
```

Expose `configure(&mut tokio::process::Command)`, register a `pre_exec` closure, call
`sandbox_init(KEYCHAIN_PROFILE.as_ptr(), 0, &mut error_buffer)`, free any returned error buffer, and
return `EPERM` on failure. Call `native_sandbox::configure(&mut child)` after environment setup and
before `spawn`. Do not fall back to an unsandboxed child.

- [ ] **Step 4: Run the Keychain test and ordinary runner smoke tests**

Run:

```bash
cargo test -p agora-sandbox --test runner sandbox_denies_host_keychain_mach_lookup -- --exact --nocapture
cargo test -p agora-sandbox --test runner runner_generates_default_tls_ca_in_the_configured_workdir -- --exact --nocapture
cargo test -p agora-sandbox --test runner system_curl_completes_the_transparent_tls_chain -- --exact --nocapture
```

Expected: the Keychain lookup is denied and ordinary process/TLS behavior remains green.

### Task 4: Specification Consistency And Focused Validation

**Files:**
- Modify: `spec/architecture/sandbox.md`
- Modify: `spec/architecture/sandbox-network.md`
- Verify: `spec/plans/2026-08-04-native-filesystem-passthrough-allowlist-design.md`
- Verify: `spec/plans/2026-08-04-macos-keychain-isolation-design.md`

- [ ] **Step 1: Update architecture behavior**

Document that `/dev` is a compile-time native passthrough root excluded from filesystem audit and
descriptor tracking. Document that the runner installs a narrow native Seatbelt layer denying host
Keychain Mach services, while the remaining hook/network limitations and unavailable strict egress
mode are unchanged.

- [ ] **Step 2: Format and run focused crate validation**

Run:

```bash
cargo fmt --all -- --check
cargo test -p agora-sandbox --lib --jobs 16
cargo test -p agora-sandbox --test runner --jobs 16
cargo clippy -p agora-sandbox --all-targets -- -D warnings
```

Expected: zero warnings and zero failures.

- [ ] **Step 3: Run the project spec check if available**

Run `just spec-check` only if a `justfile`/`Justfile` target exists. This repository currently has no
Justfile, so record the check as unavailable rather than inventing a replacement.

### Task 5: Workspace Coverage And Exact Codex/Lark Acceptance

**Files:**
- No production files; validation only.

- [ ] **Step 1: Run workspace tests and coverage once**

Run sequentially:

```bash
cargo test --workspace --all-targets --jobs 16
cargo clippy --workspace --all-targets -- -D warnings
cargo llvm-cov --no-clean --workspace --all-targets --jobs 16 --fail-under-lines 90
```

Expected: zero warnings/errors and at least 90% workspace line coverage.

- [ ] **Step 2: Build the release sandbox artifacts**

Run:

```bash
cargo build --release -p agora-sandbox --jobs 16
```

Expected: `target/release/agora-sandbox` and `target/release/libagora_sandbox.dylib` build cleanly.

- [ ] **Step 3: Record non-secret Lark credential metadata**

Without reading file contents or invoking any `lark-cli auth` command, record filenames, inode,
size, and modification timestamps under the Lark configuration directory. Confirm the supported
`master.key.file` backend exists. Abort acceptance if it is absent; do not run
`keychain-downgrade` automatically.

- [ ] **Step 4: Verify Codex MCP startup in a fresh sandbox workdir**

Start Codex through the release sandbox with the user's existing Codex home and a fresh Agora
workdir. Wait for both `node_repl` and `codex_apps` to settle. Assert the TUI does not render
`MCP startup interrupted` and the audit stream contains no `/dev` filesystem records.

- [ ] **Step 5: Execute the exact user prompt and verify the export**

Submit exactly:

```text
帮我用lark-cli 看下https://example.invalid/wiki/WIKI_TOKEN 这个文档，给下lark-cli的命令行，然后下载到~/目录
```

Require Codex to complete without `/bin/bash` or MCP startup errors. In the same persistent sandbox
workdir, verify the exported `.docx` is immediately visible from the logical home and its logical
name is absent from encrypted physical metadata/backing names.

- [ ] **Step 6: Verify host isolation after acceptance**

Compare the non-secret Lark credential metadata from Step 3. Credential identities and modification
times must be unchanged, the exported document must not appear in the host home, and the sandbox
audit must show no `/dev` records. Report any difference as an incomplete/failed acceptance rather
than claiming success.
