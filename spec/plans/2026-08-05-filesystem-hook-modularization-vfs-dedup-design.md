# Filesystem Hook Modularization and VFS Deduplication Design

## Status

Implemented and validated on 2026-08-05.

## Goal

Reduce filesystem-hook structural complexity and remove demonstrable duplicate VFS path work while preserving all existing observable behavior.

This change has two parts:

1. Split the macOS filesystem hook by libc operation family without changing its ABI, runtime state, or operation flow.
2. Reuse final-path resolution and endpoint attributes inside authorized VFS operations instead of resolving an already-resolved entry again.

## Non-goals

- Change supported or unsupported libc operations.
- Change errno values or validation ordering.
- Change audit events, configuration, native-passthrough roots, metadata format, encrypted filenames, COW behavior, or reconciliation rules.
- Change the existing overlay transaction or encrypted writeback boundaries.
- Add a generic filesystem-operation enum, authorization trait, policy engine, normalized-path type, macro-generated hook framework, or new dependency.
- Put one libc function in each source file.
- Reorganize the existing hook tests beyond imports required by the production module split.

## Current Problems

### Hook structure

`hook/filesystem.rs` currently combines more than 5,000 lines of unrelated concerns:

- process initialization, recursion protection, and fork synchronization;
- hook runtime and descriptor state;
- path translation, native passthrough, and audit adaptation;
- file opening and writeback;
- metadata and permission operations;
- namespace mutations;
- merged directory enumeration;
- macOS FTS traversal and `getattrlistbulk` synthesis;
- original-function lookup and dyld interpose registration for every operation.

Handlers, their `original_*` lookup, and their `dyld_interpose!` registration are separated by thousands of lines. This increases navigation cost and makes unrelated operation families appear coupled even when they only share the hook runtime.

### VFS path work

Authorized VFS operations repeat a common sequence:

1. check search permission on the requested path;
2. resolve the final symlink;
3. check search permission on a different resolved target;
4. inspect endpoint attributes.

Some callers already resolve the endpoint and then call `require_entry_access_in`, which calls `effective_attributes_in` and resolves the same endpoint again. This occurs in paths such as authorized open and change-directory preparation. The existing approved VFS design requires each operation to resolve each logical input once, so this duplicate work is both unnecessary and contrary to the intended transaction design.

## Chosen Architecture

### Source layout

```text
crates/agora-sandbox/src/hook/
├── filesystem.rs
├── filesystem_shim.c
└── filesystem/
    ├── open.rs
    ├── descriptor.rs
    ├── metadata.rs
    ├── namespace.rs
    ├── unsupported.rs
    ├── directory/
    │   ├── mod.rs
    │   └── fts.rs
    └── tests.rs
```

`filesystem_shim.c` and the existing test file retain their current locations.

### Parent facade and runtime

`hook/filesystem.rs` remains the parent module and owns only state or behavior shared across multiple operation families:

- `FilesystemHookRuntime` and global runtime initialization;
- recursion guard and fork barrier;
- logical-path and descriptor-path translation;
- compile-time native-passthrough classification;
- audit publication;
- shared descriptor registries and open-file identity;
- open-request preparation shared by ordinary open handlers and descriptor-based truncate;
- shared errno, panic, lock, and native-result helpers;
- current-directory reporting and pre-exec/process-exit flush entry points;
- child-module declarations and the minimal private imports needed by tests.

It does not contain concrete libc hook handlers or interpose registrations after the split.

### Operation modules

#### `open.rs`

Owns:

- `open`, `openat`, and `creat`;
- `fopen` and `freopen`;
- `posix_spawn_file_actions_addopen`;
- handler-specific native open/fopen invocation;
- open/openat C shim declarations;
- original-function lookup and interpose registration for this family.

#### `descriptor.rs`

Owns:

- `close`, `fclose`, and `fsync`;
- `dup`, `dup2`, and `fcntl`;
- `truncate` and `ftruncate`;
- descriptor mutation, synchronization, writeback, duplication, and close lifecycle;
- the fcntl C shim declaration;
- original-function lookup and interpose registration for this family.

`open.rs` uses the descriptor family's original close/fclose helpers solely to clean up a native descriptor or stream when open commit fails. Shared open-request preparation remains on the parent runtime because descriptor-based truncate reuses the same authorization and commit flow.

#### `metadata.rs`

Owns:

- `stat`, `lstat`, `fstat`, and `fstatat`;
- `access` and `faccessat`;
- `readlink` and `readlinkat`;
- `chmod`, `fchmod`, and `fchmodat`;
- logical stat patching and access-plan execution;
- original-function lookup and interpose registration for this family.

#### `namespace.rs`

Owns:

- `mkdir` and `mkdirat`;
- `symlink` and `symlinkat`;
- `unlink`, `unlinkat`, and `rmdir`;
- `rename`, `renameat`, `renamex_np`, and `renameatx_np`;
- original-function lookup and interpose registration for this family.

#### `unsupported.rs`

Owns intercepted mutations that remain unsupported for non-allowlisted paths:

- ownership changes;
- hard links, clone, and copy operations;
- timestamp changes;
- file-flag changes;
- extended-attribute mutations.

It also owns the shared path, descriptor, and pair helpers that choose native passthrough or `ENOTSUP`, plus this family's original-function lookup and interpose registration.

#### `directory/mod.rs`

Owns:

- `chdir`, `fchdir`, `getcwd`, and `realpath`;
- `opendir`, `fdopendir`, `readdir`, `readdir_r`, `rewinddir`, and `closedir`;
- merged-directory cursor state and helpers;
- original-function lookup and interpose registration for this family.

#### `directory/fts.rs`

Owns:

- Darwin FTS ABI types and stream presentation state;
- `fts_open`, `fts_children`, `fts_read`, and `fts_close`;
- virtual `getattrlistbulk` state and record synthesis;
- FTS-specific original-function lookup and interpose registration.

FTS is nested below `directory` because it consumes the merged directory view and cursor filtering rules. This keeps that dependency vertical rather than exposing directory internals to an unrelated sibling module.

FTS also reuses the metadata family's logical stat patcher and native `lstat` lookup so synthesized traversal entries report exactly the same logical size and attributes as stat-family calls.

### ABI and symbol placement

Each operation module keeps these items together:

1. the libc function type alias;
2. the private implementation handler;
3. the existing `agora_sandbox_*` no-mangle export when one exists;
4. its `original_*` lookup;
5. its `dyld_interpose!` registration.

No exported symbol name, C signature, interpose replacement, or section placement changes. Moving a Rust item between modules must not rename its `#[unsafe(no_mangle)]` symbol.

### Visibility and dependency rules

- Child modules may use private state and helpers owned by their parent `filesystem` module.
- Items are widened only to `pub(super)` when a demonstrated sibling or existing test needs them.
- There is no new public crate API.
- Operation modules must not call one another except for the documented native cleanup and FTS stat-patching helpers above.
- The parent runtime may call the namespace family's original `mkdir`, `symlink`, `unlink`, `rmdir`, and `rename` functions for the shared native-passthrough mutation path used by `/dev`.
- There is no catch-all `abi.rs`, `utils.rs`, or `operations.rs` dumping-ground module.

## VFS Deduplication

### Resolved versus unresolved endpoint checks

The VFS will distinguish two private cases explicitly:

- access checking for a raw path whose final symlink still needs resolution;
- access checking for a logical endpoint already resolved by the current operation.

The already-resolved helper reads attributes directly through `entry_attributes_in` and never calls `resolve_final`. The unresolved helper resolves once and delegates to the resolved helper. `effective_attributes_in` is removed because it hides resolution inside an attribute lookup and makes duplicate resolution easy.

Authorized open and change-directory preparation pass their existing resolved endpoint to the resolved helper. Raw endpoint callers retain the unresolved helper, preserving current symlink and errno behavior.

Ancestor search returns the effective attributes it already loaded for the immediate parent. Open-create and namespace-mutation paths reuse those attributes for the later parent write check instead of resolving and loading the parent a second time. Existence and errno ordering remain unchanged because the write decision is still made at the same operation-specific point; only the data is reused.

### Shared final-resolution sequence

A small private VFS helper combines the repeated final-follow sequence:

1. require search permission on the requested path;
2. call `resolve_final` once;
3. when the result differs, require search permission on the resolved target;
4. return the resolved logical path together with the effective immediate-parent attributes produced by the applicable search.

The helper accepts only the existing `allow_missing` distinction needed by open/create flows. No operation enum or generic callback is introduced. No-follow operations retain their current explicit path and search handling.

The helper is used only where the existing operation already performs this exact sequence. Canonicalization or directory-view behavior is not silently changed to a different path presentation rule.

### Work deliberately retained

The following similar-looking paths are not redundant and remain separate:

- VFS, overlay, and metadata modules, because they own operation semantics, physical COW state, and persistence respectively;
- the native lower fast-path probe and the full logical path, because the full path runs only when native passthrough is not valid;
- authorization/staging and encrypted descriptor construction, because `.vfs.lock` must not span native open or decryption;
- authorization/staging and writeback publication, because descriptor writes occur after the namespace transaction;
- test-only storage adapters, because they do not exist in production and keep storage-level tests below the authorization layer.

## Error and Behavior Preservation

This refactor preserves:

- logical path and symlink-follow rules;
- permission credential selection;
- errno values and check ordering;
- `/dev` native passthrough and absence from audit;
- descriptor tracking, close-on-exec, writeback, rename, and unlink behavior;
- directory merge, FTS presentation, and hidden-name filtering;
- all no-mangle C symbols and dyld interpose targets;
- one authorization-and-stage overlay transaction per authorized operation;
- the native lower read and metadata fast paths.

No user-visible configuration, filesystem metadata, or protocol data changes.

## Implementation Sequence

1. Record a green baseline for focused hook and VFS tests.
2. Mechanically split one hook function family at a time, keeping handlers and registrations unchanged.
3. Run the focused hook tests after each family move so symbol, visibility, and state-sharing mistakes are isolated.
4. Add test-only final-resolution counting and failing VFS tests that demonstrate the duplicate endpoint resolution.
5. Implement the resolved/unresolved endpoint helpers and shared final-resolution sequence.
6. Run focused VFS, hook, and runner regressions.
7. Update `spec/architecture/sandbox.md` only with the new internal hook module boundaries; external semantics remain unchanged.
8. Run formatting, workspace tests, Clippy with warnings denied, release build, spec check when available, and workspace coverage at or above 90 percent.

## Test Design

### Hook split characterization

Existing hook tests remain the behavioral characterization suite. They cover the no-mangle entry points through their Rust-visible exports and must pass unchanged apart from module imports.

Focused checks cover:

- open/fopen parity;
- descriptor close, duplicate, sync, and encrypted writeback;
- stat/access/chmod behavior;
- namespace mutations and unsupported operations;
- merged directory enumeration;
- FTS traversal and virtual bulk enumeration;
- `/dev` passthrough across all operation families.

### VFS resolution regression

Test-only instrumentation counts transaction-level calls to final resolution. Tests use a path shape with a deterministic ancestor count and assert that:

- an authorized open resolves the endpoint once rather than once in open preparation and again in endpoint access;
- change-directory preparation resolves the endpoint once rather than again in endpoint access;
- parent mutations reuse the immediate-parent attributes already obtained by ancestor search;
- authorization failure remains side-effect free.

The counter remains under `#[cfg(test)]` and does not alter the production API.

### Full regression

The existing rm/rmdir, external-upper reconciliation, encrypted filename, permission, Codex startup, and Lark export regressions remain green. The exact external behavior is unchanged; this design only reduces code coupling and repeated internal work.

## Specification Impact

`spec/architecture/sandbox.md` will be updated after the code move to describe the hook's internal module ownership. Existing filesystem semantics do not change.

The earlier VFS permission transaction design remains valid. This design completes its existing acceptance criterion that each authorized operation resolves each logical input once, while separately superseding only that plan's earlier decision to leave the monolithic hook file unsplit.

## Acceptance Criteria

- `hook/filesystem.rs` contains shared runtime/facade behavior and no concrete libc hook handlers.
- Hook operations are grouped by the function-family layout above.
- Each handler, original-function lookup, and interpose registration are colocated.
- No exported C symbol, signature, or interpose target changes.
- No generic operation framework, policy layer, or new dependency is introduced.
- Authorized open and change-directory flows do not resolve an already-resolved endpoint again for access checks.
- Parent mutation flows do not resolve and load the immediate parent again after ancestor search.
- Common final-follow authorization orchestration has one private implementation.
- Existing errno ordering, transaction boundaries, native fast paths, COW behavior, and audit behavior are unchanged.
- Focused and workspace validation complete with zero warnings and errors.
- Workspace Rust line coverage remains at least 90 percent.
