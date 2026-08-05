# VFS Permission Transaction Design

## Status

Approved for implementation on 2026-08-05.

## Goal

Reduce duplicated permission orchestration and make authorization observe the same overlay namespace state as the operation it authorizes. Preserve the existing user-visible POSIX mode behavior and errno ordering.

The design applies only to non-allowlisted overlay paths. Compile-time native passthrough roots such as `/dev` continue to delegate directly to libc and the kernel.

## Non-goals

- Add ACL, sticky-bit, capability, sandbox identity, or ownership virtualization.
- Add support for `chown`, hard links, or other currently unsupported filesystem operations.
- Change the metadata schema, encrypted filename format, COW publication format, or native-passthrough allowlist.
- Change the existing encrypted writeback publication or its lock scope. The authorization transaction must not be extended across native `open`, open-time decryption, descriptor construction, or ordinary descriptor I/O.
- Introduce a generic authorization trait, policy engine, or catch-all filesystem-operation enum.

## Current Problems

Permission-bit evaluation is correctly owned by the VFS, but operation orchestration is split across the hook and VFS:

1. The hook resolves a logical path and calls a VFS validation method.
2. The validation method obtains and releases `.vfs.lock` while reading overlay state.
3. The hook separately calls the VFS operation, which obtains `.vfs.lock` again and may observe different state.

This produces redundant path traversal, metadata lookup, and lock acquisition. It also leaves a state-change window in which another process can change logical permissions, rename an entry, or publish a whiteout after validation but before staging.

The hook also maintains parallel request-building paths for `open` and `fopen`, while `access` and `faccessat` repeat logical-attribute evaluation and result mapping.

## Redundancy Removal

The transaction API replaces old orchestration paths; it is not an additional layer around them.

- Delete the hook-facing `validate_open_permissions`, `validate_create_directory`, `require_search`, `require_access`, and `require_parent_mutation` workflow. Their small rule primitives become private implementation details of authorized VFS operations.
- Remove unauthorised VFS mutation wrappers. Every production mutation entry point requires credentials and performs authorization itself; test-only storage helpers remain explicitly test-only.
- Convert `open` flags and `fopen` mode strings into one `OpenIntent`, then use one common hook request builder and one VFS open path.
- Route `access` and `faccessat` through one common hook helper after their credential and follow-mode differences have been selected.
- Resolve each logical input path once per operation and reuse the result for permission checks, audit context, staging, and descriptor tracking.
- Read ancestor records as one batch from one metadata generation instead of repeatedly calling path-level permission methods.
- Replace repeated public-locking-wrapper followed by private-locked-helper call chains with the scoped `OverlayTransaction` entry point for authorized operations.

The VFS, overlay, and metadata modules remain separate because they own different responsibilities: logical operation semantics, physical COW namespace state, and persisted directory records. Merging those modules would reduce file count but increase coupling. Splitting the entire hook file is also outside this focused change; only the duplicated open and access orchestration is extracted.

## Chosen Architecture

Authorization is part of each explicit VFS operation. The hook remains an ABI adapter; the VFS owns overlay path resolution, permission checks, and operation staging; the overlay owns storage and transaction locking.

### Hook responsibilities

- Validate and convert raw libc arguments.
- Resolve `dirfd`-relative input into a normalized logical path.
- Classify compile-time native-passthrough paths before entering the VFS.
- Select real or effective credentials according to the libc operation.
- Convert `fopen` mode strings into the same open intent used by `open`.
- Invoke the original libc function when the VFS returns a native lower-layer plan.
- Track descriptors and produce audit events after successful operations.

The hook does not calculate owner/group/other permissions and does not separately validate a mutation before invoking it.

### Permission policy responsibilities

A small `filesystem/permissions.rs` module contains only pure data and rules:

- `Credentials { uid, gid, groups }`.
- `AccessRequest { read, write, execute }`.
- Owner/group/other selection and root execute semantics.
- The owner-or-root rule for `chmod`.

The module does not read paths, resolve symlinks, acquire locks, or mutate metadata. It uses no trait or external dependency.

### VFS responsibilities

The VFS exposes explicit operation methods rather than a generic policy dispatcher:

- authorized open preparation;
- access checking;
- metadata/stat preparation and canonicalization;
- directory opening, enumeration, and current-directory preparation;
- directory and symlink creation;
- removal;
- rename;
- chmod.

Each method combines the operation-specific POSIX ordering with shared private primitives for ancestor search, endpoint access, and parent mutation. Hook code never calls those primitives directly. `open` and `fopen` construct one `OpenIntent` and enter one common preparation path.

### Overlay responsibilities

The overlay exposes a filesystem-internal scoped transaction. The transaction holds one `.vfs.lock` acquisition and provides only the lookup, reconciliation, effective-attribute, and mutation primitives needed by the VFS. Locked helpers cannot be called without the transaction, and public locking wrappers cannot be called recursively from it.

This transaction is an internal correctness boundary, not a generic storage abstraction.

## Operation Flows

### Immediate mutations

`mkdir`, symlink creation, removal, rename, and chmod perform the following sequence in one overlay transaction:

1. Normalize the logical path before locking.
2. Reconcile relevant upper state.
3. Resolve final symlinks according to the operation.
4. Check ancestor search permissions.
5. Check endpoint or parent permissions in POSIX order.
6. Apply the upper and metadata mutation.
7. Publish the metadata generation and release the lock.

No authoritative state is published after a failed authorization check.

### Open

Open remains a two-phase operation because native descriptor construction and open-time decryption must not hold the namespace lock.

The first transaction resolves the path, checks permissions, and creates any required COW stage, encrypted filename reservation, and write lease from one namespace snapshot. Native `open` or anonymous plaintext descriptor construction then occurs without `.vfs.lock`. A short commit transaction publishes `cow` only after descriptor construction succeeds.

Dropping an uncommitted open plan releases an exclusive encrypted-name reservation. An ordinary copy-up cache may remain reusable and non-authoritative, matching current behavior, but no `cow` state is published. If reservation cleanup itself fails, the object has no authoritative metadata and lazy reconciliation must keep it invisible and remove it later. The original operation errno remains authoritative.

An already-open descriptor is not re-authorized after a later chmod. Existing rename, unlink, and write-lease rules continue to prevent a stale descriptor from republishing a detached name.

### Read-only lower fast path

The VFS retains native lower-layer passthrough when the path, resolved target, and relevant ancestor chains have no overlay state requiring logical handling. The kernel remains responsible for lower permissions in that case. A logical endpoint attribute override or denied logical ancestor forces the full VFS path.

### Access-family calls

`access` uses real credentials. `faccessat` uses real credentials unless `AT_EACCESS` requests effective credentials. Invalid access bits still return `EINVAL`. The VFS either returns a logical authorization result or a native lower path for the hook to pass to the original libc function.

## Error Semantics

Existing externally visible ordering is preserved:

- denied read, write, execute, traversal, or parent mutation returns `EACCES`;
- chmod by a non-owner and non-root identity returns `EPERM`;
- visible `O_CREAT|O_EXCL` targets return `EEXIST`;
- `mkdir` checks searchable ancestry and a visible endpoint before parent mutation permission so BSD `mkdir -p` retains `EEXIST` behavior;
- missing non-created targets return `ENOENT`;
- rename crossing a native-passthrough boundary returns `EXDEV`;
- unsupported flags and operations retain their current errors.

Authorization failure occurs before copy-up, authoritative metadata publication, or audit success reporting. Lower host data and permissions are never changed by non-allowlisted operations.

## Performance Constraints

- One authorization-and-stage transaction must acquire `.vfs.lock` once.
- Ancestor permission checks must use one metadata generation snapshot and batched metadata records rather than one snapshot per ancestor.
- `open` and `fopen` must share flag and access derivation after mode-string parsing.
- Native read-only lower access must retain the existing fast path.
- The permission transaction must not extend across open-time decryption, native descriptor construction, or ordinary descriptor I/O. Existing encrypted writeback publication remains out of scope.
- The refactor must not add a recursive lock path.

## Test Design

### Pure policy tests

Table-driven tests cover owner, primary group, supplementary group, other, and UID 0 for every read/write/execute combination. Separate cases cover root execute behavior and chmod ownership.

### VFS transaction tests

- Permission denial leaves no cached entry, COW entry, encrypted reservation, attributes, or physical upper object.
- Open authorization and staging use one transaction snapshot.
- Directory creation, symlink creation, removal, rename, and chmod authorize and mutate under one lock acquisition.
- A second VFS instance cannot interleave a logical permission or namespace publication between authorization and staging.
- Failed native descriptor construction drops the uncommitted plan without publishing COW state.
- Existing errno-ordering cases remain unchanged.

Test-only instrumentation may count transaction entries; production APIs do not expose lock counters.

### Hook parity tests

- Equivalent `open` flags and `fopen` modes produce the same `OpenIntent` and permission result.
- `access` and `faccessat` preserve real/effective credential selection and no-follow behavior.
- Native `/dev` operations continue to bypass logical authorization and audit.

### Integration and regression tests

- A logically read-only lower file rejects write and creates no upper state.
- Owner chmod changes only logical metadata; a later permitted write creates COW while the lower mode and contents remain unchanged.
- Deleting a read-only file from a writable searchable parent succeeds.
- An unsearchable ancestor denies open, stat-family logical handling, mutation, and directory traversal.
- Plain and encrypted filesystems produce the same logical permission behavior.
- Existing rm, external-upper reconciliation, encrypted filename, Codex startup, and Lark export regressions remain green.

Validation includes formatting, focused affected-crate tests, workspace all-target tests, Clippy with warnings denied, release build, and workspace line coverage of at least 90 percent.

## Compatibility and Specification Impact

This is an internal API and transaction-boundary refactor. It does not change CLI flags, configuration, persistent metadata, audit schema, or intended POSIX behavior. `spec/architecture/sandbox.md` must be updated to state that authorization and operation staging share one overlay transaction and that open publication remains two-phase.

## Acceptance Criteria

- The hook contains no duplicate open/fopen permission orchestration.
- `open`/`fopen` and `access`/`faccessat` each have one shared internal execution path after ABI-specific parsing.
- Logical mode-bit decisions live only in the permission policy module.
- Production hook code does not call standalone permission-validation methods before a later mutation call.
- Old hook-facing `validate_*` and `require_*` permission orchestration entry points are removed rather than retained as wrappers.
- Non-allowlisted mutation entry points cannot call an unauthorised overlay mutation directly.
- Each authorized operation resolves each logical input once and batches ancestor metadata from one generation snapshot.
- Authorization and namespace staging observe one `.vfs.lock` snapshot.
- Permission failures leave no visible or authoritative upper state.
- All existing user-visible permission and errno behavior remains unchanged.
- Required validation completes with zero warnings and at least 90 percent line coverage.
