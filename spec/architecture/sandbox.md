# Sandbox Filesystem And Executable Preparation

`agora-sandbox` provides a rootless, process-tree-scoped filesystem view on macOS. Supported path operations read through to the host filesystem, while sandbox mutations use a persistent copy-on-write tree. The original host paths are never modified.

This is a cooperative boundary, not a kernel namespace. It applies only to processes that load the Agora hook library. Executable preparation fails closed when a process cannot be made injectable.

## Storage Layout

`SandboxConfig::new` defaults the work directory to `~/.agora-sandbox`. The CLI accepts `--workdir <WORKDIR>`, and the SDK exposes `SandboxConfig::with_workdir`.

`<workdir>/fs` is the only persistent filesystem backing tree. Absolute logical paths are mirrored below it: `/usr/bin/curl` maps to `<workdir>/fs/usr/bin/curl`. There is no disk image, mount point, or separate `filesystem` directory.

Control data is stored in place:

```text
<workdir>/fs/
├── .fs.lock
├── .key.json              # encrypted mode only
├── .vfs.lock
├── .rekey.json            # only while key migration is recoverable
├── usr/
│   └── bin/
│       └── .metadata
└── ...
```

Every mirrored directory may contain one `.metadata` file for entry state. Hooked processes cannot access the physical work directory or any physical control path, even when they know the absolute path. Directory enumeration hides control entries. A sandbox may still create a logical business file with a reserved control name such as `.metadata`, `.fs.lock`, `.key.json`, `.vfs.lock`, or `.rekey.json`; exact names, dot-suffixed variants, and internal backing-name prefixes use an encoded physical filename and remain separate from control data.

Automatically managed TLS CA certificate, key, and trust-bundle files remain under `<workdir>/ca`. Prepared SIP-restricted executables are persistent plaintext cache entries at their mirrored paths below `<workdir>/fs`; for example, `/usr/bin/curl` is cached at `<workdir>/fs/usr/bin/curl`. They are controller-managed executable artifacts rather than encrypted business COW files and are reused while the recorded source checksum matches.

## Storage Modes

`--filesystem plain` is the default. It uses the persistent `<workdir>/fs` tree without file-content encryption and rejects a filesystem key.

`--filesystem encrypted` or `SandboxConfig::with_encrypted_workspace` requires a non-empty key. The first run creates `<workdir>/fs/.key.json` with a random salt and derived key identifier. Later runs derive the cipher again and reject a different key before starting the child. Existing unmanaged data is not imported into encrypted mode.

Encrypted regular files use a versioned, chunked AES-256-GCM format. The key is derived with PBKDF2-HMAC-SHA256. Directory paths remain mirrored, while encrypted business-file leaf names use random physical aliases recorded in the parent `.metadata`. Persisted aliases must be unique 32-character hexadecimal backing names; malformed metadata fails closed before an alias is joined to the backing tree. Physical business files beneath `<workdir>/fs` remain ciphertext while the sandbox is running. Reads of encrypted upper files decrypt into anonymous, unlinked file descriptors; the short-lived named staging entry is unlinked before plaintext is written. Lower files without an authoritative upper entry are opened directly from their host paths. Writes modify anonymous descriptors and atomically replace upper ciphertext on `fsync`, successful `fcntl(F_FULLFSYNC/F_BARRIERFSYNC)`, or the last tracked close. Direct host reads of upper storage therefore see only ciphertext, while the hooked process sees plaintext.

The root `.fs.lock` prevents two sandbox runs or a key migration from using the same work directory concurrently. `.vfs.lock` serializes short overlay metadata and publication transactions inside one process tree; every acquisition opens a fresh descriptor so the advisory lock remains effective across threads and forked descendants. Open encrypted descriptors do not retain advisory file leases. Different work directories are independent.

## Copy-On-Write View

The VFS owns path normalization, physical-name encoding, lower-layer reads, whole-file copy-up, whiteouts, per-directory metadata, encryption, and atomic publication. The hook is an adapter for libc operations, descriptor tracking, and audit events; it does not own overlay policy.

Reads prefer an authoritative `cow` upper entry and reject a `whiteout`. Otherwise a lower file or directory is opened directly from its host path without copying it, creating upper directories or metadata, or passing it through decryption. A `cached` entry is non-authoritative and is reserved for explicit materialization such as executable preparation or a staged mutation; normal reads continue to use lower until the mutation commits as `cow`. A later staged write refreshes stale cached data when the lower checksum changes. Cached lower MD5 values are change detectors, not security primitives.

A successful write-intent open changes an entry to `cow`. Existing lower data is copied up first; newly created data exists only in the upper tree. A native open failure leaves a staged cache entry non-authoritative. COW entries are never refreshed from the lower path.

Deletion records a `whiteout`, hiding any lower entry with the same logical path. Rename validates POSIX type, descendant, non-empty-directory, and materializable-file constraints before copy-up, preserves ordinary symlinks when materializing a lower directory, and then moves only upper state. Unsupported special files fail without leaving staged upper data. Intercepted `opendir`/`fdopendir` plus `readdir`/`readdir_r` enumeration merges upper and lower names, prefers upper entries, filters whiteouts, decodes logical aliases, and hides controls. `fdopendir` retains the descriptor's actual layer when the view changes after `open`; it opens any complementary layer before transferring descriptor ownership, so preparation failure leaves the caller's descriptor open.

Each directory's `.metadata` is versioned JSON. Entries are `cached`, `cow`, or `whiteout`; non-authoritative cached entries also carry the lower MD5 and materializer type. Logical mode, owner, group, and access/modification times are stored separately from physical ciphertext attributes. Metadata and ciphertext publication sync the temporary file, atomically rename it while holding `.vfs.lock`, and sync the parent directory before returning success.

## Hook Semantics

The hook covers `open`, `openat`, `creat`, `fopen`, `stat`, `lstat`, `fstat`, `fstatat`, `access`, truncate, deletion, rename, directory creation, current-directory operations, `opendir`/`fdopendir`/`readdir`/`readdir_r` enumeration, `close`, `fclose`, `fsync`, `dup`, `dup2`, and relevant `fcntl` operations. Relative `*at` operations resolve tracked directory descriptors through logical paths, including duplicated descriptors; successful close removes both file and directory tracking. `fchdir` resolves the descriptor's logical path before changing the native current directory and fails closed when that resolution is unavailable.

Encrypted upper regular-file descriptors refer to anonymous plaintext files opened with the caller's requested read/write mode; direct lower reads retain native host descriptors. `open`, `stat`, `fstatat`, and `access` follow the final logical symlink through overlay state, while `lstat` and `AT_SYMLINK_NOFOLLOW` retain link semantics. `stat`, `lstat`, `fstat`, and `fstatat` report logical attributes and plaintext file length instead of encrypted-container attributes when an upper entry or explicit logical permission override is active. Untouched lower entries retain native host attributes. Create mode applies the child process's current umask, and successful encrypted writeback refreshes logical access and modification timestamps. `access` and intercepted opens evaluate logical mode bits. Descriptor duplicates share one writeback record, so ciphertext is published when the last tracked alias closes.

`chmod`, `fchmod`, and `fchmodat` update only logical overlay metadata; they never change lower host permissions. Ownership changes, hard links, symlink creation, `clonefile`, and `copyfile` currently return `ENOTSUP` while the hook is active. Encrypted `posix_spawn_file_actions_addopen` also returns `ENOTSUP` because its deferred native open cannot safely carry an anonymous plaintext descriptor. Supported deferred spawn opens stage their COW state before the native spawn and roll it back when the spawn fails. Direct syscalls and writes made through a mapping after its tracked descriptor has closed are outside the current hook surface.

Writeback is guaranteed for intercepted `fsync`, successful `F_FULLFSYNC`/`F_BARRIERFSYNC`, and tracked close paths. An uncatchable process termination can discard plaintext changes that were never synchronized. Independently opened writable descriptors use independent anonymous snapshots and do not wait on lifetime locks; if they overlap, the last successful writeback wins. Full POSIX shared-inode coherence would require a descriptor broker or kernel-backed filesystem and is outside the current hook-only implementation.

## Executable Preparation

Injectable executables and shebang scripts can run from their original visible paths. When SIP flags, dyld restrictions, library validation, Hardened Runtime, or architecture selection prevent injection, the execution controller copies the selected Mach-O slice into its exact mirrored path below `<workdir>/fs`, applies required processing, and ad-hoc signs it.

Prepared executable copies persist across runs. The source checksum and materializer metadata prevent stale reuse. Descendant `posix_spawn` and `execve` calls use the authenticated execution-preparation channel and fail closed when preparation fails. A shebang interpreter goes through the same path, with its optional argument and prepared script path inserted before caller arguments. An executable replaced by encrypted business COW data never falls back to the stale lower executable, but executing that encrypted upper image remains unsupported until the execution protocol can pass an already-decrypted executable descriptor rather than only a path.

## Key Migration

Normal startup never changes an existing key. Migration is explicit and interactive:

```bash
agora-sandbox migrate-key --workdir <WORKDIR>
```

The command reads the current and replacement keys as visible text, acquires the same `.fs.lock`, validates the old key, decrypts each encrypted business file into an anonymous descriptor, prepares and verifies replacement ciphertext, and persists `.rekey.json` before replacing any file. Controller-managed cached executable copies and whiteouts are not re-encrypted. Old ciphertext remains in per-file backups until `.key.json` commits the new key. Startup rolls back an old-key journal or completes cleanup for a committed new-key journal before opening the workspace. Progress is stage-based rather than byte-based. Identical keys are rejected, and the old key is rejected after a successful migration.

There is no `clean` command. Persistent state is removed only by explicitly deleting the work directory outside normal sandbox startup.

## Audit And Trace

The callback receives unified network, process, and file events. Process and file events are audit-only; network events may allow, deny, or proxy a connection.

The filesystem hook publishes `filesystem.open` before an intercepted open and `filesystem.close` before an intercepted close. Events carry the logical path, structured access flags, current process identity, and trace chain. An unavailable audit controller fails the intercepted operation instead of silently bypassing audit.

Every run starts with one trace ID. Descendants append an ID and forward a bounded comma-separated chain, following `X-Forwarded-For` style. Process, file, and network events carry the same chain so one command can be correlated with its file and network activity.

## TLS Runtime Files

With TLS interception enabled, the runner reuses or creates the configured CA certificate and key, defaulting to `<workdir>/ca/ca.crt` and `<workdir>/ca/ca.key`. A CA-specific trust bundle is assembled below `<workdir>/ca` from the sandbox CA and native roots. File-based TLS clients receive that path; SecTrust clients receive the interception CA through internal hook configuration. There is no public independent trust-anchor option.

Leaf certificates are valid for one day and cached in memory for one hour. DNS names use public-suffix-aware wildcard selection, while IP addresses remain exact. The test suite covers copied `/bin/bash`, system `curl`, transparent CA trust, TLS interception, and a local HTTPS origin without an explicit `--cacert` argument.
