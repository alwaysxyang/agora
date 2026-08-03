# Rootless Encrypted Overlay Implementation

## Architecture

The implementation has four focused layers:

1. `filesystem::workspace` owns the persistent root, mode selection, and exclusive run lock.
2. `filesystem::overlay`, `metadata`, and `namespace` own logical paths, lower reads, COW, whiteouts, and physical layout.
3. `filesystem::crypto`, `encrypted`, and `vfs` own key identity, authenticated file encryption, anonymous plaintext descriptors, logical mode authorization, writeback, and key migration.
4. `hook::filesystem` adapts libc calls to the VFS, tracks descriptors, and emits audit events.

Executable preparation remains separate under `execution`; restricted native copies persist as checksum-validated cache entries at exact mirrored paths below `<workdir>/fs`.

## Completed Work

- [x] Use `<workdir>/fs` as the only persistent backing tree.
- [x] Remove the previous image, mount, detach, watchdog, and helper-process behavior.
- [x] Add root `.fs.lock`, encrypted `.key.json`, and VFS `.vfs.lock`.
- [x] Store versioned `.metadata` beside each mirrored directory.
- [x] Encode reserved logical business names and randomize encrypted business-file leaf names without exposing controls.
- [x] Implement cached, COW, and whiteout states.
- [x] Keep ordinary lower reads on native host paths and copy up only on write intent or another mutation.
- [x] Encrypt all persistent regular business files with chunked AES-256-GCM.
- [x] Keep plaintext in anonymous descriptors and publish ciphertext atomically.
- [x] Write back on `fsync`, successful `F_FULLFSYNC`/`F_BARRIERFSYNC`, last tracked `close`/`fclose`, normal exit, and before intercepted `exec`.
- [x] Track file and directory aliases across `dup`, `dup2`, `fcntl(F_DUPFD*)`, close, and `fdopendir`.
- [x] Reject physical work-directory access, including external symlink aliases, from hooked processes.
- [x] Report plaintext length and logical attributes through `stat`, `lstat`, `fstat`, and `fstatat`.
- [x] Evaluate `access` against logical permissions rather than ciphertext-container mode.
- [x] Evaluate ancestor, parent mutation, owner/group/other, real/effective credential, and `O_NOFOLLOW` rules in the VFS.
- [x] Keep `chmod`, `fchmod`, and `fchmodat` inside logical metadata, require owner or UID 0, and never change lower permissions.
- [x] Map `readlink`, `readlinkat`, `faccessat`, and zero-flag extended rename through the logical view.
- [x] Fail closed on unsupported timestamp, file-flag, xattr, and extended-rename mutations.
- [x] Follow final overlay symlinks for open/stat while preserving lstat and no-follow behavior.
- [x] Validate rename before materialization and preserve ordinary lower symlinks.
- [x] Keep encrypted descriptors close-on-exec, commit them before intercepted `exec`, and prevent `F_SETFD` from clearing close-on-exec.
- [x] Hold shared per-backing leases for writable encrypted snapshots so rename and removal fail with `EBUSY` without serializing independent writers.
- [x] Reserve encrypted `O_CREAT|O_EXCL` backing names until staged creation commits or is abandoned.
- [x] Commit staged COW metadata only after native open succeeds.
- [x] Persist executable copies below `<workdir>/fs` and CA-specific trust material below `<workdir>/ca`.
- [x] Implement interactive, journaled, recoverable per-file key migration.
- [x] Keep workspace and migration cores synchronous and dispatch them from async APIs through blocking workers.
- [x] Preserve plain mode with the same overlay semantics.

## Verification Matrix

- Unit tests cover encryption authentication, durable ciphertext publication, key identity, namespace encoding, per-directory metadata, COW transitions, whiteouts, encrypted directory rename and removal, merged `opendir`/`fdopendir` views and rewind, descriptor aliasing, plaintext stat size, physical path denial, logical credential/ownership enforcement, failed-open behavior, mapped link/access operations, fail-closed metadata mutations, deferred-write rejection, and blocking-worker lifecycle boundaries.
- Runner tests cover the actual interposed filesystem symbol set, ciphertext persistence while a child is active, source immutability, session cleanup, wrong-key rejection, same-workdir exclusion, copied executable descendants, system curl, and transparent TLS.
- CLI tests cover mode/key validation, interactive migration, TLS CA handling, audit output, and removed-command rejection.
- Final validation requires formatting, workspace tests, clippy with warnings denied, `just spec-check`, and at least 90% workspace line coverage.

## Deferred Surface

The encrypted implementation intentionally rejects operations that cannot preserve the logical overlay safely. Write-intent deferred spawn opens, `freopen`, timestamp/file-flag/xattr mutations, non-zero extended rename flags, encrypted-upper executable FD launching, direct syscalls, memory-mapped writes after tracked close, libc-private directory walkers, and uninjectable descendants remain outside the supported surface. Read-only deferred spawn opens are allowed only when the visible entry maps to a native path; no deferred operation publishes speculative COW state. Recursive hook entry delegates to native libc for Overlay backing I/O and would require a complete original-libc backend to remove. Full shared-inode coherence across independently opened writable snapshots would require a descriptor broker or kernel-backed filesystem.
