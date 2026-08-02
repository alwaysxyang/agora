# Rootless Encrypted Overlay Implementation

## Architecture

The implementation has four focused layers:

1. `filesystem::workspace` owns the persistent root, mode selection, and exclusive run lock.
2. `filesystem::overlay`, `metadata`, and `namespace` own logical paths, lower reads, COW, whiteouts, and physical layout.
3. `filesystem::crypto`, `encrypted`, and `vfs` own key identity, authenticated file encryption, anonymous plaintext descriptors, writeback, and key migration.
4. `hook::filesystem` adapts libc calls to the VFS, tracks descriptors, and emits audit events.

Executable preparation remains separate under `execution`; it uses a per-run temporary root rather than persistent filesystem storage.

## Completed Work

- [x] Use `<workdir>/fs` as the only persistent backing tree.
- [x] Remove the previous image, mount, detach, watchdog, and helper-process behavior.
- [x] Add root `.fs.lock`, encrypted `.key.json`, and VFS `.vfs.lock`.
- [x] Store versioned `.metadata` beside each mirrored directory.
- [x] Encode reserved logical business names without exposing controls.
- [x] Implement cached, COW, and whiteout states.
- [x] Keep ordinary lower reads on native host paths and copy up only on write intent or another mutation.
- [x] Encrypt all persistent regular business files with chunked AES-256-GCM.
- [x] Keep plaintext in anonymous descriptors and publish ciphertext atomically.
- [x] Write back on `fsync` and last tracked `close`/`fclose`.
- [x] Track `dup`, `dup2`, and `fcntl(F_DUPFD*)` aliases.
- [x] Reject physical work-directory access, including external symlink aliases, from hooked processes.
- [x] Report plaintext length and logical attributes through `stat`, `lstat`, `fstat`, and `fstatat`.
- [x] Evaluate `access` against logical permissions rather than ciphertext-container mode.
- [x] Keep `chmod`, `fchmod`, and `fchmodat` inside logical metadata without changing lower permissions.
- [x] Follow final overlay symlinks for open/stat while preserving lstat and no-follow behavior.
- [x] Validate rename before materialization and preserve ordinary lower symlinks.
- [x] Serialize encrypted opens per logical file with shared reader and exclusive writer leases.
- [x] Commit staged COW metadata only after native open succeeds.
- [x] Move executable copies and TLS trust bundles into per-run temporary storage.
- [x] Implement interactive, journaled, recoverable per-file key migration.
- [x] Preserve plain mode with the same overlay semantics.

## Verification Matrix

- Unit tests cover encryption authentication, ciphertext publication, key identity, namespace encoding, per-directory metadata, COW transitions, whiteouts, merged directory views, descriptor aliasing, plaintext stat size, physical path denial, and failed-open rollback.
- Runner tests cover ciphertext persistence while a child is active, source immutability, session cleanup, wrong-key rejection, same-workdir exclusion, copied executable descendants, system curl, and transparent TLS.
- CLI tests cover mode/key validation, interactive migration, transient trust anchors, audit output, and removed-command rejection.
- Final validation requires formatting, workspace tests, clippy with warnings denied, `just spec-check`, and at least 90% workspace line coverage.

## Deferred Surface

The encrypted implementation intentionally rejects operations that cannot preserve the anonymous-descriptor model safely. Deferred spawn opens, direct syscalls, memory-mapped writes after tracked close, and uninjectable descendants remain outside the supported surface.
