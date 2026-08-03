# Rootless Encrypted Overlay Filesystem

## Goal

Provide one rootless filesystem view for injectable macOS process trees. Reads fall through to host paths, writes remain isolated under `<workdir>/fs`, and encrypted mode keeps every persistent business file as ciphertext for the entire run.

## Decisions

- `<workdir>/fs` is the only persistent backing tree.
- The implementation does not use filesystem images, mounts, FUSE, `chroot`, or privileged helpers.
- Plain mode stores upper files directly.
- Encrypted mode stores upper files as chunked AES-256-GCM data and exposes their plaintext only through anonymous descriptors.
- VFS overlay, logical mode authorization, and cryptography are independent from libc interposition.
- Control files live beside mirrored data but are hidden and physically unreachable from the sandbox.
- Logical business files may use control-like names through physical name encoding.
- Copy-on-write and whiteouts operate at whole-file granularity.
- SIP-restricted executable copies are persistent controller-managed cache entries at exact mirrored paths below `<workdir>/fs`.
- Runtime trust material remains below `<workdir>/ca`.

## Persistent Layout

```text
<workdir>/
├── ca/
└── fs/
    ├── .fs.lock
    ├── .key.json          # encrypted mode only
    ├── .vfs.lock
    ├── .rekey.json        # present only during recoverable key migration
    └── <mirrored path>/
        ├── .metadata
        └── <business files>
```

`.fs.lock` guards the whole work directory. `.vfs.lock` guards short VFS publication and metadata transactions. A fresh descriptor is opened for each acquisition so the lock remains effective across threads and forked descendants. Each writable encrypted snapshot holds a shared `.agora-write-lease-*` sidecar lease; writers coexist, while rename and removal use a non-blocking exclusive lease and return `EBUSY` if an affected writer is active. `.key.json` stores only a version, salt, and derived key identifier. `.metadata` stores entry state, logical file attributes, and encrypted business-file leaf aliases for its own logical directory.

## Read And Write Flow

1. Normalize the logical absolute path, resolve existing path components without following a path into the private work directory, and reject physical work-directory aliases.
2. Keep directory paths mirrored. Resolve control-like logical names to encoded physical names and encrypted business-file leaves to random physical aliases.
3. Consult the parent directory's `.metadata`.
4. Prefer authoritative `cow` upper data, reject `whiteout`, and otherwise return the lower host path directly. A non-authoritative `cached` entry does not shadow lower for normal reads.
5. On write intent, copy lower data into upper before opening it. Newly created files start in upper. Encrypted exclusive creation reserves its backing name under `.vfs.lock` until the staged open commits or is dropped. Read-only lower traversal creates no upper directory or metadata.
6. In encrypted mode, open an empty staging descriptor, unlink its temporary name, and only then verify and decrypt upper regular data into the anonymous inode.
7. Duplicate descriptors, including `fcntl(F_DUPFD*)`, share one open-file record and writeback state. Anonymous encrypted descriptors remain close-on-exec even after duplication or `F_SETFD`.
8. On write intent, stage metadata without making it authoritative until open succeeds.
9. On `fsync`, successful `fcntl(F_FULLFSYNC/F_BARRIERFSYNC)`, last tracked close, normal process exit, or before intercepted `exec`, encrypt the descriptor into a temporary ciphertext, sync it, atomically rename it into place while holding `.vfs.lock`, and sync the parent directory.
10. Apply the child umask at logical creation and refresh logical timestamps after successful writeback.

At no point does encrypted mode publish a named plaintext business file beneath the work directory.

## Directory And Metadata Flow

Directories are ordinary owner-accessible backing directories so the controller can maintain them. Their requested mode is retained where possible, with owner management bits forced on physically. Directory enumeration merges lower and upper entries, applies whiteouts, decodes logical aliases, and filters controls.

Cached entries carry lower MD5, materializer type, and logical file attributes, but remain non-authoritative for normal reads. COW entries remain authoritative and retain logical mode and timestamps independently from the physical `0600` ciphertext container. Explicit materializers refresh their own cached entries when lower changes. Logical permission overrides are also stored in metadata and are enforced by VFS authorization methods without changing lower permissions; path traversal checks ancestor search permission, parent mutations check write plus search permission, and chmod requires the effective owner or UID 0. The hook selects real credentials for `access`/ordinary `faccessat` and effective credentials for opens and mutations. Rename validates the operation before materialization, preserves ordinary symlinks, and then updates only upper state; rename and removal never mutate lower data. Intercepted `readlink`/`readlinkat` and `faccessat` observe the logical view. Intercepted `opendir`/`fdopendir` plus `readdir`/`readdir_r` merge the visible lower and upper view, and `rewinddir` resets both physical cursors; programs that bypass those APIs through libc-private traversal helpers remain outside this hook surface.

## Key Lifecycle

The first encrypted run creates `.key.json`. A later run derives the cipher and compares the key identifier before child startup. Keys cannot change implicitly.

`migrate-key` acquires `.fs.lock`, prepares and verifies replacement ciphertext for every encrypted business file, and writes `.rekey.json` before publication. Persistent executable cache entries and whiteouts are skipped. Each replacement keeps a recoverable old copy until `.key.json` has switched to the new key. Startup reads the journal and deterministically rolls back an old-key transaction or completes cleanup for a committed new-key transaction. Workspace setup and migration are synchronous storage operations dispatched to blocking workers by the public async runner; progress returns to the async caller over a channel. The UI reports stage percentages because migration does not expose byte-level progress.

## Security Boundary

The design is rootless and requires no mount permission. Its boundary is only as strong as hook coverage. Non-injectable processes, direct syscalls, and uncatchable termination are explicit limitations. The host user can inspect control metadata and ciphertext but not a named plaintext backing file during normal operation.

The runtime fails closed when key validation, metadata parsing, decryption authentication, audit delivery, executable preparation, or supported VFS mapping fails.

## Current Limitations

- Write-intent deferred `posix_spawn_file_actions_addopen` and `freopen` are unsupported; read-only deferred opens remain available when they map to a native path.
- Executing encrypted upper business data requires an FD-based execution protocol and currently fails closed instead of falling back to a stale lower executable.
- Ownership changes, links, and native copy/clone operations are unsupported while hooked. Permission changes are logical overlay metadata only.
- Timestamp, file-flag, and extended-attribute mutations, plus non-zero `renamex_np`/`renameatx_np` flags, fail with `ENOTSUP` until the VFS can represent them logically.
- Unsynchronized writes may be lost through `_exit`, fatal signals, or other uncatchable process termination; normal exit and intercepted `exec` commit tracked writes.
- Independently opened writable descriptors use independent plaintext snapshots and shared namespace leases. They do not block one another; overlapping writeback is last-successful-commit-wins rather than full POSIX shared-inode coherence.
- libc-private directory walkers such as the system `fts_*` implementation do not receive the merged encrypted-upper view, although ordinary intercepted directory iteration does.
- Recursive calls on a thread already inside a filesystem hook delegate to native libc so Overlay backing I/O can complete; replacing this guard requires an explicit native backend for all host operations.
- This is not a kernel namespace and does not hide host paths from an unhooked executable.
