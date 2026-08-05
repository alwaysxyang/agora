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
- Every physical upper directory has a valid `.metadata` marker, with a continuous marker chain
  from the backing root.
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
    ├── .metadata          # managed-directory root marker
    ├── .vfs.lock
    ├── .rekey.json        # present only during recoverable key migration
    └── <mirrored path>/
        ├── .metadata
        └── <business files>
```

`.fs.lock` guards the whole work directory. `.vfs.lock` guards short VFS publication and metadata transactions. A fork-aware per-process descriptor pool reuses unlocked descriptors sequentially, opens separate descriptors for concurrent transactions, and discards inherited descriptors after a PID change. Each writable encrypted snapshot holds a shared `.agora-write-lease-*` sidecar lease whose contents identify the currently attached ciphertext destination. Writers coexist; regular-file rename retargets the lease, unlink detaches it so an old snapshot cannot recreate the name, and directory rename still returns `EBUSY` when a subtree writer prevents an exclusive namespace lease. `.key.json` stores only a version, salt, and derived key identifier. Version-3 `.metadata` records store entry state and logical attributes. An encrypted business leaf's authenticated filename ciphertext is both its metadata key and physical filename, with no `backing_names` map or separate persisted logical-name field.

## Read And Write Flow

1. Normalize the logical absolute path, resolve existing path components without following a path into the private work directory, and reject physical work-directory aliases.
2. Keep directory paths mirrored. Resolve control-like logical names to encoded physical names. In encrypted mode, authenticate-encrypt each business-file leaf directly into an `enc_` token used as both the metadata key and physical filename; do not generate a separate random alias.
3. Validate the continuous upper-directory marker chain and consult the parent directory's `.metadata`.
4. Reconcile externally changed upper state under `.vfs.lock`: clear a `cow` or `cached` record whose backing object is missing, preserve `whiteout`, remove an unexpected object at a whiteout path, preserve an attribute-only lower override, and remove unrecorded files, symlinks, or unmarked directory subtrees. Then prefer authoritative `cow` upper data, reject `whiteout`, and otherwise return the lower host path directly. A non-authoritative `cached` entry does not shadow lower for normal reads.
5. On write intent, copy lower data into upper before opening it. Newly created files start in upper. Encrypted exclusive creation reserves its filename ciphertext under `.vfs.lock` until the staged open commits or is dropped. Read-only lower traversal creates no upper directory or metadata.
6. In encrypted mode, open an empty staging descriptor, unlink its temporary name, and only then verify and decrypt upper regular data into the anonymous inode.
7. Duplicate descriptors, including `fcntl(F_DUPFD*)`, share one open-file record and writeback state. Anonymous encrypted descriptors remain close-on-exec even after duplication or `F_SETFD`.
8. On write intent, stage metadata without making it authoritative until open succeeds.
9. On `fsync`, successful `fcntl(F_FULLFSYNC/F_BARRIERFSYNC)`, last tracked close, normal process exit, or before intercepted `exec`, encrypt the descriptor into a temporary ciphertext, sync it, atomically rename it into place while holding `.vfs.lock`, and sync the parent directory.
10. Apply the child umask at logical creation and refresh logical timestamps after successful writeback.

At no point does encrypted mode publish a named plaintext business file beneath the work directory.

## Directory And Metadata Flow

Directories are ordinary owner-accessible backing directories so the controller can maintain them. Their requested mode is retained where possible, with owner management bits forced on physically. Every creation and metadata-publication path writes an empty-or-populated marker before publishing child state. Marker identity is retained with cached metadata, so external marker deletion invalidates cached descendants and advances the shared generation. A present directory without its own marker is untrusted and is removed recursively; descendant metadata cannot restore trust. Startup does not scan the whole upper tree, and deployments use a fresh `<workdir>/fs` rather than a compatibility migration. Directory enumeration merges lower and upper entries, applies whiteouts, reconciles orphans, decrypts encrypted logical leaves, and filters controls. Managed macOS FTS traversal receives the same merged view through scoped synthetic `getattrlistbulk` records, forces `FTS_NOCHDIR`, and presents logical paths rather than private backing paths.

Cached entries carry lower MD5, source identity, materializer type, and logical file attributes, but remain non-authoritative for normal reads. Source-derived cached attributes refresh with a changed lower snapshot; attributes that differ from the recorded source identity are explicit logical overrides and survive copy-up or an uncommitted native open. COW entries remain authoritative and retain logical mode and timestamps independently from the physical `0600` ciphertext container. Explicit materializers reuse an unchanged source identity without recomputing the MD5 and refresh their cached entries when lower changes. Logical permission overrides are enforced by credential-requiring VFS operations without changing lower permissions; each operation resolves, authorizes, and stages or mutates against one scoped overlay transaction. Path traversal checks ancestor search permission, parent mutations check write plus search permission, and chmod requires the effective owner or UID 0. The hook selects real credentials for `access`/ordinary `faccessat` and effective credentials for opens and mutations. Rename validates the operation before materialization, preserves ordinary symlinks, and then updates only upper state; rename and removal never mutate lower data. Intercepted `readlink`/`readlinkat`, `realpath`, and `faccessat` observe the logical view. Intercepted `opendir`/`fdopendir` plus `readdir`/`readdir_r` merge the visible lower and upper view, `rewinddir` resets both physical cursors, and the covered macOS `fts_*`/`getattrlistbulk` path supplies that same view to system tools.

## Key Lifecycle

The first encrypted run creates `.key.json`. A later run derives the cipher and compares the key identifier before child startup. Keys cannot change implicitly.

`migrate-key` acquires `.fs.lock`, prepares and verifies replacement ciphertext for every encrypted business file, and writes `.rekey.json` before publication. Persistent executable cache entries and whiteouts are skipped. Each replacement keeps a recoverable old copy until `.key.json` has switched to the new key. Startup reads the journal and deterministically rolls back an old-key transaction or completes cleanup for a committed new-key transaction. Workspace setup and migration are synchronous storage operations dispatched to blocking workers by the public async runner; progress returns to the async caller over a channel. The UI reports stage percentages because migration does not expose byte-level progress.

## Security Boundary

The design is rootless and requires no mount permission. Its boundary is only as strong as hook coverage. Non-injectable processes, direct syscalls, and uncatchable termination are explicit limitations. The host user can inspect control metadata and ciphertext but not a named plaintext backing file during normal operation. Keychain is not virtualized; descendants use and may mutate the current user's host Keychain directly.

The runtime fails closed when key validation, metadata parsing, decryption authentication, audit delivery, executable preparation, or supported VFS mapping fails.

## Current Limitations

- Write-intent deferred `posix_spawn_file_actions_addopen` and `freopen` are unsupported; read-only deferred opens remain available when they map to a native path.
- Executing encrypted upper business data requires an FD-based execution protocol and currently fails closed instead of falling back to a stale lower executable.
- Ownership changes, hard links, and native copy/clone operations are unsupported while hooked. Symlink creation is supported through upper COW state, and permission changes are logical overlay metadata only.
- Timestamp, file-flag, and extended-attribute mutations, plus non-zero `renamex_np`/`renameatx_np` flags, fail with `ENOTSUP` until the VFS can represent them logically.
- Unsynchronized writes may be lost through `_exit`, fatal signals, or other uncatchable process termination; normal exit and intercepted `exec` commit tracked writes.
- Independently opened writable descriptors use independent plaintext snapshots and shared namespace leases. They do not block one another; overlapping writeback is last-successful-commit-wins rather than full POSIX shared-inode coherence.
- Directory walkers outside the covered `opendir`/`readdir` and macOS `fts_*`/`getattrlistbulk` surfaces may not receive the merged encrypted-upper view.
- Recursive calls on a thread already inside a filesystem hook delegate to native libc so Overlay backing I/O can complete; replacing this guard requires an explicit native backend for all host operations.
- This is not a kernel namespace and does not hide host paths from an unhooked executable.
