# Rootless Encrypted Overlay Filesystem

## Goal

Provide one rootless filesystem view for injectable macOS process trees. Reads fall through to host paths, writes remain isolated under `<workdir>/fs`, and encrypted mode keeps every persistent business file as ciphertext for the entire run.

## Decisions

- `<workdir>/fs` is the only persistent backing tree.
- The implementation does not use filesystem images, mounts, FUSE, `chroot`, or privileged helpers.
- Plain mode stores upper files directly.
- Encrypted mode stores upper files as chunked AES-256-GCM data and exposes their plaintext only through anonymous descriptors.
- VFS policy and cryptography are independent from libc interposition.
- Control files live beside mirrored data but are hidden and physically unreachable from the sandbox.
- Logical business files may use control-like names through physical name encoding.
- Copy-on-write and whiteouts operate at whole-file granularity.
- Runtime executable copies and trust bundles are per-run temporary files outside the work directory.

## Persistent Layout

```text
<workdir>/
├── ca/
└── fs/
    ├── .fs.lock
    ├── .key.json          # encrypted mode only
    ├── .vfs.lock
    ├── .locks/            # stable per-logical-file locks
    ├── .rekey.json        # present only during recoverable key migration
    └── <mirrored path>/
        ├── .metadata
        └── <business files>
```

`.fs.lock` guards the whole work directory. `.vfs.lock` guards short VFS publication and metadata transactions. A fresh descriptor is opened for each lock acquisition so the lock remains effective across threads and forked descendants. `.locks` contains stable files keyed by normalized logical path; encrypted upper readers hold shared locks and writers hold exclusive locks for the lifetime of their open-file description. Direct lower readers do not create a file lease. `.key.json` stores only a version, salt, and derived key identifier. `.metadata` stores entry state and logical file attributes for its own logical directory.

## Read And Write Flow

1. Normalize the logical absolute path, resolve existing path components without following a path into the private work directory, and reject physical work-directory aliases.
2. Resolve reserved logical names to encoded physical names.
3. Consult the parent directory's `.metadata`.
4. Prefer authoritative `cow` upper data, reject `whiteout`, and otherwise return the lower host path directly. A non-authoritative `cached` entry does not shadow lower for normal reads.
5. On write intent, acquire the logical file's exclusive lock and copy lower data into upper before opening it. Newly created files start in upper.
6. For an encrypted upper read, acquire the logical file's shared lock before creating a view. Direct lower reads do not create a VFS lock.
7. In encrypted mode, verify and decrypt upper regular data into an anonymous descriptor.
8. Duplicate descriptors, including `fcntl(F_DUPFD*)`, share one open-file record and lock lease.
9. On write intent, stage metadata without making it authoritative until open succeeds.
10. On `fsync` or last tracked close, encrypt the descriptor into a temporary ciphertext and atomically rename it into place.
11. Release the per-file lock only after the last tracked descriptor closes.

At no point does encrypted mode publish a named plaintext business file beneath the work directory.

## Directory And Metadata Flow

Directories are ordinary owner-accessible backing directories so the controller can maintain them. Their requested mode is retained where possible, with owner management bits forced on physically. Directory enumeration merges lower and upper entries, applies whiteouts, decodes logical aliases, and filters controls.

Cached entries carry lower MD5, materializer type, and logical file attributes, but remain non-authoritative for normal reads. COW entries remain authoritative and retain logical mode and timestamps independently from the physical `0600` ciphertext container. Explicit materializers refresh their own cached entries when lower changes. Logical permission overrides are also stored in metadata and are enforced by intercepted stat, access, and open operations without changing lower permissions. Rename validates the operation before materialization, preserves ordinary symlinks, and then updates only upper state; rename and removal never mutate lower data.

## Key Lifecycle

The first encrypted run creates `.key.json`. A later run derives the cipher and compares the key identifier before child startup. Keys cannot change implicitly.

`migrate-key` acquires `.fs.lock`, prepares and verifies replacement ciphertext for every business file, and writes `.rekey.json` before publication. Each replacement keeps a recoverable old copy until `.key.json` has switched to the new key. Startup reads the journal and deterministically rolls back an old-key transaction or completes cleanup for a committed new-key transaction. The UI reports stage percentages because migration does not expose byte-level progress.

## Security Boundary

The design is rootless and requires no mount permission. Its boundary is only as strong as hook coverage. Non-injectable processes, direct syscalls, and uncatchable termination are explicit limitations. The host user can inspect control metadata and ciphertext but not a named plaintext backing file during normal operation.

The runtime fails closed when key validation, metadata parsing, decryption authentication, audit delivery, executable preparation, or supported VFS mapping fails.

## Current Limitations

- Encrypted deferred `posix_spawn_file_actions_addopen` is unsupported.
- Ownership changes, links, and native copy/clone operations are unsupported while hooked. Permission changes are logical overlay metadata only.
- Unsynchronized writes may be lost on uncatchable process termination.
- File content is serialized per logical path. Multiple readers may coexist, while a writer excludes readers and other writers until its last descriptor closes.
- This is not a kernel namespace and does not hide host paths from an unhooked executable.
