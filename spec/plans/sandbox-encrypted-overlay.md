# Encrypted Filesystem Overlay

## Goal

`agora-sandbox` provides one rootless filesystem view for every injectable process in a sandbox run. The view mirrors absolute host paths beneath `<workdir>/fs`, reads through to the host filesystem on cache misses, preserves sandbox writes through copy-on-write, and never modifies the host filesystem. Encrypted APFS storage is the default; plaintext storage is available only through an explicit mode selection.

The implementation is process-tree scoped. It applies only to processes that successfully load the Agora hook library. A process that cannot be prepared for injection is rejected instead of running outside the filesystem view.

## Storage Layout

The APFS AES-256 sparse bundle is stored outside its mount point:

```text
<workdir>/
├── filesystem/
│   ├── fs.sparsebundle
│   └── fs.lock
└── fs/                         # encrypted APFS mount or explicit plaintext root
    ├── .agora/
    │   ├── volume.json
    │   ├── overlay.lock
    │   └── metadata/           # one metadata.json per mirrored host directory
    ├── usr/bin/curl
    ├── tmp/example
    └── Users/example/project/...
```

There are no separate executable, upper, and metadata data trees. Cached host files, prepared executables, and copy-on-write files share the same mirrored tree. The reserved `.agora` control directory is hidden from sandboxed directory enumeration and cannot be addressed by sandboxed processes.

An absolute host path `/tmp/example` maps to `<workdir>/fs/tmp/example`. Relative paths are resolved against the process's logical host current directory before mapping.

## Storage Modes

Encrypted mode is the default and requires a filesystem key. The CLI uses `--filesystem encrypted --filesystem-key <KEY>`, and the SDK uses `SandboxConfig::with_encrypted_workspace`. An absent, empty, invalid, or incorrect key fails closed before the target process starts.

Plaintext mode is selected explicitly with `--filesystem plain` or `SandboxConfig::with_plain_workspace`. It rejects a filesystem key and uses an ordinary persistent `<workdir>/fs` directory. It is not a fallback for an encrypted startup failure. The overlay behavior is identical, but plaintext mode does not encrypt data at rest.

Both modes acquire `<workdir>/filesystem/fs.lock`. Runs using the same work directory are mutually exclusive, while runs using different work directories can proceed concurrently.

The key is an APFS disk-image passphrase. It is sent to `hdiutil` through standard input and is not injected into child arguments or environment. The CLI value remains visible in the parent process arguments and may be retained by shell history.

After a successful mount, `<workdir>/fs/.agora/volume.json` records a version, random volume ID, and random key ID. These IDs are identifiers, not passphrase hashes. An existing image that cannot be mounted reports that the key is incorrect and directs the caller to the explicit key migration command. It is never recreated automatically.

## Directory Metadata

Each mirrored host directory has one control record under the hidden metadata tree. Entry names are encoded so non-UTF-8 host names are supported and cannot escape the metadata directory.

```json
{
  "version": 1,
  "entries": {
    "Y29uZmlnLmpzb24=": {
      "state": "cached",
      "checksum": "d41d8cd98f00b204e9800998ecf8427e",
      "materializer": "copy"
    },
    "Y3VybA==": {
      "state": "cached",
      "checksum": "d41d8cd98f00b204e9800998ecf8427e",
      "materializer": "executable"
    },
    "bm90ZXMudHh0": {
      "state": "cow"
    },
    "ZGVsZXRlZC50eHQ=": {
      "state": "whiteout"
    }
  }
}
```

MD5 is used only for source-change detection; it is not a security primitive.

- `cached`: The file is an unchanged materialization of the host file. The source MD5 is checked before reuse. A mismatch refreshes the file atomically.
- `cow`: The file was created or modified by the sandbox. It is authoritative and is never overwritten when the host file changes.
- `whiteout`: The sandbox deleted the path. Host fallback is blocked until the sandbox explicitly creates the path again.
- `materializer = copy`: Refresh by copying the host file and preserving its supported metadata.
- `materializer = executable`: Refresh by running the executable preparation pipeline, including architecture selection and ad-hoc signing.

Metadata and file publication are serialized by the filesystem root's overlay lock. Files and metadata are written to temporary paths within the selected root and atomically renamed.

## Path Resolution And Copy-On-Write

The hook intercepts path-based filesystem entry points rather than `read` and `write`. File descriptors returned by an intercepted open point at files in the selected sandbox tree, so normal descriptor reads, writes, seeks, locks, `mmap`, and `fsync` retain native kernel behavior.

Intercepted `open`, `openat`, and `fopen` attempts publish the logical path and structured open mode through the sandbox audit callback. Successful opens associate that context with the native descriptor; intercepted `close` and `fclose` publish the matching close event and release the association after native close succeeds. File events carry the inherited trace chain used by process and network events.

For a read:

1. Resolve the logical absolute host path.
2. Reject access to the reserved `.agora` control namespace.
3. If metadata records a whiteout, return `ENOENT`.
4. If metadata records a COW file, open the sandbox copy.
5. If metadata records a cached file, compare its source MD5 and refresh it when changed.
6. If no entry exists, materialize the host file into the sandbox tree, record it as cached, and open the sandbox copy.

For a write-intent open (`O_WRONLY`, `O_RDWR`, `O_APPEND`, `O_TRUNC`, or creation):

1. Materialize the host file first when no sandbox copy exists.
2. Change its state to `cow` before returning a writable descriptor.
3. Create a new sandbox file and mark it `cow` when neither view contains the path.

This is file-level copy-on-write. The first write-intent open copies the complete host file; it does not copy individual blocks lazily.

Deleting a path removes its sandbox copy and records a whiteout. Renaming moves the sandbox entry and its state without modifying either host path. Directory reads merge host and sandbox names, remove whiteouts, prefer sandbox entries, and hide `.agora`.

## Process Integration

The runner prepares the selected filesystem root before starting the execution controller. Encrypted mode mounts its APFS volume; plaintext mode prepares the ordinary root directory. The executable store writes prepared system binaries into the same mirrored tree and publishes directory metadata with `materializer = executable`.

The runner injects the selected root path into the hook environment. `posix_spawn` and `execve` continue to prepare descendants and propagate the same root. Hook-internal paths, control sockets, the hook library, and paths already beneath the root bypass virtualization to prevent recursion.

The original current directory remains the process's logical current directory. Path hooks resolve relative paths against it and redirect the resulting absolute paths into the selected sandbox tree.

## Key Migration

The CLI exposes an explicit command:

```bash
agora-sandbox migrate-key \
  --workdir <WORKDIR>
```

The command reads the current and replacement keys interactively as visible text and reports milestone-based percentage progress. Migration takes the same exclusive filesystem lock as sandbox startup, requires the image to be detached, rejects identical keys, verifies the old key, and uses `hdiutil chpass` to change the passphrase in place. It then mounts with the new key, generates a new random key ID in `volume.json`, verifies the result, and detaches the image. Existing encrypted data is preserved, and a failed normal startup never attempts migration.

The previous `clean` command is removed. The encrypted filesystem is persistent; deleting the entire sparse bundle is the explicit destructive reset operation and is not performed by sandbox startup.

## Failure Behavior

All filesystem setup and path-virtualization failures are fail-closed. The target process is not started when its selected filesystem root cannot be created, mounted when required, validated, or locked. An intercepted operation returns an appropriate POSIX error instead of falling back to a host write.

The sparse bundle is detached on normal completion, startup rollback, service failure, and best-effort synchronous drop. The mounted plaintext view remains accessible to the same host user while the sandbox is running; encryption protects data at rest.

## Verification

Tests cover encrypted-key validation, explicit plaintext selection, encrypted-volume identity, wrong-key errors, key migration, directory metadata transitions, source checksum refresh, COW preservation across host changes, whiteouts, write-intent copy-up, directory merge behavior, executable refresh, process-tree propagation, same-workdir exclusion, and cleanup after failures.

The macOS integration path verifies that a copied shell can read, modify, delete, and recreate files through the overlay while the original host files remain unchanged.
