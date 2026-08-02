# Sandbox Filesystem And Executable Preparation

`agora-sandbox` provides a process-tree-scoped, rootless filesystem view on macOS. Supported path operations read through to the host filesystem, while all materialized and modified data is stored beneath one persistent sandbox filesystem root. Plaintext storage is the default; encrypted APFS storage is available when encryption at rest is required. The original host paths are never modified. This guarantee applies only to processes that load the Agora hook library; executable preparation fails closed when a process cannot be made injectable.

## Work Directory

`SandboxConfig::new` defaults the sandbox work directory to `~/.agora-sandbox`, using the current process's `HOME`. The CLI accepts `--workdir <WORKDIR>`, and the library exposes `SandboxConfig::with_workdir`.

Both filesystem modes expose `<workdir>/fs` as the mirrored root: `/usr/bin/curl` maps to `<workdir>/fs/usr/bin/curl`, and `/Users/example/project/file` maps to `<workdir>/fs/Users/example/project/file`. In encrypted mode, an AES-256 APFS sparse bundle is stored at `<workdir>/filesystem/fs.sparsebundle` and mounted at that root; it has a 100 GiB logical capacity and grows on demand. In plaintext mode, `<workdir>/fs` is an ordinary persistent directory. Automatically managed TLS CA material remains outside the filesystem root under `<workdir>/ca`.

The volume contains a reserved `<workdir>/fs/.agora` control directory for `volume.json`, the overlay lock, and directory metadata. Hooked processes cannot address this namespace, and directory enumeration hides it.

## Filesystem Storage Modes

`--filesystem plain` is the default. It selects an ordinary persistent `<workdir>/fs` directory and does not accept a filesystem key.

`--filesystem encrypted` or `SandboxConfig::with_encrypted_workspace` explicitly selects encrypted APFS storage and requires a passphrase through `--filesystem-key <KEY>` or the SDK builder. An absent, empty, NUL-containing, oversized, or incorrect key fails before the target process starts. The passphrase has redacted `Debug` output and is sent to `hdiutil` through standard input; it is not injected into child arguments or environment. A CLI value remains visible in the parent process arguments and may be retained by shell history. Plaintext mode preserves the same read-through, COW, whiteout, executable-preparation, and host-isolation behavior, but provides no encryption at rest and is never selected as a fallback after encrypted startup fails.

The first encrypted run creates the sparse bundle and writes a versioned random volume ID and key ID to `<workdir>/fs/.agora/volume.json`. Later encrypted runs reuse the same volume. Existing plaintext data in an unmounted `<workdir>/fs` is rejected rather than imported or overwritten. Both modes acquire the same non-blocking lock at `<workdir>/filesystem/fs.lock`, so only one run or encrypted-key migration can use a work directory at a time. Different work directories remain independent.

The volume is detached after the child, network controller, and execution controller stop. Detach retries tolerate the short vnode retention period after running copied Mach-O files, without using forced unmount. A synchronous best-effort detach also runs during error-path destruction. While a volume is mounted, a watchdog process inherits the filesystem lock and a controller-liveness pipe; unexpected controller death closes the pipe, so the watchdog retries a normal detach before releasing the lock.

## Copy-On-Write Overlay

The injected hook redirects `open`, `openat`, `creat`, `fopen`, path metadata and access checks, truncate, deletion, rename, directory creation, current-directory operations, and directory enumeration. The `*at` variants resolve tracked directory descriptors through their recorded logical paths, and `posix_spawn_file_actions_addopen` stores a mirrored path for the pre-exec open. Returned file descriptors refer to native files beneath the selected filesystem root, so descriptor reads, writes, seeks, locks, `mmap`, and `fsync` retain kernel behavior without interposing `read` or `write`. Descriptor-based truncate, permission, and ownership changes are allowed only after verifying that the descriptor names a regular file in the selected root. Path-based permission/ownership changes, hard-link and symlink creation, and `clonefile`/`copyfile` currently return `ENOTSUP` while the sandbox runtime is active instead of falling back to a host mutation.

Reads prefer an existing sandbox entry. On a cache miss, a regular host file is copied into the mirrored root and marked `cached`. Its host MD5 is checked before reuse; a changed host file refreshes the cached copy. MD5 is only a change detector, not a security primitive.

A write-intent open copies an existing host file into the mirrored root before opening it. The entry changes from `cached` to `cow` only after the native open succeeds; a failed open cannot make a cached file authoritative. A newly created file is created only in the mirrored root and is marked `cow` after its native open succeeds. Deferred `posix_spawn` open actions are staged when the action is added and committed immediately before a spawn uses those actions. COW entries remain authoritative and are never replaced when the host changes. Copy-on-write operates at whole-file granularity rather than block granularity.

Deletion removes the sandbox entry and records a `whiteout`, which hides any host entry with the same logical path. Rename moves only sandbox state after applying POSIX same-path, type, descendant, and non-empty-directory checks, so a failed replacement cannot recursively remove the destination's COW data. Directory enumeration lazily merges sandbox and host names, prefers sandbox entries, filters whiteouts, and never creates placeholder files for lower-only names.

Each logical directory has one versioned JSON record beneath `<workdir>/fs/.agora/metadata`. Entry names are encoded to support non-UTF-8 names and prevent path traversal. Entry states are `cached`, `cow`, or `whiteout`; cached entries also record their MD5 and whether they were materialized as a regular copy or prepared executable. Metadata and file publication use temporary paths and atomic rename while holding `<workdir>/fs/.agora/overlay.lock`.

## Executable Preparation

Injectable executables and shebang scripts can run from their visible paths. When SIP file flags, dyld restrictions, library validation, or Hardened Runtime prevent injection, the execution controller copies the compatible native architecture into the sandbox mirror, applies required Mach-O processing, and ad-hoc signs the result. A prepared executable is reused only while its sandbox copy remains executable and its recorded source MD5 matches.

The executable store and general filesystem overlay share the same mirrored tree and metadata. A regular cached file is upgraded through executable preparation before execution. A COW executable is never replaced with its lower host version; if its signature restricts injection, the COW copy is re-signed in place.

For a shebang script, the optional shebang argument and script path are inserted before caller arguments, and the interpreter goes through the same preparation pipeline. Descendant `posix_spawn` and `execve` calls use execution-preparation protocol version 5 and propagate the selected filesystem root. The preparation protocol carries only authentication and the executable path; process and file events use the independent audit channel described below. Structured POSIX errors remain fail-closed and never fall back to an unprepared executable.

## Key Migration

Normal startup never changes a key. An incorrect key reports that the existing image is unavailable and points callers to the explicit migration command:

```bash
agora-sandbox migrate-key \
  --workdir <WORKDIR>
```

The command interactively asks for the current key and the replacement key using visible text input. Keys are not accepted as migration command arguments. It renders milestone-based percentage progress while validating the keys, acquiring the filesystem lock, changing the APFS passphrase, mounting with the new key, updating metadata, and completing. The percentage represents completed migration stages because `hdiutil chpass` does not expose byte-level progress.

Migration takes the same exclusive lock, rejects identical keys, changes the APFS passphrase in place with `hdiutil chpass`, verifies the new key by mounting the existing image, rotates the random key ID, and preserves the volume ID and encrypted data. It does not recreate the sparse bundle, so existing files remain available after migration. The old key no longer mounts the volume after a successful migration.

The previous `clean` command is removed. The selected filesystem root, prepared executables, metadata, COW files, and whiteouts are persistent. Destructive reset requires explicit removal of the sparse bundle or plaintext root outside normal sandbox startup.

## Audit Events

The callback receives one unified `Event` containing `NetworkEvent`, `ProcessEvent`, or `FileEvent`. Event schema version 8 adds filesystem open and close events. The root command is launched directly by the runner and does not emit `process.exec.attempt`. Process and file events are audit-only: their callback decisions are ignored for now. Network decisions continue to allow, deny, or proxy a connection.

Hook-originated process and file events use an authenticated, versioned local audit channel independent of executable preparation and network proxying. Audit protocol version 1 carries the run trace, current process identity, and event-specific context. The host controller owns `sandbox_id`, `run_id`, event IDs, timestamps, and schema version, so the hook does not echo host-owned metadata. A malformed or unauthenticated audit connection is isolated to that connection. An unavailable audit controller fails a descendant launch or intercepted file operation instead of silently running without an event. Dynamic-loader file operations before hook initialization bypass virtualization and auditing so the injected library can initialize safely; user code begins only after initialization completes.

The filesystem hook publishes `filesystem.open` before calling native `open`, `openat`, or `fopen`. The event contains the logical pre-overlay path and a structured mode: `access` (`read`, `write`, or `read_write`) plus `create`, `truncate`, `append`, and `exclusive` flags. A successful open registers its native descriptor with that context. Intercepted `close` and `fclose` publish `filesystem.close` with the same path and mode before closing and then remove the descriptor mapping only after native close succeeds. This records attempts rather than post-operation outcomes; both event types currently use `result.status = started`. Descriptor duplication APIs and direct syscalls are outside the current hook surface.

The CLI writes compact JSON Lines records to the configured audit destination. Records use `type: "network"`, `type: "process"`, or `type: "filesystem"`. Filesystem records include operation, logical path, structured mode, PID, access time, and trace ID. A network record is written as soon as a validated connection attempt has been inspected, so it appears before a long-lived connection closes and includes a normalized domain when HTTP `Host` or TLS SNI supplied one. TLS passthrough exposes the domain but not the encrypted request path or body. A descendant process record includes the resolved executable, argument values, current directory, parent process, and execution operation. The hook records at most 256 arguments and replaces an omitted tail with `[truncated]`.

Every run starts with one trace ID in `AGORA_SANDBOX_TRACE_ID`. A hooked process appends one ID when it starts a descendant and forwards the chain as one comma-separated `trace_id` string, following the `X-Forwarded-For` style. Network CONNECT protocol version 7 and audit protocol version 1 carry the same chain, allowing process, file, and network events to be correlated. Event schema version 8 exposes the chain as a single `trace_id` string. A chain contains at most 32 entries; appending to a full chain removes the oldest entry.

Connection handlers are isolated from their listeners. A malformed or unauthenticated network, execution-control, or audit connection is rejected without terminating the controller or other sandbox work. If the audit controller itself exits, the runner terminates the child just as it does for network or execution-controller failure. On relay failure, the closing network event has failed status but retains all bytes successfully written in each direction before the error instead of reporting both counters as zero.

The macOS test suite includes a full transparent TLS path using a copied `/bin/bash`, system `/usr/bin/curl`, an automatically trusted sandbox CA, TLS interception, and a local HTTPS origin. The client does not receive an explicit `--cacert` argument.

## TLS Certificate Lifecycle

When TLS interception is enabled, the runner uses the explicitly configured CA paths or defaults to `<workdir>/ca/ca.crt` and `<workdir>/ca/ca.key`. If both files exist, it reuses them. If either file is missing, it generates a new pair at the selected paths and replaces the existing file, if any, as part of that regeneration. CA generation is part of sandbox startup; there is no separate CLI generation subcommand.

The runner publishes a CA-keyed `<workdir>/ca/trust-bundle-<fingerprint>.crt` to file-based client trust environment variables. This bundle contains the sandbox CA followed by the current native system roots, so a TLS connection that is not terminated by the sandbox—such as TLS nested inside an application-managed HTTP proxy tunnel—continues to validate its real peer certificate. If macOS cannot read any roots from the native trust store, the loader falls back to `/etc/ssl/cert.pem`; startup remains fail-closed when neither source provides a valid certificate. Different CA configurations sharing one work directory use different bundle files and do not overwrite each other.

Leaf certificates are valid for one day. DNS names are normalized with public-suffix awareness: subdomains use a wildcard for their registrable domain, registrable domains remain exact, and IP addresses remain exact. The certificate authority caches issued leaf certificates in memory for one hour and reuses a cached certificate while it remains valid.
