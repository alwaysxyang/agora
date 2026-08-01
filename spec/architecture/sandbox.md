# Sandbox Filesystem And Executable Preparation

`agora-sandbox` provides a process-tree-scoped, rootless filesystem view on macOS. Supported path operations read through to the host filesystem, while all materialized and modified data is stored in one persistent encrypted APFS volume. The original host paths are never modified. This guarantee applies only to processes that load the Agora hook library; executable preparation fails closed when a process cannot be made injectable.

## Work Directory

`SandboxConfig::new` defaults the sandbox work directory to `~/.agora-sandbox`, using the current process's `HOME`. The CLI accepts `--workdir <WORKDIR>`, and the library exposes `SandboxConfig::with_workdir`.

The AES-256 APFS sparse bundle is stored at `<workdir>/filesystem/fs.sparsebundle` and mounted at `<workdir>/fs`. It has a 100 GiB logical capacity and grows on demand. The encrypted mount mirrors absolute host paths: `/usr/bin/curl` maps to `<workdir>/fs/usr/bin/curl`, and `/Users/example/project/file` maps to `<workdir>/fs/Users/example/project/file`. Automatically managed TLS CA material remains outside the volume under `<workdir>/ca`.

The volume contains a reserved `<workdir>/fs/.agora` control directory for `volume.json`, the overlay lock, and directory metadata. Hooked processes cannot address this namespace, and directory enumeration hides it.

## Mandatory Encryption

Every sandbox run requires a filesystem passphrase through `--filesystem-key <KEY>` or `SandboxConfig::with_encrypted_workspace`. An absent, empty, NUL-containing, oversized, or incorrect key fails before the target process starts. There is no plaintext fallback. The passphrase has redacted `Debug` output and is sent to `hdiutil` through standard input; it is not injected into child arguments or environment. A CLI value remains visible in the parent process arguments and may be retained by shell history.

The first run creates the sparse bundle and writes a versioned random volume ID and key ID to `<workdir>/fs/.agora/volume.json`. Later runs reuse the same volume. Existing plaintext data in an unmounted `<workdir>/fs` is rejected rather than imported or overwritten. A non-blocking lock at `<workdir>/filesystem/fs.lock` permits only one run or key migration per work directory.

The volume is detached after the child, network controller, and execution controller stop. Detach retries tolerate the short vnode retention period after running copied Mach-O files, without using forced unmount. A synchronous best-effort detach also runs during error-path destruction.

## Copy-On-Write Overlay

The injected hook redirects `open`, `openat`, `fopen`, path metadata checks, access checks, mutations, current-directory operations, and directory enumeration. Returned file descriptors refer to native files in the encrypted APFS volume, so descriptor reads, writes, seeks, locks, `mmap`, and `fsync` retain kernel behavior without interposing `read` or `write`.

Reads prefer an existing encrypted entry. On a cache miss, a regular host file is copied into the encrypted mirror and marked `cached`. Its host MD5 is checked before reuse; a changed host file refreshes the encrypted cached copy. MD5 is only a change detector, not a security primitive.

A write-intent open copies an existing host file into the encrypted mirror before opening it and changes the state to `cow`. A newly created file is created only in the encrypted mirror and is also marked `cow`. COW entries remain authoritative and are never replaced when the host changes. Copy-on-write operates at whole-file granularity rather than block granularity.

Deletion removes the encrypted entry and records a `whiteout`, which hides any host entry with the same logical path. Rename moves only encrypted state. Directory enumeration lazily merges encrypted and host names, prefers encrypted entries, filters whiteouts, and never creates placeholder files for lower-only names.

Each logical directory has one versioned JSON record beneath `<workdir>/fs/.agora/metadata`. Entry names are encoded to support non-UTF-8 names and prevent path traversal. Entry states are `cached`, `cow`, or `whiteout`; cached entries also record their MD5 and whether they were materialized as a regular copy or prepared executable. Metadata and file publication use temporary paths and atomic rename while holding `<workdir>/fs/.agora/overlay.lock`.

## Executable Preparation

Injectable executables and shebang scripts can run from their visible paths. When SIP file flags, dyld restrictions, library validation, or Hardened Runtime prevent injection, the execution controller copies the compatible native architecture into the encrypted mirror, applies required Mach-O processing, and ad-hoc signs the result. A prepared executable is reused only while its encrypted copy remains executable and its recorded source MD5 matches.

The executable store and general filesystem overlay share the same mirrored tree and metadata. A regular cached file is upgraded through executable preparation before execution. A COW executable is never replaced with its lower host version; if its signature restricts injection, the COW copy is re-signed in place.

For a shebang script, the optional shebang argument and script path are inserted before caller arguments, and the interpreter goes through the same preparation pipeline. Descendant `posix_spawn` and `execve` calls use execution-preparation protocol version 4 and propagate the encrypted-root configuration. Structured POSIX errors remain fail-closed and never fall back to an unprepared executable.

## Key Migration

Normal startup never changes a key. An incorrect key reports that the existing image is unavailable and points callers to the explicit migration command:

```bash
agora-sandbox migrate-key \
  --workdir <WORKDIR> \
  --filesystem-key <OLD_KEY> \
  --new-filesystem-key <NEW_KEY>
```

Migration takes the same exclusive lock, rejects identical keys, changes the APFS passphrase in place with `hdiutil chpass`, verifies the new key by mounting the existing image, rotates the random key ID, and preserves the volume ID and encrypted data. The old key no longer mounts the volume after a successful migration.

The previous `clean` command is removed. The encrypted overlay, prepared executables, metadata, COW files, and whiteouts are persistent. Destructive reset requires explicit removal of the sparse bundle outside normal sandbox startup.

## Audit Timing

The callback receives a unified `Event` containing either a `NetworkEvent` or a `ProcessEvent`. Event schema version 7 includes intercepted descendant process execution attempts and exposes the trace ID chain as one `trace_id` string. The root command is launched directly by the runner and does not emit `process.exec.attempt`. Process events are audit-only: the callback decision is ignored for now. Network decisions continue to allow, deny, or proxy a connection.

The CLI writes compact JSON Lines records to the configured audit destination. Records use `type: "network"` or `type: "process"`. A network record is written as soon as a validated connection attempt has been inspected, so it appears before a long-lived connection closes and includes a normalized domain when HTTP `Host` or TLS SNI supplied one. TLS passthrough exposes the domain but not the encrypted request path or body. A descendant process record includes the resolved executable, argument values, current directory, parent process, and execution operation. The hook records at most 256 arguments. If the argument count or encoded command metadata exceeds the execution protocol budget, the retained argument prefix ends with `[truncated]`. Oversized audit metadata is truncated instead of causing an otherwise valid command to fail.

Every run starts with one trace ID in `AGORA_SANDBOX_TRACE_ID`. A hooked process appends one ID when it starts a descendant and forwards the chain as one comma-separated `trace_id` string, following the `X-Forwarded-For` style. Network CONNECT protocol version 7 requires the same string in `Agora-Trace-Id`, allowing process and network events to be correlated. Event schema version 7 exposes the chain as a single `trace_id` string. A chain contains at most 32 entries; appending to a full chain removes the oldest entry.

Connection handlers are isolated from their listeners. A malformed or unauthenticated network or execution-control connection is rejected without terminating the controller or other sandbox work. On relay failure, the closing network event has failed status but retains all bytes successfully written in each direction before the error instead of reporting both counters as zero.

The macOS test suite includes a full transparent TLS path using a copied `/bin/bash`, system `/usr/bin/curl`, an automatically trusted sandbox CA, TLS interception, and a local HTTPS origin. The client does not receive an explicit `--cacert` argument.

## TLS Certificate Lifecycle

When TLS interception is enabled, the runner uses the explicitly configured CA paths or defaults to `<workdir>/ca/ca.crt` and `<workdir>/ca/ca.key`. If both files exist, it reuses them. If either file is missing, it generates a new pair at the selected paths and replaces the existing file, if any, as part of that regeneration. CA generation is part of sandbox startup; there is no separate CLI generation subcommand.

The runner publishes a CA-keyed `<workdir>/ca/trust-bundle-<fingerprint>.crt` to file-based client trust environment variables. This bundle contains the sandbox CA followed by the current native system roots, so a TLS connection that is not terminated by the sandbox—such as TLS nested inside an application-managed HTTP proxy tunnel—continues to validate its real peer certificate. If macOS cannot read any roots from the native trust store, the loader falls back to `/etc/ssl/cert.pem`; startup remains fail-closed when neither source provides a valid certificate. Different CA configurations sharing one work directory use different bundle files and do not overwrite each other.

Leaf certificates are valid for one day. DNS names are normalized with public-suffix awareness: subdomains use a wildcard for their registrable domain, registrable domains remain exact, and IP addresses remain exact. The certificate authority caches issued leaf certificates in memory for one hour and reuses a cached certificate while it remains valid.
