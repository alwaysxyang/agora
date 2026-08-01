# Sandbox Executable Cache

`agora-sandbox` runs injectable executables and shebang scripts from their original paths. When an executable cannot receive `DYLD_INSERT_LIBRARIES` because either System Integrity Protection enforces its macOS `SF_RESTRICTED` file flag or its code-signing flags require dyld restriction, library validation, or Hardened Runtime, the sandbox runs a copied, ad-hoc-signed native-architecture slice instead. Prepared copies are persistent and reusable across sandbox runs.

## Work Directory

`SandboxConfig::new` defaults the sandbox work directory to `~/.agora-sandbox`, using the current process's `HOME`. The CLI accepts `--workdir <WORKDIR>` to override it, and the library exposes `SandboxConfig::with_workdir` for the same purpose. Prepared executables live under `<workdir>/fs`, while automatically managed TLS CA material lives under `<workdir>/ca`.

The sandbox creates the executable cache and missing parents when execution starts and sets `<workdir>/fs` mode to `0700`. It does not remove the cache or prepared files when a run exits. The cache may contain only its lock file when a run uses no non-injectable executable. A legacy `<workdir>/root` directory is left untouched.

## Encrypted Workspace

The optional `--filesystem-key <KEY>` CLI argument and `SandboxConfig::with_encrypted_workspace` library method enable a persistent encrypted workspace on macOS. The value is an APFS disk-image passphrase rather than a raw AES key. An empty key, a NUL byte, or a key larger than 64 KiB is rejected. The passphrase is retained in memory with redacted `Debug` output and is sent only to `hdiutil` through its standard input; it is not added to the sandbox child's arguments or environment. The CLI value remains visible in the `agora-sandbox` process arguments and may be retained by shell history, so callers must account for that exposure.

The sandbox stores the AES-256 APFS sparse bundle at `<workdir>/filesystem/workspace.sparsebundle`, its source metadata at `<workdir>/filesystem/workspace.json`, and its temporary mount at `<workdir>/filesystem/mount`. The sparse bundle has a 100 GiB logical capacity and grows on demand. The first run copies the command's canonical current directory into a matching absolute-path mirror inside the encrypted volume. For example, `/Users/example/project` is copied to `<mount>/Users/example/project`. The command then runs with that encrypted mirror as its current directory. The original source directory is not modified, and later runs with the same work directory and key reuse the volume and retain prior changes.

An existing encrypted workspace is bound to its original source directory. A different source or key fails closed instead of recreating or rotating the volume. The sandbox work directory must not be inside the source directory. An exclusive non-blocking lock permits only one encrypted-workspace run per sandbox work directory. The volume is detached after the child and sandbox services stop; a synchronous detach is also attempted if startup or execution exits through an error path.

This first stage provides native filesystem behavior and transparent APFS encryption for accesses relative to the relocated current directory. It is a persistent encrypted snapshot, not a complete overlay filesystem: source changes after initialization are not merged, deletions are not represented as whiteouts, and absolute paths that explicitly refer to the original source are not redirected. The mounted volume is also accessible to the same host user while the run is active. Full lower/upper copy-on-write path virtualization remains a separate filesystem-backend concern.

The encrypted workspace is independent of the executable cache. `agora-sandbox clean` continues to remove only executable copies recorded beneath `<workdir>/fs`; it does not remove the sparse bundle, source metadata, TLS material, or encrypted workspace contents.

## Cache Entries

A prepared non-injectable executable mirrors its canonical absolute source path beneath `<workdir>/fs`. For example, `/usr/bin/curl` is stored as `<workdir>/fs/usr/bin/curl`. Executables that are neither SIP-restricted nor signed with dyld-restricting flags are returned at their canonical original paths without checksumming, copying, architecture processing, or signing. The sandbox creates the parent directory structure for a copied executable but does not recursively copy the source directory.

When a relocated executable derives a missing sibling path from its own executable location, the execution controller maps that path from `<workdir>/fs/<absolute-path>` back to `/<absolute-path>` and prepares the original sibling on demand. Existing cache files continue to resolve directly. This preserves `current_exe`-relative helper discovery without recursively copying or interpreting the executable's source directory.

For a shebang script, the sandbox keeps the script at its canonical original path and launches the interpreter named after `#!` explicitly. The optional shebang argument and script path are inserted before the caller's arguments. The interpreter goes through the same injection check, so `/usr/bin/env` or `/bin/sh` is copied when restricted, while an injectable interpreter such as a Homebrew `node` or `python3` remains at its original path. This preserves hook injection across a restricted shebang interpreter without treating the text script as Mach-O.

Each mapped source directory contains its own versioned `checksums.json` manifest. Its `files` object maps canonical source paths in that directory to the MD5 of each source executable before architecture selection and ad-hoc signing. For example, `<workdir>/fs/usr/bin/checksums.json` contains:

```json
{
  "version": 1,
  "files": {
    "/usr/bin/curl": "d41d8cd98f00b204e9800998ecf8427e"
  }
}
```

A prepared non-injectable executable is reused only when it exists, remains executable, and its manifest entry matches the current source MD5. A missing executable, missing manifest, missing entry, or mismatched MD5 causes the executable to be copied, processed, and signed again before the manifest is updated. An unreadable, malformed, or unsupported manifest returns an error instead of silently discarding existing records.

Prepared executables and their directory-local `checksums.json` manifests are persistent. The sandbox does not impose an entry limit and does not automatically prune them.

## Cleaning

`agora-sandbox clean [--workdir <WORKDIR>]` recursively discovers the directory-local `checksums.json` manifests beneath `<workdir>/fs` and removes only the prepared executable copies recorded by those manifests. It then removes the processed manifests and any mapped directories left empty, while retaining `<workdir>/fs`, its lock file, unregistered filesystem content, the work directory, legacy `<workdir>/root` content, and TLS CA material. Every manifest entry must be an absolute source path whose mapped destination belongs to the manifest's own directory; malformed, unsupported, or cross-directory entries fail the command before any manifest cleanup begins.

The command does not require a sandbox command, hook library, audit output, or TLS configuration. When `--workdir` is omitted, it cleans `~/.agora-sandbox/fs`. A missing cache is treated as already clean. Cleaning takes the same exclusive `<workdir>/fs/.lock` used during executable preparation, so it cannot race a concurrent manifest update.

## Concurrent Runs

Every sandbox opens `<workdir>/fs/.lock`. Preparing a non-injectable executable takes an exclusive `flock` while reading the destination directory's manifest, checking and publishing one mapped executable, and updating that manifest. Injectable executables and scripts do not take this lock after their executable metadata, code-signing flags, and shebang have been inspected. Each manifest is written to a fixed temporary file in its mapped directory and atomically renamed to `checksums.json`. The lock is released immediately after preparation and automatically when a process exits unexpectedly.

Execution-preparation protocol version 4 returns a structured POSIX errno with every error and carries bounded process audit metadata, including the single XFF-style `trace_id` string. Process hooks preserve error codes through `posix_spawn` or `execve`; missing paths therefore remain `ENOENT`, invalid arguments remain `EINVAL`, and policy failures remain `EACCES`. Preparation and protocol failures remain fail-closed and never fall back to executing the unprepared source.

## Audit Timing

The callback receives a unified `Event` containing either a `NetworkEvent` or a `ProcessEvent`. Event schema version 7 includes process execution attempts and exposes the trace ID chain as one `trace_id` string. Process events are audit-only: the callback decision is ignored for now. Network decisions continue to allow, deny, or proxy a connection.

The CLI writes compact JSON Lines records to the configured audit destination. Records use `type: "network"` or `type: "process"`. A network record is written as soon as a validated connection attempt has been inspected, so it appears before a long-lived connection closes and includes a normalized domain when HTTP `Host` or TLS SNI supplied one. TLS passthrough exposes the domain but not the encrypted request path or body. A process record includes the resolved executable, argument values, current directory, parent process, and execution operation. The hook records at most 256 arguments. If the argument count or encoded command metadata exceeds the execution protocol budget, the retained argument prefix ends with `[truncated]`. Oversized audit metadata is truncated instead of causing an otherwise valid command to fail.

Every run starts with one trace ID in `AGORA_SANDBOX_TRACE_ID`. A hooked process appends one ID when it starts a descendant and forwards the chain as one comma-separated `trace_id` string, following the `X-Forwarded-For` style. Network CONNECT protocol version 7 requires the same string in `Agora-Trace-Id`, allowing process and network events to be correlated. Event schema version 7 exposes the chain as a single `trace_id` string. A chain contains at most 32 entries; appending to a full chain removes the oldest entry.

Connection handlers are isolated from their listeners. A malformed or unauthenticated network or execution-control connection is rejected without terminating the controller or other sandbox work. On relay failure, the closing network event has failed status but retains all bytes successfully written in each direction before the error instead of reporting both counters as zero.

The macOS test suite includes a full transparent TLS path using a copied `/bin/bash`, system `/usr/bin/curl`, an automatically trusted sandbox CA, TLS interception, and a local HTTPS origin. The client does not receive an explicit `--cacert` argument.

## TLS Certificate Lifecycle

When TLS interception is enabled, the runner uses the explicitly configured CA paths or defaults to `<workdir>/ca/ca.crt` and `<workdir>/ca/ca.key`. If both files exist, it reuses them. If either file is missing, it generates a new pair at the selected paths and replaces the existing file, if any, as part of that regeneration. CA generation is part of sandbox startup; there is no separate CLI generation subcommand.

The runner publishes a CA-keyed `<workdir>/ca/trust-bundle-<fingerprint>.crt` to file-based client trust environment variables. This bundle contains the sandbox CA followed by the current native system roots, so a TLS connection that is not terminated by the sandbox—such as TLS nested inside an application-managed HTTP proxy tunnel—continues to validate its real peer certificate. Different CA configurations sharing one work directory use different bundle files and do not overwrite each other.

Leaf certificates are valid for one day. DNS names are normalized with public-suffix awareness: subdomains use a wildcard for their registrable domain, registrable domains remain exact, and IP addresses remain exact. The certificate authority caches issued leaf certificates in memory for one hour and reuses a cached certificate while it remains valid.
