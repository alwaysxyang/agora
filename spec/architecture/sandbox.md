# Sandbox Executable Root

`agora-sandbox` runs injectable executables and shebang scripts from their original paths. When an executable cannot receive `DYLD_INSERT_LIBRARIES` because either System Integrity Protection enforces its macOS `SF_RESTRICTED` file flag or its code-signing flags require dyld restriction, library validation, or Hardened Runtime, the sandbox runs a copied, ad-hoc-signed native-architecture slice instead. Prepared copies are persistent and reusable across sandbox runs.

## Work Directory

`SandboxConfig::new` defaults the sandbox work directory to `~/.agora-sandbox`, using the current process's `HOME`. The CLI accepts `--workdir <WORKDIR>` to override it, and the library exposes `SandboxConfig::with_workdir` for the same purpose. Prepared executables live under `<workdir>/root`, while automatically managed TLS CA material lives under `<workdir>/ca`.

The sandbox creates the executable root and missing parents when execution starts and sets `<workdir>/root` mode to `0700`. It does not remove the root or prepared files when a run exits. The root may contain only its lock file when a run uses no non-injectable executable.

## Cache Entries

A prepared non-injectable executable mirrors its canonical absolute source path beneath `<workdir>/root`. For example, `/usr/bin/curl` is stored as `<workdir>/root/usr/bin/curl`. Executables that are neither SIP-restricted nor signed with dyld-restricting flags are returned at their canonical original paths without checksumming, copying, architecture processing, or signing. The sandbox creates the parent directory structure for a copied executable but does not recursively copy the source directory.

For a shebang script, the sandbox keeps the script at its canonical original path and launches the interpreter named after `#!` explicitly. The optional shebang argument and script path are inserted before the caller's arguments. The interpreter goes through the same injection check, so `/usr/bin/env` or `/bin/sh` is copied when restricted, while an injectable interpreter such as a Homebrew `node` or `python3` remains at its original path. This preserves hook injection across a restricted shebang interpreter without treating the text script as Mach-O.

Each mapped source directory contains its own versioned `checksums.json` manifest. Its `files` object maps canonical source paths in that directory to the MD5 of each source executable before architecture selection and ad-hoc signing. For example, `<workdir>/root/usr/bin/checksums.json` contains:

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

`agora-sandbox clean [--workdir <WORKDIR>]` recursively removes `<workdir>/root` while retaining the work directory and its TLS CA material. It does not require a command, hook library, audit output, or TLS configuration. When `--workdir` is omitted, it removes `~/.agora-sandbox/root`. A missing root is treated as already clean. The command does not lock, inspect, selectively retain, or recreate executable-root content.

## Concurrent Runs

Every sandbox opens `<workdir>/root/.lock`. Preparing a non-injectable executable takes an exclusive `flock` while reading the destination directory's manifest, checking and publishing one mapped executable, and updating that manifest. Injectable executables and scripts do not take this lock after their executable metadata, code-signing flags, and shebang have been inspected. Each manifest is written to a fixed temporary file in its mapped directory and atomically renamed to `checksums.json`. The lock is released immediately after preparation and automatically when a process exits unexpectedly.

## Audit Timing

The CLI writes one compact audit record as soon as a validated connection attempt has been inspected. The record therefore appears before a long-lived connection closes and includes a normalized domain when HTTP `Host` or TLS SNI supplied one. TLS passthrough exposes the domain but not the encrypted request path or body.

## TLS Certificate Lifecycle

When TLS interception is enabled, the runner uses the explicitly configured CA paths or defaults to `<workdir>/ca/ca.crt` and `<workdir>/ca/ca.key`. If both files exist, it reuses them. If either file is missing, it generates a new pair at the selected paths and replaces the existing file, if any, as part of that regeneration. CA generation is part of sandbox startup; there is no separate CLI generation subcommand.

The runner publishes a CA-keyed `<workdir>/ca/trust-bundle-<fingerprint>.crt` to file-based client trust environment variables. This bundle contains the sandbox CA followed by the current native system roots, so a TLS connection that is not terminated by the sandbox—such as TLS nested inside an application-managed HTTP proxy tunnel—continues to validate its real peer certificate. Different CA configurations sharing one work directory use different bundle files and do not overwrite each other.

Leaf certificates are valid for one day. DNS names are normalized with public-suffix awareness: subdomains use a wildcard for their registrable domain, registrable domains remain exact, and IP addresses remain exact. The certificate authority caches issued leaf certificates in memory for one hour and reuses a cached certificate while it remains valid.
