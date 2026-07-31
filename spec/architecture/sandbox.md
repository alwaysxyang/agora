# Sandbox Executable Root

`agora-sandbox` runs a copied, ad-hoc-signed executable so the process hook can prepare every subsequently executed image through the same controller. Prepared executable copies are persistent and reusable across sandbox runs.

## Work Directory

`SandboxConfig::new` defaults the executable root to `~/.agora-sandbox/root`, using the current process's `HOME`. The CLI accepts `--workdir <WORKDIR>` to override it, and the library exposes `SandboxConfig::with_workdir` for the same purpose.

The sandbox creates the root and missing parents when execution starts and sets the root mode to `0700`. It does not remove the root or prepared files when a run exits.

## Cache Entries

A prepared executable mirrors its canonical absolute source path beneath the configured root. For example, `/usr/bin/curl` is stored as `<workdir>/usr/bin/curl`. Only an executable that is requested by the initial command or a hooked child process is copied; the sandbox creates its parent directory structure but does not recursively copy the source directory.

The root contains one versioned `checksums.json` manifest. Its `files` object maps each canonical source path to the MD5 of that source executable before architecture selection and ad-hoc signing. For example:

```json
{
  "version": 1,
  "files": {
    "/usr/bin/curl": "d41d8cd98f00b204e9800998ecf8427e"
  }
}
```

A prepared executable is reused only when it exists, remains executable, and its manifest entry matches the current source MD5. A missing executable, missing manifest, missing entry, or mismatched MD5 causes the executable to be copied, processed, and signed again before the manifest is updated. An unreadable, malformed, or unsupported manifest returns an error instead of silently discarding existing records.

Prepared executables and `checksums.json` are persistent. The sandbox does not impose an entry limit and does not automatically prune them.

## Cleaning

`agora-sandbox clean [--workdir <WORKDIR>]` recursively removes the complete executable root. It does not require a command, hook library, audit output, or TLS configuration. When `--workdir` is omitted, it removes `~/.agora-sandbox/root`. A missing root is treated as already clean. The command does not lock, inspect, selectively retain, or recreate any content.

## Concurrent Runs

Every sandbox opens `<workdir>/.lock`. Executable preparation takes an exclusive `flock` while reading the manifest, checking and publishing one mapped executable, and updating the manifest. The manifest is written to a fixed temporary file and atomically renamed to `checksums.json`. The lock is released immediately after preparation and automatically when a process exits unexpectedly.

## TLS Certificate Lifecycle

When TLS interception is enabled and no CA paths are configured, the runner uses `<command-workdir>/ca/ca.pem` and `<command-workdir>/ca/ca-key.pem`. It reuses an existing complete pair. If either file is missing, it generates a new pair and replaces the other file as part of that regeneration.

Leaf certificates are valid for one day. DNS names are normalized with public-suffix awareness: subdomains use a wildcard for their registrable domain, registrable domains remain exact, and IP addresses remain exact. The certificate authority caches issued leaf certificates in memory for one hour and reuses a cached certificate while it remains valid.
