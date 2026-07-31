# Sandbox Executable Cache

`agora-sandbox` runs a copied, ad-hoc-signed executable so the process hook can prepare every subsequently executed image through the same controller. Prepared executable copies are persistent and reusable across sandbox runs.

## Work Directory

`SandboxConfig::new` defaults the executable cache directory to `~/.agora-sandbox/bin`, using the current process's `HOME`. The CLI accepts `--workdir <WORKDIR>` to override it, and the library exposes `SandboxConfig::with_workdir` for the same purpose.

The sandbox creates the directory and missing parents when execution starts and sets the cache directory mode to `0700`. It does not remove the directory when a run exits.

## Cache Entries

A prepared executable name begins with `cache-v1-` and is derived from the canonical source file's filesystem identity, size, timestamps, native architecture, and sanitized source name. An executable cache entry with the same name is reused by later runs. Preparation writes to a unique temporary file and publishes the signed copy with an atomic rename.

The cache retains at most 10 prepared executable entries after cleanup. When more than 10 entries exist, cleanup removes arbitrary excess entries rather than ordering them by age. The `.lock` file, preparation temporary files, and unrelated files are not counted or removed.

## Concurrent Runs

Every running sandbox opens `<workdir>/.lock` and holds a shared `flock` for the lifetime of its execution controller. Normal shutdown releases that run's shared lock and attempts to acquire a non-blocking exclusive lock.

If the exclusive lock cannot be acquired because another sandbox still holds a shared lock, the exiting sandbox skips cleanup entirely. If it acquires the exclusive lock, no other sandbox is running against that work directory, so it prunes arbitrary excess cache entries down to 10 and then releases the lock. The lock is also released automatically when a process exits unexpectedly, but unexpected shutdown does not perform cache cleanup.
