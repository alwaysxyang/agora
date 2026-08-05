# Hook Module Directory Layout Design

## Status

Approved for implementation on 2026-08-05.

## Goal

Make the macOS hook source layout reflect its global lifecycle, filesystem, network, and process
ownership boundaries without changing runtime behavior, exported symbols, initialization order,
or public APIs.

## Scope

- Move the filesystem hook module root from `hook/filesystem.rs` to `hook/filesystem/mod.rs`.
- Move `hook/filesystem_shim.c` beside the filesystem hook implementation as
  `hook/filesystem/filesystem_shim.c`.
- Group the network interception, socket-address helpers, and TLS trust hooks under
  `hook/network/`.
- Use directory module roots for process and TLS trust hooks because both own nested test modules.
- Move the shared macOS `set_errno` helper to `hook/mod.rs` so filesystem and process hooks do not
  depend on a network child module for generic error handling.
- Move global hook initialization state, config/filesystem startup, and exit flushing to
  `hook/mod.rs` so sibling domains do not depend on network lifecycle state.
- Update Rust module references, the C build input path, tests, and architecture documentation.

The crate-level `src/network/` controller remains unchanged. Hook configuration and shared dyld
support remain direct leaf modules under `hook`.

## Target Layout

```text
crates/agora-sandbox/src/hook/
├── mod.rs
├── config.rs
├── dyld.rs
├── tests.rs
├── process/
│   ├── mod.rs
│   └── tests.rs
├── filesystem/
│   ├── mod.rs
│   ├── filesystem_shim.c
│   ├── descriptor.rs
│   ├── metadata.rs
│   ├── namespace.rs
│   ├── open.rs
│   ├── unsupported.rs
│   ├── tests.rs
│   └── directory/
│       ├── mod.rs
│       └── fts.rs
└── network/
    ├── mod.rs
    ├── socket.rs
    ├── tests.rs
    └── trust/
        ├── mod.rs
        └── tests.rs
```

## Module Responsibilities

`hook/filesystem/mod.rs` remains the filesystem hook facade and shared runtime. Its existing child
modules continue to own complete libc operation families. The C shim remains an implementation
detail of that same module and is compiled from its new path by `build.rs`.

`hook/network/mod.rs` owns `connect`/`connectx` interception and its network recursion guard. Its
`socket` child owns raw socket address conversion, and its `trust` child owns Security.framework
trust interception. Their tests move with the corresponding modules. `hook/process/mod.rs` owns
process execution interposition and its existing child tests.

`hook/mod.rs` owns the global dylib initializer, initialized flag, config/filesystem startup,
filesystem exit flush registration, and the generic macOS errno setter shared by filesystem,
network, and process hooks. This prevents filesystem or process hooks from depending on network
state for global lifecycle or platform error handling. No general-purpose utility module is
introduced.

## Compatibility

The move preserves:

- every `agora_sandbox_*` exported symbol and C signature;
- every `dyld_interpose!` registration and initialization sequence;
- filesystem, process, socket, and trust-hook behavior;
- native `/dev` passthrough, overlay reconciliation, permission handling, and audit behavior;
- network routing and TLS trust-anchor injection;
- Cargo features, dependencies, public APIs, and configuration.

Only Rust module paths, source locations, private lifecycle ownership, test module paths, and the
`cc::Build` input path change.

## Error Handling

The shared `set_errno` implementation is moved byte-for-byte to `hook/mod.rs` under the existing
macOS target guard. Call sites use the parent helper and retain their current errno mapping. Moving
the C shim changes no compile flags or fallback behavior; a missing or invalid source path remains a
build failure.

## Verification

- Compare the pre-move and post-move `agora_sandbox_*` source symbol inventories.
- Confirm global initialization and exit-flush ownership live only in `hook/mod.rs`.
- Run `cargo fmt --all -- --check` and `git diff --check`.
- Run focused filesystem, network-interpose, trust, and process hook tests.
- Run workspace all-target tests and Clippy with warnings denied.
- Run a workspace release build.
- Run workspace coverage with the required 90 percent line threshold.
- Confirm `spec/architecture/sandbox.md` describes the directory-based hook ownership accurately.
