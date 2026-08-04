# macOS Keychain Isolation Design

## Goal

Prevent every process in an Agora sandbox from reading or mutating the host user's macOS Keychain,
while preserving Lark CLI operation through its supported file-backed master-key mode.

## Boundary

The existing DYLD hook is a cooperative filesystem and network boundary. Security.framework talks
to Keychain daemons over Mach services, so filesystem COW cannot isolate `SecItemAdd`,
`SecItemUpdate`, or `SecItemDelete`. Interposing individual Security.framework functions would be
bypassable through other APIs, the `security` command, direct XPC, or a process that does not import
the same symbols.

The runner therefore installs a minimal native macOS Seatbelt profile in the root child immediately
before `exec`. The profile allows existing behavior by default and denies Mach lookup for the
Keychain service endpoints used by current macOS releases:

- `com.apple.SecurityServer`
- `com.apple.securityd`
- `com.apple.securityd.xpc`
- `com.apple.securityd.general`
- `com.apple.securityd.systemkeychain`

Seatbelt restrictions are inherited across `exec`, `posix_spawn`, and forked descendants. The
runner and its proxy, execution, and audit controllers remain outside this profile.

## Failure Semantics

Installing the native policy is mandatory on macOS. If profile compilation or installation fails,
the pre-exec hook fails and the sandbox child is not started. There is no warning-only fallback that
would silently restore host Keychain access.

The policy is intentionally limited to Keychain Mach services. It does not claim strict network or
full host-service containment, and it does not change the existing filesystem hook boundary.

## Lark CLI Compatibility

Lark CLI's supported `config keychain-downgrade` operation materializes its master key in a local
file for sandbox and automation use. That one-time operation must be performed interactively outside
the sandbox. Agora never runs it automatically because it changes credential-at-rest protection.

When the file backend is already present, Lark credential and token files are ordinary logical-home
files. Reads use the lower view and any refresh or update is contained by the encrypted COW layer.
Lark commands do not require access to the denied Keychain services.

## Verification

- A child-side Mach bootstrap probe must confirm that `com.apple.SecurityServer` lookup is denied.
- The same sandbox child must retain ordinary process, filesystem, loopback-controller, and TLS
  behavior.
- A sandboxed Lark read/export must use the existing file backend without invoking an auth mutation
  command.
- The exact Codex prompt supplied by the user must generate the Lark command, export the document to
  the sandboxed home, and observe it immediately through `ls`.
- Before and after acceptance, non-secret host credential file identities and modification times
  must remain unchanged. No test may print or copy credential contents.
