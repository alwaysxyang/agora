# Overlay Reconciliation And Keychain Passthrough Design

## Goal

Make external removal of sandbox upper data deterministic: the next sandbox access discards stale
upper state and falls through to the lower host path. At the same time, remove the native macOS
Keychain denial so sandboxed tools use the current user's Keychain exactly as they do outside the
sandbox.

This change starts from a new workspace. Existing `<workdir>/fs` data is deliberately deleted and
is not migrated.

## Scope

- Require a continuous managed-directory marker chain for every upper directory.
- Reconcile missing COW/cache backing objects and unrecorded upper objects lazily during access.
- Preserve whiteouts and valid attribute-only lower overrides.
- Invalidate descendant metadata caches when an externally removed directory breaks the marker
  chain.
- Remove the native Keychain-denial profile and all claims that host Keychain access is isolated.
- Verify Lark CLI against both a clean workspace and a workspace whose upper Lark paths have been
  removed externally.

The design does not add filesystem monitoring, a compatibility migration, Keychain COW, or an
application-specific Lark CLI path.

## Directory Trust Invariant

`<workdir>/fs/.metadata` is the root marker. Every physical upper directory below the root must
contain its own valid `.metadata` file, including directories that exist only to merge child upper
entries with a lower directory. The marker chain from the filesystem root to a physical upper
object must be continuous.

A directory's marker is not a `cow` entry. A `cow` directory hides the corresponding lower
subtree, while a marked merge directory continues to merge lower and upper children. Empty version
3 metadata is therefore a valid managed-directory marker.

If any directory in the chain is physically present without a valid marker, that directory and its
entire upper subtree are untrusted. Child metadata cannot make an unmarked parent trustworthy.
After acquiring the VFS transaction lock, the overlay removes the untrusted subtree, invalidates
the shared metadata generation, and falls through to lower. Failure to remove the subtree fails the
operation rather than exposing a partly reconciled view.

All upper-directory creation paths create and sync the directory marker before publishing child
state. Existing marked empty merge directories may remain because they do not shadow lower data.

## Entry Reconciliation

Reconciliation happens under `.vfs.lock` before upper state is used:

- `cow` plus a present upper object remains authoritative.
- `cow` plus a missing upper object is stale. Remove its entry state, logical attributes,
  encrypted-name reservation, and detached write lease, publish metadata, then use lower.
- `cached` plus a missing upper object is stale non-authoritative cache. Remove its record and use
  lower.
- `whiteout` plus no upper object is valid and continues to hide lower.
- `whiteout` plus an upper object keeps the whiteout and removes the unexpected upper object.
- An attribute-only record without an upper object remains valid because logical chmod-style
  overrides apply to lower data without copy-up.
- A regular file or symlink physically present in a marked upper directory without a matching
  metadata record is an orphan. Remove it and use lower.
- A physical directory without its own marker is an orphan subtree even if a descendant contains a
  plausible `.metadata` file. Remove the subtree and use lower.

Encrypted file reconciliation removes the existing lease sidecar before clearing metadata so an
older anonymous writable snapshot cannot recreate an externally removed name during later
writeback. Reconciliation uses the existing atomic metadata publication and generation update
path. External mutations racing an active operation remain outside the cooperative sandbox's hard
security boundary, but the first observed stable mismatch converges to lower.

## Cache Invalidation

The shared metadata generation remains the fast invalidation path for normal sandbox mutations.
Because external deletion does not advance that generation, cached metadata must also retain and
validate the physical marker identity used to load it. A missing or replaced marker invalidates
that directory and all cached descendants. The process that observes the mismatch advances the
shared generation so other descendants discard their cached state.

Validation is lazy. Startup does not recursively scan the complete workspace. Native lower reads
that require no overlay state retain the existing fast path; marker checks occur only while an
operation is already consulting or enumerating upper state.

## Keychain Behavior

The runner installs no native Keychain-denial profile. No Keychain API is intercepted or virtualized.
Sandbox descendants use the host user's Keychain directly, including reads, refreshes, updates, and
deletes. A Keychain mutation inside the sandbox therefore has the same host-visible effect as the
same command outside the sandbox.

Lark CLI configuration under `~/.lark-cli`, credential files under
`~/Library/Application Support/lark-cli`, and the macOS Keychain are separate state sources.
Removing only the upper `.lark-cli` directory resets that filesystem subtree but does not replace
the credential directory or Keychain. With a clean marker chain and Keychain passthrough, untouched
paths read all three sources from the host.

## Workspace Reset

There is no compatibility migration. Before acceptance testing, stop every sandbox using the
default work directory, resolve the exact target as `<resolved HOME>/.agora-sandbox/fs`, report that
target, and delete it. The next run creates a new root marker and only the new directory invariants
apply. Other configured or temporary work directories are not deleted implicitly.

## Error Handling

- Invalid metadata in an otherwise continuous marker chain remains a hard error; it is not treated
  as an absent marker.
- A reconciliation cleanup failure returns the native error and does not fall through to lower.
- A missing/replaced marker or backing object is repaired only while holding `.vfs.lock`.
- Whiteouts are never removed by automatic reconciliation.
- Control files, temporary publication files, key files, locks, and write leases are handled by
  their existing control-file rules rather than classified as business-file orphans.

## Verification

Automated coverage must include:

- every created upper directory has a continuous valid marker chain;
- a child marker below an unmarked parent is ignored and the subtree is removed;
- externally removing a COW regular file clears its record and reveals lower in the same process;
- externally removing a COW directory clears stale state and reveals the lower directory;
- externally removing a cached backing copy clears only the cache and reveals lower;
- a whiteout without backing remains effective;
- an orphan regular file, symlink, or unmarked directory is removed and does not shadow lower;
- attribute-only lower overrides remain effective;
- external marker deletion invalidates cached descendant metadata across descendants;
- encrypted stale-writer writeback cannot recreate a reconciled path;
- directory enumeration and macOS FTS traversal expose the reconciled lower view;
- the sandbox child can look up the normal macOS Keychain Mach service after profile removal;
- existing filesystem, executable preparation, TLS, audit, and `/dev` passthrough tests remain
  green.

Manual acceptance must compare host and sandbox `lark-cli auth status --json --verify`, then execute
the exact user-supplied Codex/Lark export prompt in a fresh default workspace. The export must
succeed, the downloaded file must be visible immediately inside the sandbox, and Codex startup must
not report Keychain, arg0, PATH-alias, Bash, or MCP initialization errors. No credential contents may
be printed or persisted in repository fixtures.
