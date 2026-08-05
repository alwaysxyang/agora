# Overlay Realpath And Export Visibility Design

> **Compatibility update:** Automatic version-1/version-2 startup migration was superseded by
> [Overlay Reconciliation And Keychain Passthrough Design](2026-08-04-overlay-reconciliation-keychain-passthrough-design.md).
> The decoder remains available for direct legacy reads, but normal startup does not scan or
> rewrite legacy trees; deployments use a fresh `<workdir>/fs`.

## Problem

An encrypted upper-only path is visible through hooked `stat`, directory enumeration, and access checks, but macOS `realpath` still resolves only the host lower filesystem. A caller such as Codex can therefore create or observe a path in the sandbox and immediately receive `ENOENT` from `std::fs::canonicalize`. A persistent Codex workdir contains enough upper-only state to trigger this during TUI startup, while a fresh workdir may not.

BSD `mkdir -p` also probes existing path prefixes by calling `mkdir`. The current hook checks parent mutation permission before determining that the requested directory already exists, so `mkdir("/Users", ...)` returns `EACCES` instead of `EEXIST`; `mkdir -p` then stops even though the final child would be writable.

macOS FTS uses `getattrlistbulk` for directory enumeration before falling back to `opendir` and `readdir`. The current FTS adapter can filter native lower entries after `fts_read` or `fts_children`, but it cannot add upper-only entries that were absent from that native result. Consequently a newly written file succeeds through direct lookup and can be read with `cat`, while `/bin/ls` omits it.

The Lark export reported alongside this bug is stored correctly but was requested with `--output-dir .`. Its logical destination is therefore the caller's current directory, not `~/`. The current metadata version still exposes that logical filename as a map key even though the physical file uses an unrelated random alias. Encrypted business filenames must instead be encrypted directly: the filename ciphertext must be opaque in both the backing directory and `.metadata`, with no separate alias mapping.

## Storage Invariants

- Metadata version 3 removes the persisted `backing_names` map. Each directory has one `entries` record map, and a record may contain entry state and logical attributes.
- Encrypted COW regular files and symlinks authenticate-encrypt the original logical leaf bytes. The resulting `enc_` token is both the record key and physical leaf name; there is no separately generated alias or encrypted `name` field. A random nonce inside the ciphertext prevents deterministic encryption without changing this identity invariant.
- A reserved encrypted filename ciphertext is represented by a record even before COW state commits, so `O_CREAT|O_EXCL` remains atomic across VFS instances.
- Encrypted file whiteouts retain their ciphertext record key after physical ciphertext removal, so deletion does not re-expose the business filename. Directory entries and controller-managed plaintext executable caches retain mirrored physical names.
- Plain COW files keep their logical leaf names as both record keys and physical names. Names beginning with reserved metadata prefixes are losslessly escaped rather than encrypted.
- Metadata versions 1 and 2 remain directly readable, but Overlay startup does not recursively scan or migrate them. Existing deployments start version 3 with a fresh `<workdir>/fs`.
- A sandbox-visible export never creates the logical plaintext path on the host lower filesystem.

These rules make the metadata record key agree with the physical filename while keeping encrypted business names out of both places.

## Selected Approach

Add an Overlay-aware canonical-path operation and interpose macOS `realpath`. The VFS resolves the requested logical path, including Overlay symlinks and host aliases, verifies that the final entry is visible, and returns a canonical logical path. The hook implements both caller-provided-buffer and null-buffer allocation behavior without exposing the physical workdir.

Upgrade metadata persistence independently of the in-memory logical lookup maps. `MetadataStore` receives the optional filesystem cipher. In encrypted mode it seals the logical leaf bytes with a distinct filename-encryption domain and random nonce, then uses that ciphertext token directly as both the record key and physical name. Loading decrypts the record key, validates unique logical and physical identities, and reconstructs the existing logical lookup maps. This keeps Overlay call sites focused while avoiding deterministic filename encryption and unrelated backing aliases.

For directory creation, perform searchable path resolution and the existing-entry check before requiring parent write permission. Existing paths return POSIX `EEXIST`; only a genuinely missing final component requires parent mutation permission and creates upper state.

For FTS traversal, use a thread-local scope while calling the original `fts_read` or `fts_children`. Within that scope, interposed `getattrlistbulk` recognizes the attribute shape used by FTS and synthesizes records from the same merged upper/lower directory view used by `readdir`; unsupported attribute shapes and calls outside the scope continue natively. Managed streams force `FTS_NOCHDIR`, map physical upper roots back to logical presentation paths, filter whiteouts, and repair `FTS_NS` entries produced for virtual objects.

Codex-specific path bypasses and host temporary-directory passthrough are rejected because they would couple the filesystem layer to one application and weaken isolation.

## Data Flow

1. `realpath(logical_input, output)` enters the filesystem hook.
2. The hook converts relative input using the tracked logical current directory.
3. The VFS follows visible Overlay and lower symlinks, rejects whiteouts or missing components, and produces the canonical logical path.
4. The hook writes that logical path to the caller buffer, or allocates a new C buffer when `output` is null.
5. No physical `<workdir>/fs` path is returned to the child.

For `mkdir`, the hook first resolves ancestor search permission and checks the final visible entry. It returns `EEXIST` for an existing entry; otherwise it checks parent write-plus-execute permission and creates the upper directory.

For macOS FTS, the hook establishes a virtual-bulk scope and calls libc without the outer recursion guard. `getattrlistbulk` emits compatible native attribute records for the merged directory view, so libc continues to own and allocate every `FTSENT`; the adapters only filter, repair, and temporarily present logical paths and names.

## Lark Export Semantics

The command remains relative-path based as required by `lark-cli`:

```bash
cd ~
lark-cli drive +export \
  --url 'https://example.invalid/wiki/WIKI_TOKEN' \
  --file-extension docx \
  --file-name 'example.docx' \
  --output-dir . \
  --as user \
  --format json
```

Without `cd ~`, `--output-dir .` intentionally writes to the current directory. Acceptance checks must inspect the resolved current directory and must not infer `~/` from the filename alone.

## Tests

- Hook tests cover `realpath` for lower paths, upper-only directories, caller-owned buffers, allocated buffers, Overlay symlinks, whiteouts, missing paths, and private backing-path non-disclosure.
- Crypto tests cover authenticated filename encryption, random ciphertext for repeated names, non-UTF-8 byte round trips, wrong-key rejection, and malformed payload rejection.
- Metadata tests cover version-3 encrypted records, absence of plaintext logical names, `backing_names`, and separate `name` fields, record-key/physical-name equality, plain-mode readable records, pre-commit ciphertext-name reservation, encrypted whiteouts, malformed/duplicate record rejection, and direct legacy decoding without startup migration.
- A runner test creates an upper-only directory, calls `std::fs::canonicalize`, and asserts that the returned path is logical and usable.
- A runner test verifies `mkdir -p` through existing root-owned prefixes and confirms that the host lower path remains absent.
- A runner test writes an upper-only file and directory, then verifies `/bin/ls` lists their logical names while lower entries remain present and whiteouts remain hidden.
- Hook tests verify that `getattrlistbulk` synthesizes the merged view only inside a supported FTS virtual-bulk scope and remains native outside it.
- Existing encrypted-name tests assert opaque metadata keys, absence of separately persisted logical-name fields, ciphertext physical contents, record-key/physical-name equality, and logical visibility after reopen.
- Manual acceptance uses a clone of the persistent workdir to start bare Codex TUI, then runs the exact Lark export from `~` and verifies `ls`, `file`, and ZIP integrity inside the sandbox while the host plaintext path remains absent.

## Specification Impact

`spec/architecture/sandbox.md` must list `realpath` and scoped synthetic FTS bulk enumeration among supported hooks, document logical canonicalization and allocation semantics, define metadata version 3 and the fresh-workspace requirement, state that existing-directory creation returns `EEXIST` before parent mutation is required, and require FTS enumeration to merge upper-only entries rather than only filtering lower entries.
