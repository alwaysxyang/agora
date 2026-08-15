# Trace Viewer Batched Rendering Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Keep the Trace Viewer terminal responsive by batching live timeline rendering to at most once per second while retaining the newest 5,000 trace events.

**Architecture:** Add one dependency-free browser helper that owns an insertion-ordered, bounded event map and a single pending render timer. `app.js` continues to own presentation, but live events use the helper instead of scanning and rendering immediately; terminal WebSocket bytes remain on their existing immediate path.

**Tech Stack:** Browser JavaScript, Node.js built-in test runner, embedded Axum assets, existing xterm.js frontend.

## Global Constraints

- Refresh live trace presentation no more than once per 1,000 milliseconds.
- Keep terminal input and output immediate.
- Retain at most the newest 5,000 browser events.
- Do not change sandbox hooks, audit generation, durable logs, Rust WebSocket protocol, or server batching.
- Preserve filters, search, detail display, Clear trace, reconnect snapshots, and smart timeline following.
- Add no dependency and leave all changes uncommitted because the user has not authorized a commit.

---

### Task 1: Bounded trace render batch

**Files:**
- Create: `crates/agora-tools/web/trace-batch.js`
- Create: `crates/agora-tools/tests/trace-batch.test.js`

**Interfaces:**
- Produces: `AgoraTraceBatch.create(options)` in the browser and CommonJS export `{ create }` in Node.
- `options`: `{ keyOf, onFlush, delayMs = 1000, maxEvents = 5000, setTimer = setTimeout, clearTimer = clearTimeout }`.
- Returned methods and properties: `append(event)`, `replace(events)`, `clear()`, `flush()`, `values()`, and read-only `size`.

- [ ] **Step 1: Write failing batching and bounds tests**

Create Node tests that use injected fake timers and assert:

```js
const batch = create({
  keyOf: (event) => event.id,
  onFlush: () => flushes += 1,
  delayMs: 1000,
  maxEvents: 3,
  setTimer: (callback, delay) => {
    scheduled.push({ callback, delay });
    return scheduled.length;
  },
  clearTimer: (id) => cancelled.push(id),
});

batch.append({ id: "one" });
batch.append({ id: "two" });
assert.equal(scheduled.length, 1);
assert.equal(scheduled[0].delay, 1000);
scheduled[0].callback();
assert.equal(flushes, 1);
```

Also verify duplicate replacement preserves order, appending a fourth distinct event evicts the
oldest event, `flush()` cancels a pending timer and renders exactly once, and `replace()`/`clear()`
cancel pending work without resurrecting previous events.

- [ ] **Step 2: Run the tests and verify the missing helper fails**

Run:

```bash
node --test crates/agora-tools/tests/trace-batch.test.js
```

Expected: FAIL because `../web/trace-batch.js` does not exist.

- [ ] **Step 3: Implement the minimal helper**

Use the same browser/CommonJS wrapper as `timeline-follow.js`. Store events in a JavaScript `Map`,
whose insertion order provides chronological iteration and whose first key can be deleted in O(1)
when `maxEvents` is exceeded. `append()` replaces an existing key without moving it, schedules only
when no timer is pending, and never invokes `onFlush` synchronously. `flush()` cancels pending work
and invokes `onFlush` once; `replace()` and `clear()` cancel the timer and mutate state without
rendering so the caller can finish snapshot lifecycle updates first.

- [ ] **Step 4: Run focused helper validation**

Run:

```bash
node --test crates/agora-tools/tests/trace-batch.test.js
node --check crates/agora-tools/web/trace-batch.js
```

Expected: both commands pass without warnings or errors.

- [ ] **Step 5: Review Task 1 without committing**

Run:

```bash
git diff --check -- crates/agora-tools/web/trace-batch.js crates/agora-tools/tests/trace-batch.test.js
```

Expected: no output. Keep the changes uncommitted.

### Task 2: Integrate one-second rendering with the Trace Viewer

**Files:**
- Modify: `crates/agora-tools/web/index.html`
- Modify: `crates/agora-tools/web/app.js`
- Modify: `crates/agora-tools/src/trace_viewer/assets.rs`
- Modify: `docs/superpowers/specs/2026-08-13-trace-viewer-design.md`
- Test: `crates/agora-tools/src/trace_viewer/assets.rs`

**Interfaces:**
- Consumes: `window.AgoraTraceBatch.create(...)` from Task 1.
- Keeps: existing `eventKey(event)`, `renderTimeline()`, `renderHeader()`, and terminal binary handler.
- Adds: one `traceBatch` instance configured with `delayMs: 1000` and `maxEvents: 5000`.

- [ ] **Step 1: Add failing embedded-asset assertions**

Extend the asset test cases with `/trace-batch.js` and require the returned HTML to load its script
after `timeline-follow.js` and before `app.js`. This verifies the browser-visible dependency order;
the Node tests exercise the batching interval and bound as behavior rather than grepping `app.js`.

- [ ] **Step 2: Run the asset test and verify it fails**

Run:

```bash
cargo test -p agora-tools trace_viewer::assets::tests --jobs 16 -- --nocapture
```

Expected: FAIL because `/trace-batch.js` is not yet embedded or referenced by the page.

- [ ] **Step 3: Embed and load the helper**

Add `TRACE_BATCH_JS` in `assets.rs`, serve it as `text/javascript`, include it in the local-only asset
scan, and load `/trace-batch.js` between `/timeline-follow.js` and `/app.js` in `index.html`.

- [ ] **Step 4: Replace per-event rendering with batched state**

Create the batch with `eventKey` and an `onFlush` callback that calls `renderTimeline()` and
`renderHeader()`. Change live trace handling to `traceBatch.append(event)` and retain the active-root
assignment. Replace `state.events` reads with `traceBatch.values()` or `traceBatch.size`. Snapshot and
Clear trace call `replace()` or `clear()` before their existing immediate `renderAll()` call.

Filter clicks, search changes, close visibility, detail open/close, and terminal exit call
`traceBatch.flush()` when immediate presentation is required. The binary WebSocket branch remains:

```js
terminal.write(new Uint8Array(event.data));
```

with no scheduling or trace-state dependency.

- [ ] **Step 5: Document the presentation latency and bound**

Update the existing Trace Viewer design to state that live timeline DOM updates are coalesced into a
maximum of one render per second, terminal bytes remain immediate, and both backend and browser
presentation histories retain at most 5,000 normalized events. No `spec/architecture` update is
needed because crate ownership, protocol, runtime behavior, and dependency direction remain
unchanged.

- [ ] **Step 6: Run focused frontend and asset validation**

Run:

```bash
node --test crates/agora-tools/tests/timeline-follow.test.js crates/agora-tools/tests/trace-batch.test.js
node --check crates/agora-tools/web/timeline-follow.js
node --check crates/agora-tools/web/trace-batch.js
node --check crates/agora-tools/web/app.js
cargo test -p agora-tools trace_viewer::assets::tests --jobs 16 -- --nocapture
```

Expected: all commands pass without warnings or errors.

- [ ] **Step 7: Verify the real browser behavior**

Run the Release Trace Viewer with an isolated config, open the authenticated local page, clear the
timeline, and start interactive `codex`. Confirm that terminal input and Ctrl-C remain responsive
while several hundred file events arrive, and that the visible event count advances in batches no
more often than once per second.

- [ ] **Step 8: Run required crate and workspace validation**

Run the affected crate first:

```bash
cargo test -p agora-tools --all-targets --jobs 16 -- --test-threads=16
cargo clippy -p agora-tools --all-targets --jobs 16 -- -D warnings
```

Then run repository-required checks once:

```bash
cargo fmt --all -- --check
just spec-check
LLVM_PROFILE_FILE="$PWD/target/agora-%p-%12m.profraw" \
  cargo llvm-cov --no-clean --workspace --all-targets --jobs 16 --fail-under-lines 80
rg --files -uu -g '*.profraw' -g '!target/**'
```

Expected: all commands pass with zero warnings and errors, coverage remains at least 80%, and the
final `rg` command prints nothing.

- [ ] **Step 9: Review the complete uncommitted change**

Run:

```bash
git diff --check
git status --short
git diff --stat
```

Confirm that only the helper, tests, Trace Viewer assets/application, and two design/plan documents
are changed. Do not commit or push.
