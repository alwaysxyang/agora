# Trace Timeline Auto-Follow Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the Runtime Trace timeline follow newly appended audit events while preserving a user's historical reading position after they scroll upward.

**Architecture:** Put the 24-pixel bottom threshold and post-render scroll restoration in one dependency-free browser helper that is directly testable with Node's built-in test runner. Load that helper before the existing application script, then let `app.js` own only the current follow/pause state and update it from the real timeline scroll container.

**Tech Stack:** Browser JavaScript, Node built-in `node:test`, embedded Axum assets, existing Rust tests, xterm-based Runtime Trace UI.

## Global Constraints

- Follow when the timeline is at, or within exactly 24 pixels of, its bottom.
- Scrolling upward pauses follow mode; returning within 24 pixels of the bottom resumes it.
- A render in follow mode moves to the newest visible event; a render in paused mode restores the previous `scrollTop`.
- Initial page state follows the newest event without adding a new UI control.
- Do not add a runtime CDN, Node.js runtime requirement, package-manager dependency, or Cargo dependency.
- Do not change `agora-sandbox` behavior or touch the user's existing NFS, session, or sandbox-spec changes.
- Leave this task uncommitted unless the user separately authorizes a commit in the current task.

---

### Task 1: Testable Timeline-Follow Decisions

**Files:**
- Create: `crates/agora-tools/web/timeline-follow.js`
- Create: `crates/agora-tools/tests/timeline-follow.test.js`

**Interfaces:**
- Produces: `globalThis.AgoraTimelineFollow.isAtBottom(container) -> boolean` in the browser.
- Produces: `globalThis.AgoraTimelineFollow.restoreAfterRender(container, following, previousScrollTop) -> void` in the browser.
- Produces the same two functions through `module.exports` for the Node test runner.
- `container` supplies the numeric DOM scroll fields `scrollTop`, `clientHeight`, and `scrollHeight`.

- [x] **Step 1: Write the failing helper tests**

```javascript
"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { isAtBottom, restoreAfterRender } = require("../web/timeline-follow.js");

test("bottom detection uses the documented 24 pixel threshold", () => {
  assert.equal(isAtBottom({ scrollTop: 476, clientHeight: 500, scrollHeight: 1000 }), true);
  assert.equal(isAtBottom({ scrollTop: 475, clientHeight: 500, scrollHeight: 1000 }), false);
});

test("render restoration follows new events or preserves paused history", () => {
  const container = { scrollTop: 0, scrollHeight: 1600 };
  restoreAfterRender(container, true, 220);
  assert.equal(container.scrollTop, 1600);

  restoreAfterRender(container, false, 220);
  assert.equal(container.scrollTop, 220);
});
```

- [x] **Step 2: Run the helper tests and verify RED**

Run:

```bash
node --test crates/agora-tools/tests/timeline-follow.test.js
```

Expected: FAIL with `MODULE_NOT_FOUND` for `../web/timeline-follow.js`, proving that the test is waiting for the production helper.

- [x] **Step 3: Add the minimal browser and CommonJS helper**

```javascript
((root, factory) => {
  "use strict";

  const timelineFollow = factory();
  if (typeof module === "object" && module.exports) module.exports = timelineFollow;
  else root.AgoraTimelineFollow = timelineFollow;
})(typeof globalThis === "undefined" ? this : globalThis, () => {
  "use strict";

  const BOTTOM_THRESHOLD_PX = 24;

  function isAtBottom(container) {
    return container.scrollHeight - container.clientHeight - container.scrollTop <= BOTTOM_THRESHOLD_PX;
  }

  function restoreAfterRender(container, following, previousScrollTop) {
    container.scrollTop = following ? container.scrollHeight : previousScrollTop;
  }

  return Object.freeze({ isAtBottom, restoreAfterRender });
});
```

- [x] **Step 4: Run the helper tests and syntax checks and verify GREEN**

Run:

```bash
node --test crates/agora-tools/tests/timeline-follow.test.js
node --check crates/agora-tools/web/timeline-follow.js
```

Expected: 2 tests pass; the syntax check exits successfully with no output.

- [x] **Step 5: Review Task 1 without committing**

Run:

```bash
git diff --check -- crates/agora-tools/web/timeline-follow.js crates/agora-tools/tests/timeline-follow.test.js
```

Expected: exit 0 with no output. Keep the change uncommitted.

### Task 2: Embed and Wire Smart Timeline Following

**Files:**
- Modify: `crates/agora-tools/src/trace_viewer/assets.rs:6-43,81-147`
- Modify: `crates/agora-tools/web/index.html:10-13`
- Modify: `crates/agora-tools/web/app.js:4-101,312-333,469-487`
- Modify: `docs/superpowers/specs/2026-08-13-trace-viewer-design.md:151-166,229-264`

**Interfaces:**
- Consumes: `window.AgoraTimelineFollow.isAtBottom(container)` from Task 1.
- Consumes: `window.AgoraTimelineFollow.restoreAfterRender(container, following, previousScrollTop)` from Task 1.
- Produces: an embedded `GET /timeline-follow.js` asset with the same security and cache headers as every existing viewer asset.
- Produces: `state.timelineFollowing: boolean`, initialized to `true` and updated from the timeline's `scroll` event.

- [x] **Step 1: Add failing Rust asset and wiring assertions**

Extend the embedded-asset cases with:

```rust
("/timeline-follow.js", "text/javascript"),
```

Add this focused test in `assets.rs`:

```rust
#[test]
fn timeline_follow_helper_loads_before_the_application_and_is_wired() {
    let index = include_str!("../../web/index.html");
    let helper = r#"<script defer src="/timeline-follow.js"></script>"#;
    let application = r#"<script defer src="/app.js"></script>"#;
    assert!(index.find(helper).unwrap() < index.find(application).unwrap());

    let app = include_str!("../../web/app.js");
    assert!(app.contains("timelineFollowing: true"));
    assert!(app.contains("timelineFollow.isAtBottom(elements.timeline)"));
    assert!(app.contains("timelineFollow.restoreAfterRender("));
}
```

Also include `timeline-follow.js` in the source concatenation used by the existing local-only asset test.

- [x] **Step 2: Run the focused Rust tests and verify RED**

Run:

```bash
cargo test -p agora-tools trace_viewer::assets::tests --jobs 16 -- --nocapture
```

Expected: FAIL because `/timeline-follow.js` is not routed and the HTML/application wiring does not exist yet.

- [x] **Step 3: Embed the helper before `app.js`**

In `assets.rs`, add:

```rust
const TIMELINE_FOLLOW_JS: &str = include_str!("../../web/timeline-follow.js");
```

and serve it through:

```rust
.route(
    "/timeline-follow.js",
    get(|| async { asset(TIMELINE_FOLLOW_JS, "text/javascript; charset=utf-8") }),
)
```

In `index.html`, load it after the vendored fit addon and before the application:

```html
<script defer src="/vendor/addon-fit.js"></script>
<script defer src="/timeline-follow.js"></script>
<script defer src="/app.js"></script>
```

- [x] **Step 4: Wire follow state into the actual timeline**

At application startup, bind the helper:

```javascript
const timelineFollow = window.AgoraTimelineFollow;
```

Initialize state with:

```javascript
timelineFollowing: true,
```

Capture and restore scrolling around the existing complete timeline render:

```javascript
function renderTimeline() {
  const previousScrollTop = elements.timeline.scrollTop;
  const events = visibleEvents();
  const fragmentNode = document.createDocumentFragment();
  if (events.length === 0) {
    const hasSourceEvents = state.events.length > 0;
    elements.emptyState.querySelector("strong").textContent = hasSourceEvents ? "No events match these filters" : "Waiting for runtime activity";
    elements.emptyState.querySelector("p").textContent = hasSourceEvents
      ? "Adjust the event types, search text, or close-event toggle to reveal more activity."
      : "Run a command in the terminal. Process execution, opened files, and network destinations will appear here.";
    fragmentNode.append(elements.emptyState);
  } else {
    let previousRoot = null;
    for (const event of events) {
      if (event.root_trace_id !== previousRoot) {
        fragmentNode.append(createRootDivider(event.root_trace_id));
        previousRoot = event.root_trace_id;
      }
      fragmentNode.append(createEventRow(event));
    }
  }
  elements.timeline.replaceChildren(fragmentNode);
  timelineFollow.restoreAfterRender(elements.timeline, state.timelineFollowing, previousScrollTop);
}
```

Update follow mode from real user/programmatic scroll position:

```javascript
elements.timeline.addEventListener("scroll", () => {
  state.timelineFollowing = timelineFollow.isAtBottom(elements.timeline);
});
```

- [x] **Step 5: Run focused browser-logic, Rust, and syntax checks and verify GREEN**

Run:

```bash
node --test crates/agora-tools/tests/timeline-follow.test.js
node --check crates/agora-tools/web/timeline-follow.js
node --check crates/agora-tools/web/app.js
cargo test -p agora-tools trace_viewer::assets::tests --jobs 16 -- --nocapture
```

Expected: 2 Node tests and all focused Rust asset tests pass without warnings.

- [x] **Step 6: Verify real browser behavior**

Start the viewer with an ignored test config and a local sandbox binary, then generate enough audit records to overflow the timeline viewport. Verify all three states in the actual browser:

1. Initial events place the timeline at its maximum scroll position.
2. Scrolling upward and appending another audit record leaves `scrollTop` unchanged.
3. Returning within 24 pixels of the bottom and appending another record moves to the new maximum.

Also verify the browser console has no errors and that filters and detail selection still render correctly.

- [x] **Step 7: Run repository-required validation**

Run serially:

```bash
cargo fmt --all -- --check
node --test crates/agora-tools/tests/timeline-follow.test.js
node --check crates/agora-tools/web/timeline-follow.js
node --check crates/agora-tools/web/app.js
cargo test -p agora-tools --all-targets --jobs 16 -- --test-threads=16
cargo clippy -p agora-tools --all-targets --jobs 16 -- -D warnings
cargo test --workspace --all-targets --jobs 16 --quiet -- --test-threads=16
cargo clippy --workspace --all-targets --jobs 16 -- -D warnings
LLVM_PROFILE_FILE="$PWD/target/agora-%p-%12m.profraw" \
  cargo llvm-cov --no-clean --workspace --all-targets --jobs 16 --fail-under-lines 80
find . -path './target' -prune -o -type f -name '*.profraw' -delete
rg --files -uu -g '*.profraw' -g '!target/**'
git diff --check
```

Expected: every command exits 0, workspace line coverage remains at least 80%, and the final profile scan prints nothing. If the repository still has no `just` executable or `Justfile`, report that `just spec-check` is unavailable instead of claiming it ran.

- [x] **Step 8: Review scope and hand off uncommitted changes**

Run:

```bash
git status --short
git diff -- crates/agora-tools docs/superpowers/specs/2026-08-13-trace-viewer-design.md docs/superpowers/plans/2026-08-14-trace-timeline-auto-follow.md
```

Expected: only the viewer auto-follow files and design/plan documentation belong to this task. Pre-existing NFS, session, and `spec/architecture/sandbox.md` changes remain unstaged and untouched.
