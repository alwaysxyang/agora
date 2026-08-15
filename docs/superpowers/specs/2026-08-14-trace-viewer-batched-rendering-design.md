# Trace Viewer Batched Rendering Design

Status: implemented and verified

Date: 2026-08-14

## Problem

The Trace Viewer currently performs a complete timeline render for every live audit event. Starting
an interactive program such as Codex can produce hundreds of file events in a few seconds, so the
browser repeatedly filters the complete event list, recreates every visible row, and replaces the
timeline DOM. This blocks the browser main thread and delays xterm.js output and keyboard input even
though the Release sandbox process itself remains responsive.

## Goals

- Keep terminal input and output responsive during large trace bursts.
- Refresh the trace timeline no more than once per second while events are arriving.
- Preserve all existing event types, filters, search, detail display, and timeline-follow behavior.
- Keep browser trace memory bounded to the same 5,000-event limit as the backend.
- Limit the change to the Trace Viewer frontend.

## Non-goals

- Changing sandbox hooks, audit generation, the durable JSON Lines log, or sandbox runtime behavior.
- Changing the WebSocket protocol or batching events in the Rust server.
- Splitting terminal and trace traffic across multiple connections.
- Adding timeline virtualization or pagination in this change.

## Design

Live trace messages update the in-memory event collection immediately but do not render the timeline
immediately. The first event after an idle period schedules one refresh for one second later. Further
events reuse that pending refresh. A refresh performs the existing timeline and header rendering once
for the complete batch.

The browser keeps a key lookup alongside the ordered event list so duplicate event replacement does
not scan the entire list. Before a scheduled render, it trims the oldest entries when the list exceeds
5,000 events and rebuilds the bounded lookup. Snapshot replay rebuilds the lookup from the snapshot;
Clear trace clears both structures and cancels any pending refresh.

User-driven presentation changes remain immediate. Search input, event filters, the close-event
toggle, snapshot replay, and Clear trace render synchronously because they are infrequent and users
expect direct feedback. A user-driven render consumes any pending scheduled refresh so it does not
cause a redundant second render.

Binary terminal WebSocket messages continue to call `terminal.write` immediately. No terminal bytes,
PTY behavior, audit records, or trace records are delayed or discarded by the batching policy; only
timeline DOM updates are delayed by at most one second.

## Failure And Lifecycle Handling

- A scheduled refresh reads current state rather than retaining an event batch, so clearing or
  replacing state cannot resurrect old events.
- Session exit performs a final pending refresh so the final event count and timeline are current.
- Reconnect snapshots replace browser state and render immediately; subsequent live events return to
  the one-second schedule.
- The durable log remains authoritative if the bounded browser history drops old events.

## Testing

- A burst of events schedules one render rather than one render per event.
- A later event after the first refresh schedules another refresh.
- Duplicate keys replace their event without increasing the count.
- More than 5,000 events retain the newest 5,000.
- Clear, snapshot, filter, and search paths render immediately and do not leave a redundant timer.
- Terminal binary messages remain outside the trace scheduler.
- Existing timeline-follow tests continue to pass.

## Trade-offs

The timeline may be up to one second behind the durable log, which is acceptable for this diagnostic
surface and isolates interactive terminal work from audit presentation. Full rendering of 5,000 rows
can still be expensive, but reducing hundreds of renders to one removes the observed Codex startup
pathology with much less complexity than virtualization or a protocol change. Virtualization remains
a follow-up only if measurements after this change show that long-lived 5,000-event sessions are
still materially slow.

## Acceptance Criteria

1. A live burst causes at most one timeline render per one-second interval.
2. Terminal input and output remain immediately handled while trace rendering is pending.
3. The browser retains at most the newest 5,000 events.
4. Existing filters, search, details, clear, reconnect, and smart follow behavior remain unchanged.
5. No sandbox runtime, audit format, WebSocket protocol, or Rust backend behavior changes.
