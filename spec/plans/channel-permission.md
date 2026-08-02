# Channel Permission Implementation Plan

## Goal

Add channel-owned access control for Lark and Telegram without exposing channel-native identity or mention details to the daemon or agents.

## Configuration

Each channel accepts an optional `permission` object:

```json
{
  "users": [
    {
      "id": "user-id"
    },
    {
      "id": "*"
    }
  ],
  "groups": [
    {
      "id": "group-id",
      "require_mention": true
    }
  ]
}
```

Missing or empty permission configuration denies all access. Private messages check the sender list. Group messages check both the sender list and the group list. Exact group rules override the wildcard group rule. `require_mention` defaults to `false`. Denied group messages are silent unless they explicitly mention the current bot; mentioned denials receive the configuration guidance.

Denial guidance uses a minimal JSONC configuration fragment rooted at `channels`. The entry contains the suggested `permission` object and represents unrelated existing channel fields with `// ...`; channel-specific type, name, and credential fields are intentionally not invented.

## Boundaries

- `channel::permission` owns the shared policy model, neutral access context, deterministic decision, and structured denial details. It does not produce Markdown or channel-native UI.
- Lark and Telegram own extraction of sender id, chat kind, group id, and bot mention state.
- Lark and Telegram consume denied events, render the structured denial details in their own native rich-message format when requested, and continue receiving. Lark owns its JSON 2.0 card and Markdown layout; Telegram independently owns its Rich Markdown layout.
- The daemon, commands, execution scheduler, store, and agents remain unchanged.

## Steps

1. Add failing tests for permission deserialization and shared policy decisions.
2. Implement the permission model and evaluator.
3. Add failing Lark tests for message/action identity, mention parsing, and denial replies.
4. Enforce permissions in the Lark receive loop.
5. Add failing Telegram tests for sender/action identity, bot mention parsing, and denial replies.
6. Enforce permissions in the Telegram polling loop.
7. Run formatting, workspace tests, clippy, spec check, and workspace coverage.
