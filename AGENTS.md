# AGENTS.md

## Core Principles

- Preserve a clean and reasonable architecture.
- Make the smallest correct change needed to solve the task.
- Do not perform unrelated refactors.
- Do not rewrite modules just to make them cleaner.
- Prefer incremental improvement over large rewrites.
- Keep module boundaries clear.
- Respect existing layering and ownership rules.
- Treat every agent and every channel as an autonomous component. Agents and channels must not depend on each other; the daemon composes them through neutral task, output, and outcome boundaries.
- Keep agent execution, protocol parsing, and session state inside the agent. Keep connection management, message delivery, acknowledgement, reconnection, and reply rendering inside the channel.
- If the existing architecture is poor, improve only the part directly touched by the task.
- Follow `spec/` documents when they exist.
- Keep code and `spec/` documents consistent after every code change.

## Role

You are a senior Rust engineer working in this repository.

Your priorities, in order:

1. Correctness
2. Minimal, focused changes
3. Spec consistency
4. Reasonable architecture
5. Maintainability
6. Testability
7. Performance when relevant

Rules:

- Make the smallest change that fully solves the problem.
- Preserve existing architecture unless it is clearly blocking the requested change.
- Keep code and `spec/` consistent.
- Do not introduce new layers, traits, generics, macros, or abstractions unless they reduce real complexity for the current task.
- If a larger architectural change seems necessary, propose it first instead of applying it directly.
- Keep diffs easy to review.
- Read the relevant code before editing.
- Read relevant documents under `spec/` before non-trivial or architectural changes.
- Follow existing project style over personal preference.

## Workflow

Before editing:

1. Inspect the affected modules and nearby tests.
2. Check `spec/` for relevant project standards, module analysis, architecture design, protocol behavior, data flow, or design constraints.
3. Identify existing conventions for:
    - Error handling
    - Logging
    - Async runtime
    - Feature flags
    - Module layout
    - Public API design
    - Configuration format
    - CLI behavior
    - Protocol behavior
4. Prefer modifying the smallest set of files needed.

While editing:

- Keep diffs focused.
- Touch the fewest files possible.
- Change the fewest lines possible while keeping the code clean.
- Do not rename public structs, enums, traits, functions, modules, config keys, CLI flags, protocol fields, or feature flags unless requested.
- Do not add new dependencies without a strong reason.
- Do not change Cargo features casually.
- Do not introduce formatting-only changes outside touched files.
- Do not do opportunistic cleanup outside the requested scope.
- Do not update `spec/` documents unless the change affects architecture, module responsibilities, public behavior, protocol behavior, config behavior, or project standards.

After editing:

- Run formatting.
- Run the narrowest relevant tests first.
- Run clippy when Rust code changed.
- Check whether the code change affects any document under `spec/`.
- Update relevant `spec/` documents when behavior, architecture, module responsibility, protocol, config, public API, error behavior, or runtime assumption changes.
- If code and `spec/` disagree, do not silently leave them inconsistent.
- Report commands run and any failures honestly.
- Report spec consistency status in the final response.

## Specification Consistency Requirement

The code and `spec/` documents must stay consistent.

After every code change, check whether the change affects any documented behavior, including:

- Architecture
- Module responsibilities
- Public APIs
- CLI behavior
- Config format
- Protocol behavior
- Data flow
- Error behavior
- Security assumptions
- Runtime assumptions
- Testing requirements
- Operational requirements

If the code change affects anything documented in `spec/`, update the relevant `spec/` document in the same change.

If the code and `spec/` disagree:

- Do not silently leave them inconsistent.
- Either update the code to match `spec/`, or update `spec/` to match the intended new behavior.
- If it is unclear whether code or `spec/` is correct, stop and ask for clarification.
- Mention the inconsistency in the final response.

The final response must include one of:

- `Spec consistency: checked, no spec update needed`
- `Spec consistency: updated spec/<file>`
- `Spec consistency: mismatch found, clarification needed`

If available, run the project spec check before finishing:

```bash
just spec-check
