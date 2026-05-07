# 0001 Single combined guard handler

All three Guard modules (boundary, protected-paths, bash-gate) are evaluated by a single `tool_call` event handler rather than registering separate handlers per module. Each module exports a pure evaluation function; the entry point orchestrates them in fixed order (boundary → protected-paths → bash-gate) with first-block-wins short-circuit logic.

## Considered options

- **Separate handlers per module:** Each Guard registers its own `tool_call` listener. Rejected because pi does not guarantee handler ordering, making deterministic short-circuit impossible. A tool call touching both boundary and protected-paths could produce two confirmation dialogs.
- **Parallel evaluation:** All Guards evaluate independently, most restrictive wins. Rejected because it confuses users with multiple dialogs and makes audit trail harder to follow.
- **Single combined handler (chosen):** Pure evaluation functions composed by the entry point. Explicit ordering, single verdict per tool call, one audit entry.

## Consequences

- Adding a new Guard requires modifying the entry point's pipeline function — not just registering a new handler.
- The evaluation order is deterministic and testable: boundary is always checked before protected-paths, which is always checked before bash classification.
- Each Guard module remains independently testable as a pure function.
