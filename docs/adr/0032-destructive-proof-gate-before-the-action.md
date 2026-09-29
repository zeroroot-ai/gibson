# The destructive-proof authorization gate sits before the action, not at settlement

A human authorizes an irreversible demonstration **before the agent performs
it**, through a non-blocking request. By settlement time the act has already
happened, so `SubmitProof` never blocks and `SettleBetTrue`'s authorizer becomes
a *verification* of the recorded approval. This corrects how
[ADR-0028](0028-destructive-proof-authorization-gate.md) was wired. See
[`CONTEXT.md`](../../CONTEXT.md). Issue: #360.

## Context

The shipped code created a `DestructiveActionRequested` only inside
`SettleBetTrue` → `DestructiveAuthorizationQueue.Authorize`, which **blocks** the
caller until a human decides. But ADR-0028 authorizes "before an irreversible
demonstration runs" — and by the time an agent has evidence to submit, the
destructive act is already done, so gating at settlement is too late to prevent
harm and would block a gRPC call for a human's minutes-to-hours decision,
contradicting ADR-0028's "the fleet keeps working while one action waits."

## Decision

1. **Gate before the action.** A new agent-facing request-authorization step
   enqueues to the existing `DestructiveAuthorizationQueue` and **returns
   immediately**; the agent keeps working (ADR-0028) and performs the destructive
   act only after the human approves.

2. **`SubmitProof` is non-blocking.** After an approved-and-performed
   destructive act the agent calls `SubmitProof`; it does not block. A
   non-destructive proof settles synchronously.

3. **`SettleBetTrue.authorize` becomes a verification, not a blocking call.** It
   reads the recorded decision that the referenced destructive action was
   approved (a `DestructiveActionDecided` on the Timeline) and refuses settlement
   if there is none. The currently-blocking `Authorize` is refactored to this
   request-then-verify shape.

4. **One authorization path.** The request, the dashboard approve/deny
   (`DestructiveAuthorizationService`, live since #342), and the settlement-time
   verification all read/write the one `DestructiveAuthorizationQueue` — no
   second gate.

## Considered and rejected

- **Gate at settlement (accept-the-proof).** Simpler, reuses the queue as-is, but
  authorizes *accepting the proof* after the destruction already happened —
  it does not prevent the irreversible act, which is ADR-0028's whole point.
- **Blocking `SubmitProof`.** A long-lived gRPC call tied to a human decision —
  contradicts ADR-0028 and ties up the agent.

## Consequences

ADR-0028's "gate before the irreversible action" intent is honored. The
authorizer flips from an inline blocking call to a recorded-decision
verification, and a new request-authorization RPC joins the harness surface. The
fleet never blocks on a pending destructive authorization.
