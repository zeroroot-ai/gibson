# Proof-of-demonstration settlement is agent-triggered, system-verified

A bet settles TRUE only when a deterministic typed predicate fires against
**recorded evidence** the daemon holds — never on an agent's own verdict. The
agent *triggers* settlement and *supplies raw evidence*; the daemon *decides*.
This extends [ADR-0027](0027-proof-of-demonstration.md) into a trust boundary on
the submission path. See [`CONTEXT.md`](../../CONTEXT.md). Issue: #360.

## Context

`Engine.SettleBetTrue` evaluates a typed predicate against evidence and folds
`BetSettledTrue`, but nothing in the live daemon ever reaches it — proof
settlement has no entry point. The open question was never "add an RPC"; it was
"where does trustworthy evidence come from," because a bet must not settle on
evidence its own beneficiary fabricated.

## Decision

1. **Agent-triggered, system-verified (hybrid).** A new customer-facing
   `SubmitProof` RPC (OSS SDK `HarnessCallbackService`, alongside `PlaceBet` /
   `Observe`) lets an agent nominate the hypothesis, the predicate type, its
   params, and submit **raw** tool output as evidence. The agent never submits a
   verdict or an interpretation — only raw captured data. A deterministic,
   typed predicate (never an LLM) decides. This keeps ADR-0027's "no LLM judge,
   deterministic re-evaluation" literally true.

2. **Independent-evidence integrity is a hard invariant, resting on complete
   recording.** The agent may post the raw output of its own tools (a `curl`'s
   JSON is fine); it does not need an infrastructure tap. Integrity comes from
   three things together: the agent posts raw data not a verdict, the predicate
   is deterministic, and **every tool invocation flows through the flight
   recorder** so the submitted evidence is corroborated by an independent,
   immutable record.

3. **One canonical recording choke point, guarded.** All tool I/O routes through
   `harness.ToolCallSink` (`ingestToolCall` → `AgentToolCallObserved`). A
   completeness guard — shipped with a failing fixture — fails CI if any
   tool-execution path (main callback, sandboxed setec dispatch, metatool,
   streaming) returns a result without folding an `AgentToolCallObserved`. The
   integrity model is only as strong as its weakest unrecorded path, so
   "everything recorded" is an enforced invariant, not a convention.

4. **`SubmitProof` is non-blocking.** It never blocks on a human decision (see
   [ADR-0032](0032-destructive-proof-gate-before-the-action.md)); non-destructive
   proofs settle synchronously, destructive ones settle asynchronously on
   approval.

## Considered and rejected

- **Agent submits a verdict / an interpretation.** Lets the beneficiary judge
  its own bet — defeats the market.
- **Fully system-driven auto-settlement** against captured evidence with no
  agent trigger: a larger evidence-stream-binding engine that overlaps #333;
  deferred.
- **Infrastructure tap** (sandbox network proxy captures evidence out-of-band):
  strongest integrity, much larger build; recorded in [ADR-0027](0027-proof-of-demonstration.md)
  as a future strengthening, not v1.

## Consequences

Proof settlement becomes reachable from a real `cmd/` main (clears the deadcode
baseline entries for `SettleBetTrue` / `settlement.NewRegistry`). The daemon
gains a completeness guard on tool recording — a new invariant every tool path
must honor. `BetSettlementRequest` carries raw evidence the predicate evaluates;
the flight recorder is the corroborating record.
