# Proof-of-demonstration: settle a bet TRUE by a typed predicate over real evidence

A bet settles TRUE only when the fleet **demonstrates** the claim and a **typed success
predicate** fires against the captured evidence. No LLM judges a settlement. This is the
mechanism behind the TRUE path of [ADR-0023](0023-bet-settlement.md). See
[`CONTEXT.md`](../../CONTEXT.md). Issue: #278.

## Decision

1. **Proof = typed predicate + captured evidence + transcript.** The hypothesis carries a
   machine-checkable success predicate ("the claim holds iff this is observed"). The
   demonstration produces captured evidence. The action transcript (the flight recorder,
   #271) records exactly what the agent did. All three live on the Timeline.

2. **Settlement is deterministic predicate evaluation, never an LLM opinion.** A bet
   settles TRUE iff the predicate evaluates true against the captured evidence. Replay
   re-folds the Timeline and re-evaluates the predicate — same result — so proof is
   reproducible and auditable without re-executing anything.

3. **Predicates are typed and come from the technique, not free-form.** An agent selects a
   predicate type defined by the technique in the ontology / Domain Pack
   ([ADR-0024](0024-discoverable-taxonomy-and-ontology.md),
   [ADR-0025](0025-domain-packs.md)); it cannot invent a trivially-true predicate to game
   its own bet. This is what keeps the market honest.

4. **Prove control, not damage — by default.** The predicate is satisfiable
   non-destructively: the fleet proves it *could* reach / read / act by capturing a benign
   marker, never by exfiltrating real data or destroying state. Demonstration runs against
   the real in-scope target from an isolated sandbox (setec isolates the untrusted tooling,
   not the target), bounded by Rules of Engagement.

5. **Destructive proof is permitted only under per-action authorization.** See
   [ADR-0028](0028-destructive-proof-authorization-gate.md): an irreversible or
   state-changing demonstration runs only after a human authorizes that specific action in
   the dashboard.

## Consequences

A finding is real because a typed predicate fired against recorded evidence, not because
an agent or an LLM said so. Settlement is objective, replayable, and un-gameable. The cost
is that every technique must define its success predicate types (seeded or discovered into
its Domain Pack) — a technique with no predicate cannot auto-settle a bet TRUE and falls
back to HITL.
