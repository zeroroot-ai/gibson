# A scoped runtime authorization gate for destructive proof (amends ADR-0008)

A destructive or irreversible demonstration ([ADR-0027](0027-proof-of-demonstration.md))
runs **only after a human authorizes that specific action** in the dashboard. This
re-introduces a runtime approval gate, so it **amends** [ADR-0008](0008-autonomous-execution-no-hitl.md),
which had removed approval gates entirely. See [`CONTEXT.md`](../../CONTEXT.md). Issue:
#278; dashboard authorization-queue issue tracked separately.

## Context

ADR-0008 made the brain fully autonomous with no human approval steps, because a blanket
approve-everything gate defeats autonomy. That reasoning holds for the common case. It does
not hold for an action that could destroy or irreversibly change a customer's real system —
there, "declare the bound up front" is not enough; a human must see the specific action.

## Decision

1. **A risk tier decides auto vs gated.** Reversibility + blast radius (the risk-cost signal
   from [ADR-0026](0026-bayesian-sequential-planner.md)) plus a technique flag in the Domain
   Pack. Below the threshold: auto (non-destructive proof-of-control). Above: gated.

2. **The gate is per-action, not per-mission.** While one destructive demonstration awaits
   authorization, its bet stays OPEN and **the fleet keeps working everything else**. The
   mission never stalls — only that one action waits. This preserves ADR-0008's "the fleet
   does not block" intent while gating the dangerous move.

3. **The human authorizes the specific action in the dashboard.** They see what it would do,
   its blast radius, its reversibility, and the predicate it would satisfy, then approve or
   deny that action. Approval is per-action and recorded on the Timeline (replayable).

4. **RoE still bounds the outer edge.** Some actions are blocked outright and are never
   offered for authorization. The gate is for the risky-but-potentially-authorized middle,
   never for what RoE forbids.

## Consequences

The fleet stays autonomous for everything non-destructive and pauses only the rare
irreversible action, for one human decision, without stalling the mission. The cost is a new
security-critical surface — the dashboard authorization queue — and a small, deliberate
retreat from ADR-0008's absolute no-gate stance, scoped to destructive proof only.
