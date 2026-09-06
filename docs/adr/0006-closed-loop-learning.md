# Closed-loop learning: auto-labels + HITL labels → offline retrain

The belief model ([ADR-0005](0005-belief-field-pgm.md)) improves through a learning loop fed
by two label sources, retrained out-of-band. See [`CONTEXT.md`](../../CONTEXT.md).

## The loop

```
surprise (low P(obs|model) + contradictions) → boosts ATTENTION
   → agent investigates → confirmed = FINDING, else surprise decays
   → labels:
        • AUTO   — mission outcomes in the event log (evidence → outcome)
        • HITL   — experts async-label surfaced surprises + Findings in the
                   dashboard (true/false positive, severity, category, dismiss)
   → labels become (tenant-scoped) events
   → offline batch trainer fits CPTs → ships a VERSIONED model
   → next missions pin the new version  ──► back to top
```

## Decision

1. **Two label sources.** Auto-labels (mission outcomes, free, plentiful, noisy) + HITL
   labels (expert, scarce, gold). HITL is the higher-quality signal.
2. **HITL labeling is async — never a runtime gate.** The mission never waits on a human
   (autonomy + no-polling-on-humans). Labels improve the *next* model, not the current run.
3. **Labels are events**, tenant-scoped, fed to the **out-of-band** trainer (no online
   learning — that would break deterministic replay, [ADR-0005](0005-belief-field-pgm.md)).
4. **Anomalies are not a separate entity.** Surprise is a second *attention signal*; a
   confirmed surprise is just a **Finding**. Surprise **decays** on investigation/dismissal.
5. **OSS vs commercial:** the brain *accepting label events + emitting training data* is OSS
   (self-hosters can label via API/own UI); the polished **review-and-label UX is the
   commercial dashboard**.
6. **Label sharing is intra-tenant only.** Labels **never leave the tenant** — no cross-tenant
   sharing, and **none feed the commercial base model**. *Within* a tenant, labels **pool across
   all that tenant's users** (a shared label set) and refine **that tenant's** model only.

## Considered and rejected

- **Online learning from labels.** Drifts the model mid-mission; breaks replay.
- **Blocking the mission on human labels.** Violates autonomy / no-polling-on-humans.
- **A standalone "Anomaly" entity.** Collapsed — anomalies surface as boosted Observations
  and resolve into Findings or are dropped.

## Consequences

- Needs: a label-event type, a review queue, and the offline trainer consuming labels
  alongside auto-outcomes.
- The dashboard needs a review/label UI (evaluate off-the-shelf labeling libraries vs. a
  native shadcn build).
