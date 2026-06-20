# Autonomous mission execution — no human-in-the-loop approval gates

The legacy `internal/orchestrator` could pause a mission for **human approval**
(`request_approval`) or **escalate** to a human/specialist before continuing. The ECS-brain
cutover (gibson#770) **removes approval and escalation entirely**: the brain runs missions
**fully autonomously**. The LLM Decider decides everything; no runtime step waits on a human.

Bounds on autonomy are **declarative and mechanical**, established up front rather than
gated at runtime:

- **Rules of Engagement** — the CUE mission `MissionConstraints`
  (`allowed_techniques`/`blocked_techniques`/`blocked_tools`/`blocked_domains`/
  `severity_threshold`).
- **FGA authz** — the `Authorize` path enforced at the daemon/harness boundary.
- **Budget/limit System** — per-mission max executions / depth / token-cost
  (from `MissionConstraints` + the Entitlements provider), which also serves as the
  runaway-Decider guard.

This is distinct from the **labeling HITL** of [ADR-0006](0006-closed-loop-learning.md)
(humans labeling mission outcomes to train the belief model) — that is a closed-loop-learning
concern, not an execution gate, and is untouched.

## Considered and rejected

- **Keep approval/escalation gates** (or stub a blocking hook and defer the UI). Rejected:
  runtime human gates contradict the autonomous-Decider design and the platform's
  "no polling on human replies, ever" principle; safety is better expressed as up-front
  declared Rules of Engagement + authz than as mid-run human checkpoints.

## Consequences

- A mission, once launched within its declared Rules of Engagement, can run offensive
  actions to completion with no human checkpoint. Safety rests entirely on the RoE, FGA, and
  budget being correct — there is no runtime backstop.
- The CUE `DataPolicy` reuse/scoping fields are separately deprecated (reuse is implicit in
  the World; scoping is handled by scope-relative identity + ambient projection).
