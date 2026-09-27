# Value-of-Information planning: a Bayesian sequential planner (BAMCP)

The Decider's next move is chosen by a **Value-of-Information (VoI) planner**: it plans
multiple steps ahead over the belief field and pursues the move that most reduces
uncertainty about the goal, net of cost. The planner is **BAMCP** (Bayes-Adaptive Monte
Carlo Planning) — fully Bayesian, no UCB. It builds on [ADR-0005](0005-belief-field-pgm.md)
(the PGM), [ADR-0006](0006-closed-loop-learning.md) (learning), [ADR-0022](0022-betting-prediction-market.md)
(the market), and **refines** [ADR-0008](0008-autonomous-execution-no-hitl.md): the LLM
still decides, but from a VoI-gated set. See [`CONTEXT.md`](../../CONTEXT.md). Issue: #283.

## Decision

1. **VoI gates, the LLM chooses within the gate.** The planner computes the top-k
   highest-value candidate moves; the LLM Decider picks from that set and cannot go
   outside it. The fleet is always working near-optimal-information moves, and the LLM
   keeps contextual judgment inside that set.

2. **A candidate is an open hypothesis to test or an evidence move on a high-uncertainty
   node.** Both are scored on one scale, bounded to the ambient (belief-ranked) slice.
   Pursuing a hypothesis-candidate **is** placing/raising a bet on it
   ([ADR-0022](0022-betting-prediction-market.md)); an evidence move places no bet.

3. **Value is goal-relative info gain + surprise, over cost.** Expected reduction in
   uncertainty about goal-relevant beliefs (juiciness × connectivity), plus a surprise
   term so the off-path breakthrough is never curated away
   ([ADR-0005](0005-belief-field-pgm.md) anomaly channel), divided by resource cost
   (time + budget, shared with `BudgetSystem`) + risk cost (blast radius, reversibility,
   bounded by RoE). Raw global entropy is **not** the objective.

4. **Full multi-step sequential planning, off-tick, via BAMCP.** Exact enumeration of the
   plan tree is intractable (exponential in horizon × outcomes × candidates), so the
   planner is BAMCP/Thompson-sampled: it plans over the belief network as the simulator,
   samples promising trajectories deep, and re-plans each decision as evidence lands
   (receding horizon). It runs off-tick like the Decider, so the ~50 ms tick never blocks.

5. **The model posterior is the Dirichlet over the CPTs.** BAMCP plans over model
   uncertainty; that uncertainty is exactly the per-tenant CPT posterior the
   Laplace-smoothed `braintrain` counting already produces. Planner and learning loop are
   one Bayesian object.

6. **Reward is exploration-dominant but it commits.** Terminal reward for a demonstrated
   finding ([ADR-0027](0027-proof-of-demonstration.md)) + heavily-weighted info-gain /
   novelty shaping − risk cost, with an optimism-under-uncertainty prior and a long
   horizon. Offsec is exploration-first, so the exploration weight is high — but the
   terminal reward is kept, or the fleet would explore forever and never settle a bet.

## Consequences

The fleet is provably efficient per step and adaptive across steps, without exponential
planning. Exact enumeration and pure information-seeking are both rejected (intractable
and non-committing, respectively). Fully Bayesian exploration costs more compute per
decision than UCB; off-tick absorbs it. **Jev is out of scope now**; later it is the fast
in-search evaluator (more rollouts per unit time) and a learned fast-path policy — an
accelerator, never a replacement for the planner, and downstream of the market data it
would train on.
