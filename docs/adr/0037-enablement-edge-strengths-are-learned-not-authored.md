# Enablement-edge belief structure is declared; its strengths are learned

The ontology/Pack declares, per enablement-edge-type, **which target belief
variable it feeds** (structure). The noisy-OR **strength and leak are learned** —
a Beta posterior per edge-type, fit by `braintrain` from recorded outcomes, with
an uninformative prior at cold-start. No hand-authored strengths. This amends
[ADR-0029](0029-belief-is-a-relational-prm-over-the-graph.md) §6 and extends
[ADR-0005](0005-belief-field-pgm.md)'s "parameters are learned, not authored" to
enablement edges. See [`CONTEXT.md`](../../CONTEXT.md). Issues: #346, #333.

## Context

`DeriveAttackGraph` builds the acyclic Bayesian attack graph from Neo4j
relationships the ontology flags as enablement edges, but the flag is a bare list
of type names — it does not say which destination variable an edge feeds, nor the
noisy-OR strength each cause contributes. The noisy-OR CPT needs both. #333's
BAMCP additionally needs the strengths *with uncertainty*.

## Decision

1. **Structure is declared in the Pack.** The enablement-edge flag grows a
   `target_variable` (and direction): "edge-type X feeds variable V on the
   destination node." This is domain structure, authored like the rest of the
   ontology, versioned, shipped via rollout.

2. **Strengths are learned Beta posteriors.** Each edge-type's noisy-OR strength
   (and leak) is a Beta posterior fit by `braintrain` (Beta-Bernoulli conjugate:
   each recorded *cause-active → effect-observed?* outcome updates it), versioned
   and mission-pinned. No hand-authored magic numbers — the same discipline
   ADR-0005 applied to CPTs.

3. **Cold-start is a principled prior.** A fresh edge-type starts at an
   uninformative prior (Jeffreys `Beta(½,½)` or uniform `Beta(1,1)`, mean 0.5), so
   belief still propagates from day one and the posterior sharpens with data.
   "0.5 because we have no data yet" is defensible; an expert's "0.8" is not.

4. **One output, two uses (unifies #346 and #333).** Belief inference uses the
   posterior **mean** as the noisy-OR strength. BAMCP ([ADR-0034](0034-native-go-belief-runtime-retire-the-sidecar.md),
   #333) **Thompson-samples** the full posterior for model-uncertainty planning —
   which is exactly the "Dirichlet/Beta posterior from braintrain" prerequisite
   #333 listed. #346 and that prereq become the same `braintrain` output.

5. **Strength is per edge-**type**, not per Neo4j edge.** Neo4j stores structure
   only (no probabilities); the learned strength keys on the relationship type in
   the belief model. (Per-edge-instance strengths remain a possible future
   refinement, not v1.)

## Considered and rejected

- **Hand-authored strengths in the Pack.** Simplest and needs no braintrain, but
  they are uncalibrated magic numbers that never self-correct — exactly the
  anti-pattern ADR-0005 rejected for CPTs. The uninformative-prior cold-start
  gives the same "works on day one" benefit without the magic numbers.

## Consequences

#346 ships the pack structure now with an uninformative-prior strength, so belief
propagates immediately and improves as `braintrain` fits posteriors. #333's
posterior prerequisite is satisfied by the same mechanism. `braintrain` gains a
per-edge-type Beta-posterior output; the belief runtime consumes the mean, the
planner consumes samples.
