# Belief is a relational PRM over the graph; the market and reputation are views of it

Belief is a **generic relational probabilistic model** (a PRM) whose schema — which node
types bear belief, their variables, and the probabilistic dependencies between them — is
declared by the ontology / Domain Pack. It is instantiated over the actual graph into a
directed-acyclic **Bayesian attack graph** and solved by **exact inference on a bounded
slice**. This **amends** [ADR-0005](0005-belief-field-pgm.md) (belief was a fixed per-host
net) and reframes [ADR-0022](0022-betting-prediction-market.md): the market and reputation
become **views of this substrate**. Builds on [ADR-0024](0024-discoverable-taxonomy-and-ontology.md)
/ [ADR-0025](0025-domain-packs.md). See [`CONTEXT.md`](../../CONTEXT.md). Issue: #275.

## Decision

1. **Belief propagates over a directed-acyclic Bayesian attack graph derived from the infra
   graph** — not the raw cyclic graph. Attack enablement is directional, so a DAG is the
   honest model and it keeps ADR-0005's exact-inference promise.

2. **Belief is generic and relational (a PRM), not host-specific.** Any node type — asset,
   finding, technique, mission — declares its belief variables and dependencies in the
   ontology/Pack. `{reachable, exploitable, juicy}` on assets is *seed* content, not
   structure. The engine instantiates the declared template per node and wires cross-node
   enablement edges into one ground Bayesian attack graph. `braintrain` keeps refitting the
   template CPTs.

3. **The market and reputation are views of the belief substrate.** A hypothesis/bet is
   belief on a claim-node (`P(claim valid)`); reputation is belief on a technique ×
   environment node (`P(technique works here)`). One substrate, three faces. Provenance is
   preserved: an agent proposes the claim (hypothesis), the system computes the belief
   (derived, never asserted), the agent stakes (bet). This reframes ADR-0022, #266, #267,
   #278 as views rather than separate stores.

4. **Cycles are broken per-slice, deterministically.** Belief is computed per node by
   extracting a bounded slice *toward* that node, as a DAG, breaking cycles by a
   deterministic topological potential (attack-distance, tiebroken by stable id) and
   dropping back-edges within the slice. A back-edge dropped in one node's slice is a
   forward-edge in another's, so both directions are represented across queries.
   Time-unrolling (a DBN) is the faithful alternative, deferred; SCC-collapse is the fallback
   for dense mutual-reachability clusters.

5. **Exactness lives in the inference; the bound lives in the scope.** The slice is bounded
   by depth + a treewidth/node budget, pruned deterministically by belief-relevance
   (attention + surprise, reused). Inference on the slice is **exact VE, never sampling**, so
   ADR-0005's "exact, deterministic, reproducible" holds literally. The documented
   limitation: a node's belief reflects its bounded neighborhood, not the whole graph.

6. **Enablement CPTs use noisy-OR/noisy-MAX**, so a node with many enablement parents stays
   O(parents), not O(2^parents).

7. **Which edge types are enablement edges is declared in the ontology/Pack** (a
   belief-propagating flag). Seed the core ones (reachability, credential-grants, trust,
   runs-service→affects); discover the rest per Pack ([ADR-0024](0024-discoverable-taxonomy-and-ontology.md)).

8. **Compute reuses the async pattern.** A slice-digest gate (the node plus its bounded
   slice's relevant state) drives off-tick recompute and bounded downstream propagation;
   results submit as `BeliefScored`, stale results drop; missions pin the CPT version so
   replay reproduces.

## Consequences

Belief is reusable across every taxonomy/ontology/Pack, and the market and reputation stop
being separate machinery. The cost is real: this is a relational-PRM engine (schema →
ground DAG → exact inference on a bounded slice), materially larger than a fixed per-host
net, and it re-architects #266/#267/#278 as views. #283 (the VoI/BAMCP planner) sits
directly on this substrate and is only as deep as the slices it queries.
