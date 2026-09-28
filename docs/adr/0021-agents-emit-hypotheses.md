# Agents emit hypotheses, not only observed facts

An agent can write a **hypothesis** to the shared graph: a proposed, unproven
claim it wants the fleet to test. The hypothesis is a new variant of the
`Observation` sum type, so this **expands** [ADR-0007](0007-world-sourced-graph-projection.md)
(agents emit typed observations, never raw nodes or edges) rather than breaking
it. It builds on [ADR-0005](0005-belief-field-pgm.md). See [`CONTEXT.md`](../../CONTEXT.md).

## Decision

Three provenance classes live on the graph, and they stay distinct:

1. **Evidence** — what an agent observed. A fact.
2. **Hypothesis** — what an agent proposes but has not proven. It is attributed to
   the proposing agent and carries a confidence. It is unverified until it settles.
3. **Belief** — what the system computed. The PGM posterior. Derived from evidence,
   never asserted by an agent, so it stays calibrated and replayable.

A hypothesis is modeled as a `HypothesisObservation`. So the agent write surface
stays emit-only: an agent still only emits observations. One new observation kind
lets the agent emit its own reasoning, not just its sightings.

## Consequences

The fleet shares thinking, not only facts. Agent A proposes; agent B tests; the
resulting evidence updates belief by the normal math. A hypothesis is also an
agent-proposed novel node, so it plugs into the existing "novel node → prior" seam
([ADR-0005](0005-belief-field-pgm.md)).
