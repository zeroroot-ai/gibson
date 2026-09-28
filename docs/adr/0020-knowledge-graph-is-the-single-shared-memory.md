# The knowledge graph is the single shared memory

The Tenant World knowledge graph is the one place the fleet reads and writes.
Belief, ontology, and taxonomy are layers **on** that graph, not separate stores.
This refines [ADR-0005](0005-belief-field-pgm.md) (belief is propagated over the
attack graph) and [ADR-0007](0007-world-sourced-graph-projection.md) (the graph is
a projection of the World). See [`CONTEXT.md`](../../CONTEXT.md).

## Decision

1. **One logical memory.** Every agent read is an ambient projection of the graph.
   Every agent write is an emitted observation folded into the graph. Every
   reasoner (belief, ontology, taxonomy) reads and annotates the same graph. There
   is one thing to read, one thing to write, one thing to reason over.

2. **Belief is a property on graph nodes.** The PGM posterior
   (`P(juicy)`/`P(exploitable)`/`P(reachable)`) is recorded on the node it scores
   and propagates along typed edges. Belief stops being a side-car score.

3. **The physical model is unchanged.** The Timeline stays the source of truth,
   the ECS World stays the live cache (`World = fold(Timeline)`), and Neo4j stays
   the query projection ([ADR-0007](0007-world-sourced-graph-projection.md)). This
   ADR is about the *logical* model that everything shares, not a new store.

## Consequences

Graph-coupled belief, ontology-derived structure, and value-of-information
planning all become possible, because they finally have one common substrate to
stand on. A subsystem that keeps its own private store violates this ADR.
