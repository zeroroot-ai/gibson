# World-sourced knowledge graph (graph as a projection, not a parallel store)

The persistent knowledge graph (Neo4j) is a **read-model projected from the Tenant
World**, not a store agents write to directly. Agents emit **typed observations**;
the brain resolves identity and topology and a projector serializes the World to the
graph. See [`CONTEXT.md`](../../CONTEXT.md); this refines [ADR-0001](0001-ecs-native-mission-brain.md)
(log-first) and builds on [ADR-0002](0002-scope-relative-entity-identity.md) (identity).

## Context

Before this ADR the system had **two disjoint stores**, fed by unrelated paths:

- **Tenant World** (`internal/brain`): in-memory ark entities (`Host`, `WorkItem`,
  `Finding`, `Mission`), fed only by daemon **lifecycle events** (`mission.*`,
  `node.*`, `finding.*`) via `ingestToBrain`. Its `Host` entity was defined but never
  populated — no observation feed.
- **Neo4j knowledge graph**: typed nodes + edges with `map[string]any` properties,
  written **directly by agents** calling `StoreNode(GraphNode)` → the harness GraphRAG
  store bridge → Neo4j. Agents authored node shape *and* topology.

They never synced. The graph was the **old GraphRAG paradigm** living alongside the new
brain. This contradicts ADR-0001 (the World is the fold of the Timeline and the single
source of truth) and wastes ADR-0002 (scope-relative identity already resolves entities
and their containment — but only inside the World, which the graph ignored).

The recall side is already settled: under ADR-0001 agents do **not** read the graph back
(world state is ambiently projected to them); the query/recall surface was removed across
the SDK (sdk#341, v0.146.0) and is being removed from the daemon. This ADR settles the
**emit** side.

## Decision

1. **The World is the only source of truth; the graph is a projection of it.** Neo4j
   becomes a deterministic read-model derived from the World (which is `fold(Timeline)`).
   Replay the Timeline → identical World → identical graph. No state lives only in the
   graph.

2. **Agents emit typed observations, not graph nodes.** A first-class, strongly-typed
   `Observe(Observation)` SDK surface replaces `StoreNode(GraphNode)` for the emit path
   (`HostObservation`, `ServiceObservation`, …), mapping 1:1 to brain Timeline events
   (`HostObserved` already exists). No `map[string]any` property-bag guessing in the
   daemon. This is a breaking SDK change shipped as its own release.

3. **The brain authors identity and topology, never the agent.** An observation is a raw
   sighting ("host at `addr` in `scope`, ssh key `K`, ports `[22,80]`"). The reducer +
   scope-relative resolution (ADR-0002, `resolveHost`/`reconcilePorts`) decide whether it
   is a new entity or an enrichment of an existing one, and derive the edges between
   entities (containment `Host —HAS_PORT→ Port`, links `Finding —AFFECTS→ Host`). Agents
   never set node IDs or relationships.

4. **A projector System writes the graph, idempotently, keyed by stable entity IDs.** On
   the clock tick (ADR-0004), a projector reads World entities and upserts Neo4j nodes
   and edges keyed by the brain's replay-deterministic IDs (`Host.ID`, …). Entity → node;
   component fields → node properties; entity references → edges. Belief/attention
   (ADR-0005) are projected as node properties, so "juiciness" is queryable in the graph.

5. **The graph is per-tenant.** The projector targets the same per-tenant Neo4j the
   GraphRAG store used (`pool.For`); there is no cross-tenant graph, consistent with the
   per-tenant World/Timeline.

## Consequences

- **Graph persistence is preserved throughout the migration.** The direct
  `StoreNode`→Neo4j store path stays working until the projector (S3) exists and is
  validated; only then is the direct path cut (S4). We never lose comprehensive graph
  save (the concern that motivated this ADR).
- **One model, one identity.** Scope-relative identity, contradiction→`Surprise`, and
  time-bounded ports now flow into the graph for free — the projection inherits them.
- **Replayable graph.** Rebuilding the graph from the Timeline is well-defined (re-fold,
  re-project), which the old agent-authored graph could not offer.
- **Cost:** a second SDK breaking release (typed `Observe`), a new observation
  vocabulary + reducers beyond `HostObserved`, and a projector with idempotent upsert.
  The query/recall rip (in progress) is unaffected and lands as part of the cutover.

## Slices

- **S1** Observation vocabulary: brain events + reducers + scope-relative identity for
  the node types beyond host (service/endpoint/…); the entity↔graph mapping table.
- **S2** Typed `Observe` SDK surface (its own release) → daemon ingest → `Timeline`,
  with `ScopeID` derived from mission context.
- **S3** Graph projector System: World → per-tenant Neo4j, idempotent by stable ID.
- **S4** Cutover: remove the direct `StoreNode`→Neo4j path; finish the daemon recall rip;
  the projector becomes the sole graph writer.
- **S5** Belief/attention projected into the graph; Scroller / graph view read off the
  projection.
