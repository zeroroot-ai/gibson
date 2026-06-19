# Dashboard read path: World + Scroller

How the dashboard reads mission state for the single pane. Follows the existing
**`TracesService` pattern**: a **daemon-local read service** the dashboard consumes via
**Envoy + ConnectRPC over SPIFFE mTLS**, tenant-scoped by ext-authz. The **dashboard holds
zero backing-store clients** — the daemon is the sole tenant-scoped gateway (consistent with
the tenant-isolation epic). The dashboard never touches the World, the event log, or Neo4j
directly.

## Two read concerns, two services

**`WorldService` — current state (the live view).**
- `QueryEntities(filter)` / `GetEntity(id)` — read components + relationships of the current
  World (the graph view).
- `StreamWorld(filter)` — live updates (server pushes deltas as the reducer applies events),
  so the live pane stays current without polling.

**`TimelineService` — the Scroller (replay/scrub).**
- `ListFrames(mission, granularity)` — the event log **bucketed into display frames** (tick
  rate ~50ms ≠ display rate; server buckets for readable scrubbing).
- `GetFrameAt(mission, seq|tick)` — server **folds the log to that point** and returns the
  World snapshot as it was → the scrubber lands on any moment.
- `GetEventsInRange(mission, from, to)` — zoom from a frame down to raw domain events.
- `StreamTimeline(mission)` — live tail.

Replay fidelity comes from the log fold (server-side), not the client — the dashboard is a
thin viewer.

## Scoping
- The Timeline is **per-tenant**; the Scroller **scopes to a mission** by filtering on mission
  id. Tenant isolation is enforced by ext-authz (user/member/tenant), same as `TracesService`.

## What this replaces
- The **`TracesService` + Langfuse** mission-observability read path is **retired**.
  `LlmCall` / `ToolExecution` / `AgentRun` are now first-class World entities, so the
  trace/cost/generation data the dashboard used to pull from Langfuse comes from the
  World/Timeline. (Langfuse + ClickHouse leave the stack — [ADR-0001](../adr/0001-ecs-native-mission-brain.md).)

## Rendering (dashboard, mostly existing pieces)
- **World graph view** — reuse the `react-force-graph` GraphCanvas from the graph-explorer
  rebuild; nodes/edges = World entities/relationships.
- **Scroller** — a new native timeline-scrubber (shadcn): frame slider + step + live tail,
  backed by `TimelineService`. The HITL **review/label queue** ([ADR-0006](../adr/0006-closed-loop-learning.md))
  sits beside it (native shadcn, not Label Studio — see that ADR's note).

## Decision baked in
New **`WorldService` + `TimelineService`** (daemon-local), rather than overloading
`TracesService`. The two concerns (current-state query vs. log-fold replay) are distinct
enough to warrant separate services, and `TracesService` is being retired anyway.
