# ECS-native mission brain

The mission-execution brain (today: the ReAct loop in `internal/orchestrator/`,
mission state split across Neo4j, an in-memory loop, the tiered `internal/memory/`
store, and the checkpoint store) is rebuilt as an **Entity-Component-System** using
**ark** (Go). Every in-flight concern is expressed as components in a shared, **per-tenant
Tenant World**; **Systems** hold all mechanical behavior. See
[`CONTEXT.md`](../../CONTEXT.md) for terminology.

**Hard isolation invariant: there is NO cross-tenant anything.** World, Timeline, reducer,
and Knowledge graph are all per-tenant and fully isolated. A tenant's missions live as
subgraphs within its one Tenant World, so they see each other (running + previous); nothing
ever spans tenants.

The spine — all of these are coupled and decided together:

1. **ark, in Go, in its own module/package** (not Rust/flecs, not smeared into
   `orchestrator/`). The brain↔daemon boundary is an explicit interface; the
   agent/tool/plugin proto ABI is untouched.
2. **Scope = the mission data plane only.** Billing / signup / tenant provisioning (the
   platform control plane) stay ordinary Go services, out of the ECS.
3. **Log-first event sourcing.** One ordered **per-tenant Timeline** (domain events) is the
   system of record for the data plane; a single per-tenant reducer folds it into the Tenant
   World. The **Scroller** (operator UI) and crash-resume are both replays of the Timeline;
   the Scroller scopes to a mission by filtering. Capture is via the existing SDK
   callback/span bus (in-process, microVM, and remote workers) plus the daemon's authz
   decisions at the callback boundary.
4. **Single shared per-tenant World, single-writer reducer.** Concurrent agents across all
   of a tenant's missions emit events and have their relevant state projected to them; only
   the one per-tenant reducer mutates the World. This is the concurrency-control mechanism
   and resolves ark's non-thread-safety.
5. **The LLM is the Decider; there are no hand-authored decision rules (playbooks).**
   Systems are mechanical only (sensing, scheduling, budget, belief recompute). Topology:
   a thin per-mission Orchestrator over Worker agents; decisions are single-shot now,
   goal-directed lookahead/search is a deferred later phase.
6. **CUE stays as the authoring/validation front door**, projected into the World at
   launch. Missions and (the rejected concept of) playbooks unify under one primitive — a
   **Work-graph** (trigger + graph of work); a `depends_on` edge is just deferred ordering.
7. **Ambient persistence + unified memory.** Nobody calls read/write. Acting emits an
   event (the write); the log keeps everything, so there is **no per-component durability
   registry**. The **Knowledge graph** (Neo4j) is a durable cross-mission *projection*;
   the World is a transparent cache over it (virtual-memory model: write-through +
   fault-in). The four existing memory paths (SDK `memory/`, gibson `internal/memory/`,
   `graphrag` recall/ingest, orchestrator `recall.go`) collapse into this one path.
   Removing SDK `memory/` is a **breaking, major-version SDK change**.
8. **One belief field.** The Bayesian attack-path belief over the World
   (`P(juicy)`/`P(exploitable)`/`P(reachable)`, propagated along exploit edges) serves
   three uses at once: juicy-target score, Orchestrator prioritization, and each agent's
   ambient attention/relevance scope. Relevance is field-strength at **any** graph
   distance, plus an explicit anomaly channel — because offensive security chains
   structurally-distant systems.

## Considered and rejected

- **Rust + flecs.** Forces rewriting or bridging auth/billing/tenant/secrets; the only
  unique win (flecs explorer UI) is replaceable by a first-party, tenant-aware dashboard
  view. Loop is LLM-bound, so "Rust for speed" is a non-reason.
- **ECS as system-of-record for the whole platform** (event-sourcing billing/authz, etc.).
  Throws away ACID/auth semantics and can't hold a tenant's full Neo4j graph in RAM.
- **Hand-authored playbooks / curated plays + GOAP planning.** The expert-system
  paradigm; a frontier model has internalized more pentest knowledge and adapts to
  context. GOAP additionally needs hand-declared preconditions and replaces LLM reasoning.
- **A workflow engine (Temporal / Argo / go-workflows) for execution.** Static-DAG and
  insists on owning the runtime, conflicting with ECS-as-runtime; its event history is
  redundant with the domain Timeline (which already gives replay + crash-resume).
- **Graph-distance / spatial relevance** (the game-engine metric). Wrong for offsec,
  where value is in distant, non-obvious exploit chains. Replaced by the belief field.

## Consequences

- Breaking SDK major version (removes `memory/`; ripples to ADK, examples, docs).
- Entity identity/resolution is resolved in [ADR-0002](0002-scope-relative-entity-identity.md)
  (scope-relative coordinates + scoped loop-compare, no index/keys/merge). The **anomaly
  channel** remains a careful-design item (so a goal-directed belief field isn't blind to
  the unlooked-for breakthrough); identity contradictions feed it.
- **Same-tenant** missions share the live Tenant World, so they see each other's state
  immediately (no cross-mission lag). The only eventual-consistency is the async World→KG
  projection. **Cross-tenant is total isolation** — no shared structure at all.
