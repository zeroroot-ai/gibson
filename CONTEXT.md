# Gibson — ECS Brain

Gibson's mission-execution brain is being re-modeled as an Entity-Component-System
(ark, Go). Every in-flight concern is expressed as components in a shared, **per-tenant**
**Tenant World**; **Systems** are the only place behavior lives. The ECS is the ubiquitous
runtime model for a tenant's operations — not a replacement for the durable stores, and
not the platform control plane.

> **Hard invariant: there is NO cross-tenant anything.** World, Timeline, reducer, and
> Knowledge graph are *all* per-tenant and fully isolated — separate in-memory arenas,
> separate logs, separate Neo4j databases. No structure, no event, no projection, no
> query ever spans tenants. This matches the existing per-tenant Neo4j / FGA boundary.

## Language

**Tenant World**:
The in-memory ark ECS world for a single tenant — its live working set across *all* its
missions. Running missions are resident; previous missions' state faults in from the
tenant Knowledge graph on demand (virtual-memory model). One per tenant. Never shared.
_Avoid_: world (unqualified), mission world (it is the tenant's, not one mission's), session

**Mission**:
A **Work-graph** scoped to a tenant — the unit of identity / goal / accounting (the thing
a user launches and gets a report for). It lives as a subgraph *within* the Tenant World,
so a mission **sees other missions** (running and previous) of the same tenant.
_Avoid_: job, run (a MissionRun is the execution record)

**Mission execution (data plane)**:
Everything a mission does — agent decisions, tool calls, plugin calls, LLM calls,
in-mission authz (FGA) decisions, findings, targets. This is what the ECS models.
_Avoid_: orchestration (too narrow — orchestration is one subsystem of this)

**Platform control plane**:
Billing, signup, tenant/service provisioning. Explicitly **not** modeled in the ECS;
stays as ordinary Go services.
_Avoid_: admin plane

**System**:
A unit of *mechanical* behavior over the Tenant World — sensing (parse tool output into
components), belief recomputation, scheduling ready work, budget/claim enforcement.
Systems are plumbing and bookkeeping; they do **not** make domain decisions. They maintain
the World the LLM reasons over and carry out what the LLM decides.
_Avoid_: handler, service (control-plane terms); rule/playbook (rejected — see below)

**Decider (LLM)**:
The LLM is the orchestration decision-maker. It reasons over the structured Tenant World
(not a flat transcript) for every genuine decision — what to do next, how to attack a
target, whether the goal is met. There are **no hand-authored decision rules**; the model
decides. Auditability comes from the event-sourced journal + recorded rationale.
_Avoid_: oracle (implied "rare"; it is the decider), thinker, playbook

**Orchestrator**:
The thin LLM Decider role for one mission: reasons over the Tenant World (so it is aware
of sibling missions) to decide what *its* team does — spawn an agent, prioritize a target,
stop. One per running mission. **Single-shot per decision** for now; goal-directed
lookahead/search is a deferred later phase. Does not micromanage workers.
_Avoid_: planner, GOAP (rejected — needs hand-declared preconditions, replaces the LLM)

**Worker (agent)**:
An LLM-driven agent doing a narrow job, dispatched by an Orchestrator, using its own slot
LLM. **One-shot** ("contractor"): given a task, do the work, report, exit — the
continuous/reactive role is the Orchestrator's, not the worker's. It **never calls read or
write**: acting emits domain events (ambient write); its relevant World-slice is
**ambiently projected** into its context (ambient read). Only the single per-tenant reducer
mutates the World. The contract is `Execute(ctx, harness, task) error`, where the harness is
**emit-only**: a read-only live `WorldView` + `Emit(observation)`. The old recall methods
(`GetFindings`, `FindSimilarFindings`, `GetRelatedFindings`, `GetPreviousRunFindings`) are
removed; `SubmitFinding` becomes `Emit`; `Result` shrinks to a terminal status (the real
output is the emitted observations).
_Avoid_: long-lived agent, agent memory API

**Tool call (async, decided by observation)**:
Every tool call is dispatched the same way — async, tracked as a `ToolExecution` entity.
Duration is **never declared or tracked**; the same tool can be quick or slow per
invocation. The runtime decides by *watching whether the result appeared*: fast → the agent
continues inline (feels synchronous); slow → the agent is **set aside and re-engaged when
the result event lands**, context rebuilt from the World. A 3-second nmap and a 3-day shell
callback are the same path. (Agents are stateless between turns — state lives in the World —
so re-engaging is cheap and survives restarts.)
_Avoid_: long-running flag, tool timeout classification, blocking the agent

**Capability vs. execution**:
Every component type has two entities, kept separate: the **capability** (catalog entry —
`Tool` / `Agent` / `Plugin` — relatively static, projected from the registry; what the
Orchestrator queries to decide what to use) and the **execution** (`ToolExecution` /
`AgentRun` / `LlmCall` — dynamic, born on dispatch, has a lifecycle, emits observations).
The execution ties the graph together (`instance_of` capability, `ran_against` host,
`launched_by` agent, `produced` finding).
_Avoid_: conflating a tool with a tool run

**Agent slot LLM**:
The LLM an individual agent uses to do its *own* narrow job (craft an exploit, plan a
scan). Every agent is an LLM-driven worker; unrelated to the Decider, always present.
_Avoid_: the LLM (ambiguous — say "slot LLM" or "Decider")

**Ambient context projection**:
A system continuously materializes each agent's *relevant slice* of the Tenant World into
its context, refreshed (event-driven) as the World changes. The agent experiences "knows
everything"; the system curates relevance so it fits the context budget. This replaces
RAG/recall — relevance is the **Belief field at any distance** (top field-strength entities
+ the agent's focus + the anomaly channel + associative matches), **not** a graph
neighborhood. Periphery is LOD-summarized to fit the budget (game-engine machinery: bounded
view + level-of-detail + event-driven refresh; metric = belief field, not meters).
_Avoid_: retrieval, recall, query API (the agent does not fetch), neighborhood (distance-based)

**Work-graph**:
The single underlying primitive: a *trigger* + a graph of work. A **Mission** is a
work-graph triggered by launch. The Orchestrator dynamically spawns sub-work-graphs at
runtime. A `depends_on` edge is just deferred ordering — not a separate concept.
_Avoid_: workflow, DAG (too static — this one grows at runtime)

**Knowledge graph**:
The durable, **per-tenant**, cross-mission graph (Neo4j) — long-term memory. It is a
**projection** of the tenant Timeline, not a store anyone calls read/write on. The Tenant
World is a transparent **cache** over it (virtual-memory model): events write-through
automatically; relevant slices fault-in on demand. Strictly tenant-isolated.
_Avoid_: memory store, RAG index, the database

**Observations**:
The open-world escape-hatch component: raw, not-yet-typed things an agent perceived about
an entity. Sensing promotes recurring `Observations` into typed components (`Host`,
`Finding`, …); the residue stays here. Lets agents record emergent, unschematized findings
with **no proto change** — essential because offsec breakthroughs are often unschematized.
_Avoid_: attributes, properties, metadata

**Entitlements provider**:
The pluggable seam that decouples commercial gating from the OSS brain. The budget enforcer
and rate limiter consume "what are this tenant's limits / what's enabled?" from this interface
— they never read plans or Stripe directly. OSS ships a permissive/config-driven provider
(admins set per-team quotas; no payment); the **commercial** layer ships the plan +
subscription (Stripe) provider. `BillingService`, Stripe, and `plans.yaml` live **entirely**
in the commercial layer — never in OSS gibson.
_Avoid_: plan check, billing (billing is not in the OSS brain)

**Scope (vantage)**:
The network/addressing context an observation was made *within*, carried by the agent's
vantage (which foothold it works from). Declared up front in the CUE mission (Rules of
Engagement) or minted on pivot into a new network. The coordinate of anything is
`(scope, address)` — so the same IP in two networks is two distinct entities, validly.
Scope is the top-level partition of the World and the unit that bounds resolution loops.
_Avoid_: network (ambiguous), zone, site

**Entity resolution**:
When an observation arrives, build a *temporary* entity from its salient data, then **loop
the existing entities of that type within the same scope** (ECS archetype/relationship
iteration — what the ECS is fast at) and compare **identity signals only**, *exactly*
(SSH host key / cloud-id, or `scope+address` with no contradiction). Match → fold the new
data into the existing entity, updating its volatile state (ports, banners, intervals);
no match → the temp entity becomes new. **No key index, no composite keys, no merge events.**
A type marks only which of its fields are identity vs. volatile state. Identity
contradictions (same address, different host key) feed the **anomaly channel**.
_Avoid_: index, primary key, merge (rejected), fuzzy/similarity matching

**Ambient persistence**:
Nobody calls read/write. Acting = emitting a domain event (the write); the per-tenant event
log keeps **everything** (it is the system of record for the data plane), so there is no
per-component "durable?" decision and **no registry**. Default: everything persists. Optional
inline `persist.Ephemeral` marker on a component type excludes mission-scratch from the
Knowledge graph — colocated with the struct, never a separate file.
_Avoid_: snapshotting (the mental model, not the mechanism), save, flush

**Belief field (attack-path field)**:
The Bayesian belief over the Tenant World — `P(juicy)` / `P(exploitable)` / `P(reachable)` —
propagated along *exploit-relevant edges* (creds, reachability, trust), radiating backward
from goals and forward from footholds. **One field with three uses**: the juicy-target
*score*, the Orchestrator's *prioritization*, and each agent's *attention/relevance scope*.
Relevance is field-strength **at any graph distance** — not proximity (offsec chains
structurally-distant systems). An explicit **anomaly channel** surfaces out-of-place
entities a pure goal-directed field would miss.
_Avoid_: graph-distance relevance (rejected), influence map (the game-AI analog), the score

**Belief model (PGM)**:
The belief field is computed by a real probabilistic graphical model (**pgmpy**) — not an LLM
(poorly calibrated, non-deterministic, expensive) and not hand-tuned weights. **Exact**
inference only (VariableElimination), so the field is **deterministic and reproducible** for
replay. **Read-only at runtime** (consulted for posteriors on evidence change); **learning is
out-of-band** — a batch job fits CPTs from event-log outcomes (`evidence → outcome` pairs are
auto-labeled by mission results) and ships a **versioned model**; each mission **pins the
model version** it ran under so replay reproduces exactly. The LLM supplies priors only for
**novel** nodes the model has no table for. Runs as a Python sidecar (training fully offline;
inference only on evidence change — no Go/Python hot path). Sources: a **commercial** curated
**base model** (vendor red-team + public CVE/ATT&CK only — never tenant data) + per-tenant
refinement. Labels never leave the tenant; **within** a tenant they pool across all its users.
_Avoid_: LLM scoring, online learning (breaks replay), sampling/approximate inference

**Runtime engine (clock-tick game loop)**:
The brain runs as a fixed **~50 ms clock tick** (≈ one gRPC round-trip — the fastest an
external result can arrive; ticking faster would poll for nothing). Each tick: ingest
results that arrived → run systems, **sweeping to quiescence** (re-run until no new events,
so in-memory cascades finish *within* the tick) → emit changes as events → advance. Long
ops (LLM calls, tools) run async between ticks and are picked up when they land. Empty ticks
cost nothing (we store events, not frames). The **Scroller display granularity is separate**
— the log is bucketed coarser for readable scrubbing; tick rate ≠ display rate.
_Avoid_: event-driven cascade (rejected), per-tick frame storage, tying display rate to tick rate

## Relationships

- **OSS boundary:** gibson is **OSS and multi-tenant** (a self-hoster's teams get real
  tenancy with the per-tenant isolation above). The *only* commercial coupling is the payment
  gate, decoupled behind the **Entitlements provider**; `BillingService` + Stripe + `plans.yaml`
  live in the closed layer, not OSS gibson.
- **No cross-tenant anything** (see invariant above). Everything below is *within one tenant*.
- The **ECS** models the **Mission execution (data plane)** only; the **Platform control
  plane** is out of scope.
- One **Tenant World** per tenant holds *all* that tenant's **Missions**; a Mission is a
  subgraph and is aware of sibling missions (running + previous).
- A **Mission** is a root **Work-graph**; its **Orchestrator** (one LLM Decider) spawns
  sub-work and dispatches **Workers**, each with its own slot LLM.
- **The Decider has its own mission-level LLM slot**, distinct from worker node slots: an
  optional top-level field in the CUE mission, resolved through the same `ProviderService`
  path as worker slots, **defaulting to the tenant's default provider/model configured in the
  dashboard** when unspecified (operators may point the Decider at their strongest model; it
  must work with zero config since tenants bring their own keys).
- **Decider output v1 = `Dispatch{kind, capability, input}` + `Complete{outcome, reason}`.**
  The Decider re-invokes **all three kinds**: `agent` (a `Task` — natural-language goal +
  optional World-entity refs; the agent's slot LLM shapes specifics), `tool` (**structured
  input conforming to the tool's proto input schema** — the LLM emits schema-shaped params,
  validated/repaired, then marshalled to proto), `plugin` (`method` + params). Each dispatch
  mints a new execution (`AgentRun`/`ToolExecution`) against an existing capability.
  `Complete` carries an outcome (Mission gains a `Failed`/abandoned state). **Deferred:**
  explicit sub-work-graph spawning with `DependsOn` (dispatch-after-results suffices),
  priority-setting (belief field, #750), an explicit "wait" verb (empty decision list = wait).
- **Decider input v1 = own mission, serialized directly.** The Decider reasons over its
  own mission subgraph (work-graph nodes + states + results, findings, discovered
  hosts/assets) plus the **capability catalog** (enrolled `Agent`/`Tool`/`Plugin` entities
  + their input schemas — what it may dispatch and how to shape inputs), rendered as a
  bounded structured serialization. **No dependency on the belief field (#750) or
  ambient projection (#749)**; those swap in later by replacing the context-rendering step
  without changing the Decider contract. **Sibling-mission context is out for v1** — cross-
  mission reuse arrives properly via the belief field at any distance, not an ad-hoc prompt
  dump.
- **The Decider runs async, never inside a tick** (ADR-0004 forbids slow work in the
  ~50 ms tick). A mechanical **gate System** emits a `DecisionRequested` execution entity
  when a goal-mission has new evidence and **no decision already in flight** (quiescent);
  an async Decider worker (between ticks, like the tool dispatcher) serializes the World
  slice, calls the LLM, and `Submit()`s the resulting decisions as events. A decision is
  therefore **just another execution** in the World — its request, inputs, and emitted
  decisions are all Timeline events, fully replayable. **One in-flight decision per
  mission**: the Decider sees the whole mission World and returns a *list* of decisions, so
  it can target whichever branch just produced results without concurrent decisions racing
  on the shared World. (Per-branch decision concurrency is a deferred later phase.)
- **Workers** and the daemon emit **domain events** → the per-tenant **Timeline** (one
  ordered log); a single per-tenant reducer folds it into the **Tenant World**; the
  **Scroller** is the UI over the Timeline, **scoped to a mission** by filtering. Log-first:
  World = fold of the Timeline.
- **Cutover scope (#770, retiring `internal/orchestrator`).** *Survives, re-expressed:* the
  **runaway guard** — an unbounded LLM Decider can loop forever, so a per-mission
  **budget/limit System** (max executions / depth / token-cost, from CUE `MissionConstraints`
  + the Entitlements provider) is **mandatory**, replacing the old ancestry-based
  `spawn_cycle_guard`. *Removed entirely:* **HITL approval + escalation** — the brain runs
  **fully autonomously**; bounds come from declared **Rules of Engagement** (CUE
  `MissionConstraints`) + **FGA authz** + the budget System, never a runtime human gate (fits
  "no polling on human replies"). This is distinct from the **labeling HITL** (#753 /
  ADR-0006, belief-model training labels — untouched). *Dropped/subsumed:* **data-policy
  reuse + scoping** (`data_policy`/`policy_checker`) — reuse is implicit (the Decider sees the
  World), scoping is superseded by scope-relative identity (ADR-0002) + ambient projection;
  the CUE `DataPolicy` fields are deprecated. *Already handled:* checkpoint/crash-resume →
  Timeline replay; recall/reflect/embedding/graph-intelligence → ambient projection + belief.
- **Mission completion.** *No-goal mission* completes **mechanically**: when the scheduler
  reaches quiescence (every scripted node `done`/`failed` after its `RetryPolicy`, nothing
  ready, no goal) a System emits `MissionDone`. *Goal mission*: the **Decider owns
  completion** — emits `Complete{outcome, reason}` when it judges the goal met (or
  unreachable → `Failed`); the LLM judges, auditability from recorded rationale. **On a
  quiescent goal mission (nothing in flight), the Decider must return dispatch(es) or
  `Complete` — an empty list there is terminal** (nothing left to do ⇒ complete); "wait"
  (empty list) is valid only while work is outstanding. The **budget System** is the hard
  backstop: it forces `MissionDone{outcome: budget_exceeded}` regardless of goal.
- **Dispatch is a side effect of intent, not part of the reducer.** Systems/reducer stay
  pure (replayable); a **dispatch effect-handler** subscribes to *live* `WorkDispatched`
  events and actuates the real launch via the existing dispatch infra (Redis work-queue /
  agent-runner), `Submit()`ing `WorkCompleted` when the SDK callback path reports back.
  **Replay/crash-resume re-folds the Timeline silently — no effects re-fire** (the handler
  listens only to live, post-replay events). On resume, work still `running` with no
  completion is marked **`WorkFailed`** (a crash *is* a failure); the **mechanical retry
  System** re-dispatches it iff the CUE node's `RetryPolicy` allows (deterministic), and the
  **Decider** re-engages with judgment for goal missions. No blind auto-re-dispatch — that
  would silently double-fire a side-effectful tool (e.g. an exploit).
- The **Knowledge graph** (per tenant) is the durable projection of the Timeline; the
  Tenant World is a cache over it.
- **CUE** authors a Work-graph; at launch it is *projected* into the Tenant World
  (nodes→entities, edges→`DependsOn`, constraints→budget components, goal→goal component).
- **CUE node-type projection.** `agent`/`tool`/`plugin` nodes → `WorkItem` executions;
  `parallel`/`join` **evaporate into pure `DependsOn` topology** (siblings with no edge run
  concurrently; a join is a node depending on several — no special entity needed);
  **`condition` survives as a mechanical branch System** — when its deps are satisfied it
  evaluates its expression over the World (the legacy string-expression evaluator, ported)
  and enables the true/false branch, deterministically, so a no-goal scripted mission can
  branch without invoking the Decider.
- **CUE declares dependencies, not a schedule.** The scripted graph executes
  deterministically by honoring its `DependsOn` ordering — no LLM schedules it. As its
  results land in the World, the **Decider re-engages**: it mints *new* executions
  (`AgentRun` / `ToolExecution`) against the *existing* capability entities with adapted
  I/O ("go back to stuff" — fire an agent again with different inputs, use a tool
  differently) to chase the goal. The Decider's primary verb is **re-invocation of the
  scripted repertoire**, not greenfield work. It may **re-engage a branch as soon as that
  branch's scripted nodes produce results** — it interleaves with a still-running script;
  it does not wait for whole-graph quiescence. A **no-goal** mission runs its script to
  completion and stops (the Decider never fires → deterministic/repeatable); a **goal**
  mission interleaves Decider re-engagement on top of the script.
- The World's component/relationship types are **codegen'd from `taxonomy/v1`** (the public
  SDK schema). The proto is slimmed: generic `GraphNode`/`CoreNodeType`/`Relationship` are
  dropped (ark gives entities + native relationships); typed entities → components,
  `CoreRelationType` → relationship kinds, `Value`/`MapValue` survive only for
  **Observations**. The **ontology reasoner** becomes an inference system; the **compliance
  catalog** a stamping system. (Breaking proto change — covered by the major SDK version.)

## Flagged ambiguities

- **Scope is per-tenant, not per-mission.** Resolved: the World, Timeline, reducer, and KG
  are tenant-scoped; missions are subgraphs within the Tenant World and see each other. The
  earlier "World per mission run / World boundary = live-shared-state boundary" framing was
  **wrong** and is retracted. There is NO cross-tenant sharing of any kind.
- "highly coupled to the ECS" was resolved to the **ubiquitous model** (every subsystem
  expresses state as components in a shared world; systems hold all behavior) — *not*
  literal compile-time coupling of every package to `ark` types.
- The four existing memory paths — SDK `memory/` (public), gibson `internal/engine/memory/`
  (working/mission/long-term + vector/Redis), gibson `internal/engine/graphrag/` recall+ingest
  API, and orchestrator `recall.go` — are **ripped into one path**: emit event → Timeline
  (truth) → reducer → World (working) → projector → Knowledge graph (long-term) → hydrator
  faults slices back. `graphrag` narrows to the projection/query backend. Removing SDK
  `memory/` is a **breaking, major-version SDK change** (ADK, examples, docs ripple).
- "the LLM" was used for two distinct things — resolved: the **Agent slot LLM** (a worker
  doing its own job) vs the orchestration **Decider** (reasons over the World to decide what
  the team does). The World *knowing* something (maintained by mechanical systems) is
  distinct from the Decider *deciding* something.
- **Hand-authored playbooks / curated plays were considered and rejected.** A frontier model
  has internalized more pentest knowledge than any authored rule library and adapts to
  context; encoded "when X do Y" decision rules are the obsolete expert-system paradigm. The
  LLM decides; deterministic **systems** remain only for mechanical plumbing. Repeatability
  comes from fully-scripted CUE missions; auditability from the journal + recorded rationale.

<!-- merge-queue canary (Epic: cicd-efficiency, board #44, slice S3): no-op doc touch to
     capture merge_group check-run context strings before requiring any of them. -->
