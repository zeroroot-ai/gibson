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
A mission has **no bounded duration**: it runs until its goal is met or it is stopped,
which may be days, and it may go silent for long stretches while an agent thinks. Anything
carrying mission events therefore has to be unbounded in both total duration and idle
period — see [[0063]].
_Avoid_: job, run (a MissionRun is the execution record); "long-running" (it is not a
long *request*, it has no expected end at all)

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

**Taxonomy**:
The **global**, platform-versioned allow-list of node labels and relationship types the
Knowledge graph may materialise — the same for every tenant. `Sensing` promotes a recurring
`Observation` shape into the Taxonomy; promotion is a reviewed code change, not something a
tenant or an agent can do at runtime. A shape outside the Taxonomy is never rejected — it
lands as an `Observation` instead — so an agent can always write and can never invent
schema. Labels reach Neo4j as **parameters** (`apoc.merge.node`), never as query text, so an
out-of-taxonomy label is at worst a bad name and never a query.
Global rather than per-tenant because the Taxonomy *is* the schema: per-tenant shapes would
push multi-tenancy back into every query, and would let `Host` / `HOST` / `host_v2` diverge
silently. Flexibility is paid for by `Observations`, not by schema divergence.
_Avoid_: schema, ontology (the `ontology` package is the reasoner, a different thing), allowlist

### Application lifecycle (taxonomy expansion, decided 2026-08-30)

The Taxonomy grows past attack-surface shapes. These terms let one graph hold what an
application is, what runs, what is wrong with it, and what was done about it.

**Application**:
The unit a tenant owns and an always-on agent watches: one product with a source
repository, built images, and deployments. The anchor node every lifecycle fact hangs off.
_Avoid_: app, service (a `Service` is a listening process on a `Port`), project, workload

**Repository**:
The source of one Application on the tenant's git host, identified by host and path.
_Avoid_: repo, project (GitLab's word), codebase

**Image**:
One built container image, identified by digest, built from one Repository commit.
_Avoid_: container, artifact, build

**Package**:
One dependency at one version inside an Image or a Repository manifest.
_Avoid_: dependency, library, module, component (a platform `Component` is a different thing)

**Deployment**:
One Image running in one place, exposing zero or more `Hosts`. The bridge between the
lifecycle graph and the runtime graph (`Host`, `Port`, `Service`).
_Avoid_: release, environment, pod, instance

**Vulnerability**:
The identity of a weakness, one node per identifier per tenant (a CVE, a GHSA, or a
platform-issued id for a finding class with no public id). Never carries a status.
_Avoid_: CVE (an id scheme, not the concept), issue, bug, finding

**Finding**:
One occurrence of a Vulnerability in one place (a Package in an Image, a file in a
Repository, a `Service` on a `Host`) with one status: `open`, `fixing`, `fixed`,
`verified`. Status lives here and only here. Exists today; this sharpens it.
_Avoid_: alert, result, detection, vulnerability

**Merge request**:
One proposed change to a Repository, opened by an agent or a person, that fixes one or
more Findings. Its merge is an event in the Timeline.
_Avoid_: PR, pull request (GitHub's word), patch, fix (the fix is what the MR does)

**Pipeline**:
One run of the Repository's CI on one commit. It builds Images and it is the actor that
verifies a fixed Finding, because a Finding is `verified` only by a rescan, never by a merge.
_Avoid_: build, job, CI run, workflow

**Always-on agent**:
A catalog agent (today: zerocool) dispatched once into one long-lived Mission per
Application, which originates child Missions on triggers and never exits by itself.
It is the machine identity that starts scans: ADR-0063 lets a component originate a
Mission only from inside a running one, so the person launches the long-lived Mission and
the agent launches everything after.
_Avoid_: watcher, worker, daemon, bot, continuous agent

**Scan mission**:
A child Mission an always-on agent originates on a trigger (today: a Pipeline on `main`
finished) that runs the scanners and lands Findings on the Application.
_Avoid_: scan job, scan run, audit

**Fix**:
The always-on agent's response to an open Finding: change the Repository, open a Merge
request that auto-merges on a green Pipeline, and wait for the rescan to mark the Finding
`verified`. No human waits inside the loop by default.
_Avoid_: remediation, patch, auto-fix, self-healing

**Scope**:
The network or asset boundary an `Address` is meaningful within. Host identity is the
`(ScopeID, Address)` coordinate — never the address alone — so `10.0.0.1` on two customer
networks is two hosts. `SSHHostKey` / `CloudID` are strong signals that identify a host
*across* addresses (re-leased DHCP, NAT), and a `(scope, address)` that presents as a
different host raises a `Surprise` rather than silently merging.
ScopeID is resolved **server-side from the mission's target definition**, never from the
emitted payload — an agent-supplied scope would make host identity attacker-influenceable,
the same class of defect as an agent-supplied tenant. A mission spanning several networks
enumerates them in its target definition and observations reference one by index.
_Avoid_: network, subnet, VPC (those are instances of a Scope, not the concept)

**Write attribution**:
Which tenant a graph write lands in is resolved from the **mission record the daemon
created**, reached via the capability grant's `mission_id`. It is never read from the
request payload, and no caller can name a tenant. The bar is not "a user was present at
the time" — agents run long after the user has gone — it is that **every write is
attributable to a mission a user launched**.
_Avoid_: caller-supplied tenant, work_id lookup, "authed user" (agents are not users)

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

### Component authorization (platform authz)

**Component kind**:
One of the four kinds authorized against the single FGA `component` object type
(ADR-0046): `agent`, `tool`, `plugin`, and — decided 2026-08-24 — `connector`.
Object ref shape: `component:<kind>/<name>`. A new kind never gets its own FGA
object type.
_Avoid_: a `connector` FGA type (rejected), per-kind permission models

**Connector R/W/X**:
For `component:connector/<id>`: `can_read` = see the connector, its auth status,
and its discovered tools. `can_configure` = enable, disable, authorize, revoke
("Write" in the UI). `can_execute` = invoke its discovered tools. Tool invocation
checks `can_execute` on the connector component — the old
`can_invoke @ plugin:<tenant>/<connector>` borrow is retired (decided 2026-08-24).
The `plugin` FGA type serves true plugin invocation only.
_Avoid_: connector-as-plugin authz, `can_invoke` for connectors

**Connector enable (lifecycle)**:
`EnableConnector` / `DisableConnector` are `admin@tenant` (raised from `member`,
decided 2026-08-24), matching the ConnectorAuth grant RPCs and `SetComponentAccess`.
Enable creates the `ConnectorInstance` CRD; the reconciler converges FGA tuples to
match, with the same default posture as a plugin: `tenant_enabled` +
`direct_read`/`direct_execute` for `tenant#member`, configure for admins. Admins
narrow with the standard deny toggles. Old connector `plugin can_invoke` tuples
are reseeded away by the same reconciler, never hand-migrated.
_Avoid_: handler-written tuples, closed-by-default execute, tuple data migrations

**Connector execute granularity**:
The execute gate is per **connector**, never per discovered tool (decided
2026-08-24). `can_execute @ component:connector/<id>` covers every tool the
connector exposes; the meta-tools path (ADR-0047) is the single check point, so
finer narrowing stays an additive later change. The OAuth scope string is the
real blast-radius bound and the UI shows it next to the execute toggle.
_Avoid_: discovered tools as `component` objects, per-tool deny rows

**Connector subject asymmetry**:
A connector is an FGA **object only** — it is called, it never calls. There is no
`connector_principal`, and `secret.can_resolve` stays `[plugin_principal]` (the
isolation test is untouched). Credentials reach the ToolHive proxy via a
daemon-materialized k8s Secret (ADR-0015); no runtime principal resolves them.
"Works like plugins" holds for the object side only, and this asymmetry is
deliberate (decided 2026-08-24).
_Avoid_: adding `connector_principal` to "complete the pattern", connector secret resolution

**Connector credential**:
The vendor credential a ToolHive proxy forwards to the third-party MCP server.
Two secrets, one visible to the connector (ADR-0015): the **Grant** (OAuth refresh
token, client id, token endpoint, scope) is platform-*code*-only — the connector
never reads it — while the **access token** is short-lived and the only thing the
connector is shown, as `Bearer <token>` in a k8s Secret `<connector>-connector-cred`.
Both live in the **tenant's** store (hosted OpenBao namespace `tenant-<id>`, or the
customer's BYO Vault) — customer owns everything; gibson-minted OAuth material
follows the tenant into BYO. The **daemon** materializes the k8s Secret from its
connector-token loop (not ESO — ESO is platform-infra only), for `oauth`
(refresh → write) and `secret` (read → write) alike. A refresh/store failure is a
loud `Degraded`, never a silent fallback.
_Avoid_: ESO for connector creds, the operator holding the token, a grant in a gibson platform location

**Connector catalog gate**:
In scope (decided 2026-08-24, closes the ADR-0014 TODO). One
`component:connector/<catalog-id>` object per catalog entry, shared across
tenants; `tenant_enabled` marks a tenant's enabled instance. The catalog-source
reconciler converges `platform_enabled` tuples from the embedded catalog table.
`ListCatalog` filters by the gate and `EnableConnector` enforces it. v1 is
**mechanical only**: every embedded entry is seeded `platform_enabled`, so
behaviour is unchanged but de-listing works by removing one tuple. Plan-based
gating arrives later through the entitlements seam via `tenant_published`.
_Avoid_: plan/Stripe policy inside gibson, per-tenant catalog tables

**Connector UI parity**:
The connectors page keeps its lifecycle cards (OAuth state is kind-unique) and
gains the shared `RWXMatrix` + `AccessScopeSelector`, fed by `DiscoveryService`
kind `"connector"`. The security-policy page adds the kind. Lifecycle calls move
from raw `fetch()` to Server Actions, and Enable/Disable gate on `useAuthorize`
(needs a dashboard authz-registry regen — `ConnectorService` is absent today).
Connectors appear in `CatalogPicker` for per-principal grants. No connector
permissions page and no `CONNECTOR` recipient class: those are principal-side.
_Avoid_: raw fetch in connector surfaces, a fifth permission UI

**Platform catalog enablement (all four kinds)**:
Generalizes the connector catalog gate to `agent`/`tool`/`plugin`/`connector` as one
model (decided 2026-08-27). Two states, never conflated:
- `platform_enabled` @ `system_tenant:_system` → **listed/available** in every tenant's
  catalog. A tenant *may* enable it. It does **not** run.
- `tenant_enabled` @ `tenant:<id>` → a tenant admin **explicitly** enabled it. This is the
  *only* thing that makes a component run for a tenant.

**No auto-on, ever** (decided 2026-08-27): publishing to the platform catalog never runs a
component in any tenant, and never retroactively affects existing tenants. The
`CatalogFanout` reconciler (auto-wrote `tenant_enabled` to every tenant) is **deleted** — it
was the one path contradicting opt-in. A brand-new tenant starts **empty**: nothing is
enabled until an admin enables it from the catalog. No provisioning starter-set, no
always-on "system baseline" class.

**Publishing is super-user-only and release-gated** (decided 2026-08-27): who can make a
component `platform_enabled` is the highest privilege in the system. Two structural locks,
kept: (1) the model — `platform_enabled: [system_tenant]`, so only `system_tenant:_system`
is ever the subject; no tenant/user can be. (2) the only writer is the daemon's catalog
reconciler, seeding from **manifests embedded in the signed gibson image** (the connector
catalog pattern, generalized to all four kinds). Publishing = a PR to the catalog manifests +
the release pipeline → a new signed image → `platform_enabled` re-seeded at startup. There
is **no dynamic publish RPC/UI** — no live privileged write endpoint to defend. A random dev
may *open* the PR from a workstation; only the release/merge gate (owner-controlled) lands
it. The super-user identity is `system_tenant:_system#platform_operator` (`[user]`,
cross-tenant elevated; already gates the admin datapool + `DaemonOperatorService`); it is not
a tenant role. Because the catalog is re-seeded from the image every boot, platform
components are reproducible across cluster rebuilds; per-tenant `tenant_enabled` is durable
DB state, backed up, not re-derived.
_Avoid_: fan-out of `platform_enabled` to tenants, provisioning-time auto-enable, a
`defaultOn` manifest flag, an always-on baseline kind, a tenant-reachable publish path, a
live `platform_operator`-gated publish endpoint

**Component isolation & egress (all four kinds)**:
Generalizes the connector isolation envelope (decided 2026-08-27; agent model corrected
2026-08-28). **Agents are external gRPC components, hosted exactly like plugins — ONE workload
code path** (ADR-0027). The "trusted in-image agent" idea was WRONG (a misreading of ADR-0010,
which governs untrusted *tool* execution, not the agent process): the registry discovers an
agent by name and returns a gRPC client (`ComponentDiscovery.DiscoverAgent`), same as a plugin.
So agent, plugin, and hosted tool/connector are ALL workloads — they run in the tenant's
`tenant-<id>` namespace under the `gibson-tenant-default-deny` NetworkPolicy + carry a per-tenant
SVID. **Cross-tenant / east-west is denied always** — private ranges blocked at L3, so nothing
reaches another tenant's namespace or any in-cluster service (SSRF containment). On top of that
floor, a per-workload NetworkPolicy derived from `egressAllow` is **applied where the pod is
deployed** (corrected 2026-08-28): gibson does NOT own agent/plugin pods — `AgentEnrollment`
creates no pod, first-party plugins are GitOps-deployed — so only the connector-operator emits a
policy (for ToolHive pods it owns); external plugins/agents get theirs from their GitOps deploy
manifest. gibson provides ONE shared `egressAllow`→NetworkPolicy derivation for both to consume.
First-party agents (e.g. zerocool) live in `zerocool-plugins`, enrolled as external components;
no separate in-image agent runtime.

**Sandbox-isolation and egress-breadth are separate knobs.** Tool execution is *always*
sandboxed (ADR-0010); a sandbox's egress breadth is independent. External egress is
**per-component**, declared by `egressAllow`, the **ceiling**. For a workload (plugin, **agent**,
connector) it maps to the L7 permission profile + the L3 NetworkPolicy, as connectors do
(generalized from `ConnectorInstance.spec.EgressAllow`). An agent — itself a workload — ALSO has
its `egressAllow` bound onto the setec `LaunchRequest.Egress` of the tools it dispatches
(`zerocool: ["*"]` → scan *and* web/research tools run sandboxed with egress-any = setec
`mode=full`; a red-team agent → a target list, same tools sandboxed but confined). For
platform-wide components the field lives in the **catalog manifest baked into the signed image**
— author-set, release-gated. A tenant can never widen past the ceiling; a later extension may let
a mission NARROW within it without a release. The agent's own LLM/control traffic is the trusted
daemon path, not a per-agent concern.

**Manifest shape** (decided 2026-08-27): one discriminated format — common envelope (`id`,
`kind`, `displayName`, `description`, `egressAllow`) + a `spec` block keyed by `kind`, each
variant embedding that kind's existing runtime type (connector → `ConnectorInstance` spec; plugin
→ runtime + `image@digest` + SVID; tool → `contentTrust`/`dispatchMode` + sandboxed command/image;
agent → the **same workload spec as plugin** (runtime + `image@digest` + SVID) + `model`/`budgetLimit`
policy — a shared workload spec backs both, no in-image impl). One loader (`componentcatalog`,
replacing `connectorcatalog`) seeds `platform_enabled` per kind; validation is fail-loud;
image-bearing kinds must pin a cosign-signed digest.
_Avoid_: a tenant widening egress past the manifest ceiling, hostname allow-listing at L3
(use the L7 profile), disabling the default-deny baseline, a per-agent pod/SVID/NetworkPolicy,
four parallel per-kind catalog loaders

### Banks, members and jobs (decided 2026-09-01, ADR-0019)

Long-lived Claude Code instances fed structured jobs. The wording is copied from
`zerocool-plugins/CONTEXT.md` § Glossary so both repos name one thing one way.
The decisions are [ADR-0019](docs/adr/0019-banks-of-always-on-agents.md); how
the parts move is [`docs/architecture/banks.md`](docs/architecture/banks.md).

**Bank**:
A declarative, daemon-reconciled pool of always-on Claude Code instances: owner, desired
count, login shape, image and model, repo template, idle policy, spill policy (queue or
ephemeral launch when no member is idle). Owned by one person (a subscription sign-in is
theirs) or by the tenant on the tenant API key; same resource, different owner and no
sign-in step. The daemon launches until the desired count runs, relaunches a dead member,
and holds a member at `needs sign-in` until its owner completes the in-sandbox login
through the console. Members are never finished until the bank scales down, so the reaper
leaves them alone. Sized small at idle: the manifest gives a low request and a higher limit.
_Avoid_: pool, fleet, worker group

**Member**:
One instance in a bank. An always-on mission the owner originated (ADR-0063, the same
shape as the `watch` task kind), with an agent session as its input. One turn at a time,
so a bank of N is N parallel turns. Reached only through `SendInput`; `can_send` on the
bank decides who may. Missions reach a bank through a target selector on
`DelegateToAgent`: ephemeral launch (today), a named bank, or a session id.
_Avoid_: worker, instance (unqualified), replica

**Job**:
The unit of work a member holds. Opened by the first structured input (a `Task` with typed
fields: goal, repositories with connector ref and deliverable, credential names, input
World node ids, acceptance, constraints). Owns one Claude Code session (transcript on disk,
reopened with `--resume`), its worktrees, and a state: `open`, `working`, `waiting`,
`closed`. Every later input names the job id and carries the sender's grant for that turn.
Unrelated jobs never share a conversation or a worktree. A chat turn from the console is a
job with only a goal. Nothing arrives at a member as a bare string.
_Avoid_: task (a `Task` is the typed input that opens a job), conversation, thread

**Close**:
The wrap-up signal. The worker never closes its own job. A scorer does (a verification
agent, a person, or the mission node after its acceptance step): `CloseJob(job_id, verdict,
score)`. The driver sends one final wrap-up turn (commit, push, open the merge request,
summarize), then removes the worktrees, archives the transcript to the session store,
reports deliverables and verdict on the run, and drops the job. A job idle past the bank's
stale limit closes with verdict `abandoned`. Nothing else deletes a worktree.
_Avoid_: finish, complete, done (the worker reports those; only a scorer closes)

**Per-turn grant**:
The identity rule for a long-lived member. One sandbox serves many dispatches over its
life, so every input message carries the task grant of its own dispatch and every tool call
in that turn uses it. The driver runs the Gibson MCP server over streamable HTTP on
localhost inside the sandbox, holds the inbox subscription, and swaps the grant per turn. A
stdio server Claude Code spawns cannot do this. Recorded in ADR-0019: long-lived
single-user sandbox, per-turn task grants, MCP over localhost HTTP (amends ADR-0016's
one-run-one-sandbox rule).
_Avoid_: session grant, member grant (the member base grant covers lifetime RPCs only)

**Job node**:
`NODE_TYPE_JOB`, the mission node that drives a job on a bank. Its executor runs the verify
loop internally: open the job, dispatch the acceptance step to the declared verifier
component, on failure send the verifier's report as the next input to the same job, repeat
up to the node's `RetryPolicy`, then `CloseJob` with verdict and score. The mission graph
stays a DAG: no loop edges. Only the job node executor and a person may call `CloseJob`.
The node declares acceptance: verifier component and passing score. Each pass is an attempt
in the run history.
_Avoid_: loop node, retry edge, agent node (that one launches an ephemeral sandbox)

## Flagged ambiguities (component authorization)

- **Canonical component object ref** — RESOLVED 2026-08-27: **`component:<kind>/<name>` for
  all four kinds** (prevents cross-kind name collisions; matches the dashboard + connectors).
  `authz/objects.go` `CanonicalComponentResource` must **apply** the kind prefix, not strip it;
  existing bare objects are re-keyed (`component:zerocool` → `component:agent/zerocool`); the
  team-only `SetComponentAccess` normaliser and every checker call-site move to the prefixed
  form. Fixes the agent/tool/plugin toggle "phantom object" bug (Defect C). Hard-to-reverse → ADR.

- **"Write" vs "Configure"** named the same relation (`can_configure`) in two UIs —
  resolved 2026-08-24: the UI says **Write** everywhere; docs state that Write maps
  to `can_configure`.
- **Contributor-doc home** — resolved 2026-08-24: the docs site
  (`opensource/docs-site`) is canonical for every contributor-facing procedure
  (Contributing section: add a component kind, change the FGA model, add an RPC).
  The gibson how-tos migrate there; `gibson/docs/` keeps ADRs (internal), a pointer
  file, and machine-facing material (`rules.yaml`, `forbidden-patterns.md`, regen
  commands). No sync pipeline — one prose copy.

## Relationships

- **OSS boundary:** gibson is **OSS and multi-tenant** (a self-hoster's teams get real
  tenancy with the per-tenant isolation above). The *only* commercial coupling is the payment
  gate, decoupled behind the **Entitlements provider**; `BillingService` + Stripe + `plans.yaml`
  live in the closed layer, not OSS gibson.
- **No cross-tenant anything** (see invariant above). Everything below is *within one tenant*.
- An **Application** has one **Repository**, many **Images** (each built from one
  Repository commit by one **Pipeline**), and many **Deployments** (each running one Image).
- An **Image** contains many **Packages**. A **Deployment** exposes zero or more **Hosts**.
- A **Finding** is an instance of exactly one **Vulnerability** and affects exactly one
  place (a Package, a Repository file, or a `Service`), and therefore one Application.
- A **Merge request** fixes one or more **Findings**; a **Pipeline** verifies a Finding by
  rescan. `verified` never follows from a merge alone.
- One **Always-on agent** watches exactly one **Application** and originates every **Scan
  mission** and **Fix** for it from inside its own long-lived **Mission**.
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

- "vulnerability" was used for both the CVE identity and its occurrence in a place —
  resolved 2026-08-30: **Vulnerability** is the identity (no status), **Finding** is the
  occurrence (holds the status). One CVE across four Applications is one Vulnerability and
  four Findings.
- "the user launches a Mission and gets a report" (the **Mission** definition above) is
  still true for the long-lived Mission of an **Always-on agent**; the child **Scan
  missions** and **Fixes** are launched by the agent under ADR-0063. The person is the
  originator of record for the whole tree.
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
     capture merge_group check-run context strings before requiring any of them.
     canary #2: forces a real merge-group with one verified required check so the
     other merge_group-triggered workflows fire alongside it. -->
