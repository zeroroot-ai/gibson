# The platform component catalog: one publish, enable, and isolation model for all four kinds

A platform component is a first-party agent, tool, plugin, or connector that gibson
ships. This ADR decides how such a component enters the catalog, how a tenant turns
it on, who may publish it platform-wide, and how it is isolated at runtime. It
generalizes the connector catalog ([ADR-0014](0014-connectors-run-on-toolhive-behind-connectorinstance.md))
to all four kinds, so one model covers `agent`, `tool`, `plugin`, and `connector`.

This is a wholesale flip under `ADR-0027`
discipline: no parallel codepath, no flag. The `CatalogFanout` reconciler is
deleted, not kept behind a switch.

## Context

Today only connectors have a catalog. Agents, tools, and plugins have no
publish-or-enable path. The flagship agent `zerocool` exists as an FGA object owned
by a tenant, but nothing ever enabled it, so every action on it is denied — a
registered component that no tenant can run.

Two contradictions block a coherent model:

1. **Enablement is contradictory.** `catalog_fanout.go` auto-writes `tenant_enabled`
   to every tenant for every `platform_enabled` item, so a publish runs the
   component in all tenants at once. The connector flow is the opposite — a tenant
   opts in with `EnableConnector`. The two intents cannot both be right.

2. **The object ref is split.** `authz/objects.go` (`CanonicalComponentResource`)
   strips the kind to a bare `component:<name>` for agent/tool/plugin, while
   connectors keep `component:connector/<id>`. Live FGA proves the split
   (`component:zerocool` vs `component:connector/gitlab`). The dashboard follows the
   documented `component:<kind>/<name>` form, so its access writes land on a phantom
   object that holds no tuples — the agent/tool/plugin toggle is broken.

`platform_enabled` is the highest-privilege state in the system: it makes a
component available to every tenant. Who may set it, and how, is a security
decision, not a convenience.

## Decision

**1. One object ref for all four kinds: `component:<kind>/<name>`.**
`CanonicalComponentResource` applies the kind prefix, it never strips it. Existing
bare objects are re-keyed (`component:zerocool` → `component:agent/zerocool`). Every
checker call-site and the team-scoped `SetComponentAccess` normaliser move to the
prefixed form. This removes cross-kind name collisions — an agent and a tool of the
same name are now distinct objects — and fixes the toggle bug as a byproduct.

The re-key is a **reconciler reseed**, the house pattern for FGA tuple migration
(the connector `can_invoke` reseed already works this way): the component-authz
reconciler treats `component:<kind>/<name>` as the desired object, writes the
prefixed tuples, and deletes the bare ones. The kind comes from the component
registry; a bare tuple with no registry kind fails loud. No one-shot Job and no
dual-read window — gibson is one daemon image, so checkers cut over atomically. A
failing fixture seeds a bare tuple and asserts convergence to the prefixed form.

The toggle write-path is fixed in the same move. The deny write
(`SetComponentAccess`) is **generalized to all three deny scopes**: it derives the
subject *shape* from the relation's declared FGA type — `tenant_*_disabled →
tenant:<id>`, `team_*_disabled → team:<id>#member`, `user_*_disabled → user:<id>` —
never from a caller-supplied field, so the subject-confusion bug (a tenant id passed
as a `team_id`) cannot recur. The component *grant* (`component_*_enabled`) stays on
`GrantComponentPermissions` — a grant to a principal is a different operation, not a
parallel path. `describeDenyingGates` reads the real denying tuples instead of
fabricating `tenant_*_disabled`.

**2. Two states, never conflated.**
`platform_enabled @ system_tenant:_system` means the component is **listed** in every
tenant's catalog. `tenant_enabled @ tenant:<id>` means a tenant admin **turned it
on**. `tenant_enabled` is the only thing that makes a component run.

**3. Opt-in only. Publishing never runs a component.**
`CatalogFanout` is deleted. A publish never enables a component in any tenant and
never affects existing tenants retroactively. A new tenant starts **empty**: nothing
runs until an admin enables it. There is no starter set, no always-on baseline kind,
and no `defaultOn` manifest flag.

**4. Publishing is super-user-only and release-gated.**
The authority for `platform_enabled` is `system_tenant:_system#platform_operator`,
never a tenant role. Two structural locks stay: the model forbids any non-system
subject (`platform_enabled: [system_tenant]`), and the only writer is the daemon
catalog reconciler, which seeds from **manifests baked into the signed gibson
image**. There is no dynamic publish RPC or UI. A contributor opens a PR from a
workstation; the release and merge gate lands it. Because the catalog re-seeds at
boot, platform components are reproducible across a cluster rebuild; per-tenant
`tenant_enabled` is durable, backed-up database state, not re-derived.

**5. One discriminated manifest schema, reusing each kind's runtime type.**
A catalog manifest is a common envelope — `id`, `kind`, `displayName`,
`description`, `egressAllow` — plus a `spec` block discriminated by `kind`, each
variant embedding that kind's *existing* runtime type so the manifest cannot drift
from what the runtime accepts. `connector` embeds the `ConnectorInstance` spec
(today's `Entry` fields: shape/endpoint/image/transport/auth). `plugin` embeds the
plugin runtime (`process | pod | setec`, `image@digest`, SVID config). `tool`
embeds `contentTrust`/`dispatchMode` and a sandboxed `command`/`image@digest`
(ADR-0010). `agent` embeds the **same external-component hosting as a plugin**
(`process | pod | setec`, `image@digest`, SVID) **plus** agent policy (`model`,
`budgetLimit`) — an agent is a hosted workload, not in-image (decision 6), so one
shared workload spec backs both plugin and agent. One loader — `componentcatalog`,
replacing `connectorcatalog` — parses and validates per kind and seeds
`platform_enabled` for every kind, the way `SeedConnectorCatalogGate` does today.
Validation is fail-loud: an image-bearing kind (plugin, agent, hosted tool/connector)
whose image is not a signed digest is refused at load.

**6. Agents are external gRPC components, hosted exactly like plugins — one code path.** _Amended by [ADR-0016](0016-sandboxed-agent-dispatch.md): a code-executing agent is dispatched as an ephemeral, per-mission-run Setec sandbox (default gVisor), not a long-lived worker; dispatch is gated on `tenant_enabled`._
_Corrected 2026-08-28: the original decision said "first-party agents are trusted
in-image code, no pod/SVID." The code disproved it — that came from misreading
ADR-0010, which governs untrusted **tool** execution, not the agent process._
gibson runs an agent as an **external gRPC component**: the registry discovers it by
name and returns a gRPC client (`ComponentDiscovery.DiscoverAgent`), the same way it
serves plugins. So an agent is a **hosted workload**, identical to a plugin in how it
is packaged, enrolled, run, and isolated — `process | pod | setec` runtime, an
`image` pinned by signed digest, and a per-tenant SPIFFE SVID. It differs from a
plugin only in *role* (an LLM-driven worker with model/budget policy), never in
*hosting*. There is exactly **one** component-workload code path — agent, plugin, and
hosted tool/connector all travel it (ADR-0027); there is no separate in-image agent
runtime and none is built. First-party agents (e.g. `zerocool`) live in their own
component repo (`zerocool-plugins`) and are enrolled as external components.
`content_trust` still governs each **tool** an agent runs (untrusted tools are
setec-sandboxed, ADR-0010); the agent process itself is the hosted workload.

**7. Cross-tenant traffic is denied always; the egress envelope is applied where the pod is deployed.** _Amended by [ADR-0016](0016-sandboxed-agent-dispatch.md): an ephemeral per-run sandbox in the tenant namespace under default-deny is where an agent's isolation is enforced; network reach is blocked on every backend._
_Corrected 2026-08-28: gibson does not own the pods for agents or plugins, so an
operator cannot emit their per-workload NetworkPolicies. `AgentEnrollment` creates no
pod (it manages the FGA principal + grants for an external agent); first-party plugins
are GitOps-deployed from the operator's integrations fork; the only pods a gibson
operator makes are the tenant data-plane. The connector envelope works only because
ToolHive owns and labels connector pods._
The always-on floor is identical for every workload: it runs in a `tenant-<id>`
namespace under the `gibson-tenant-default-deny` NetworkPolicy (private ranges blocked
at L3 → no cross-tenant/in-cluster reach) and carries a per-tenant SPIFFE SVID. On top
of that floor, a per-workload NetworkPolicy derived from `egressAllow` opens exactly
what the component needs — **applied by whoever deploys the pod**: the connector-operator
for ToolHive pods; the **GitOps deploy manifest** for externally-deployed plugins and
agents. gibson provides **one shared `egressAllow`→NetworkPolicy derivation** for both
to consume — the derivation is one code path even though the pod owner is not.

**8. External egress is per-component; sandbox-isolation is a separate knob.** _Amended by [ADR-0016](0016-sandboxed-agent-dispatch.md): the sandbox backend (default gVisor) is the per-SandboxClass isolation knob for an agent; egress ceiling is separate._
Tool execution is **always** sandboxed (isolation is non-negotiable — ADR-0010); a
sandbox's egress *breadth* is an independent setting. Each manifest declares
`egressAllow`, the egress **ceiling**. For an agent it maps to the setec
`LaunchRequest.Egress` for that agent's tool dispatches: `zerocool` declares `["*"]`,
so its scan *and* web/research tools run sandboxed with egress-any (setec
`mode=full`); a red-team agent declares a target list, so the same tools run
sandboxed but egress-confined. For a hosted workload (plugin, **agent**, connector)
`egressAllow` also maps to the L7 permission profile plus the L3 policy, as connectors
do today — an agent, being a workload (decision 6), gets the same isolation envelope
(owned NetworkPolicy + per-tenant SVID) as any other workload, *and* its `egressAllow`
additionally bounds the setec `LaunchRequest.Egress` of the tools it dispatches. For
platform components the value lives in the image manifest — author-set and
release-gated. A tenant can never widen past the ceiling; a later extension may let a
mission narrow within it without a release.

**9. Component images are built from source and signed.**
The release pipeline builds each first-party component image from in-repo source,
signs it with cosign, and pins it by digest in the manifest. gibson does not run an
author-supplied binary platform-wide.

## Consequences

**Good.**

- One model for four kinds. The connector catalog stops being a special case.
- The agent/tool/plugin toggle bug is fixed by decision 1, not patched separately.
- A publish has the blast radius of one tenant's explicit choice, not the fleet.
- Platform components are reproducible across rebuilds; there is no privileged
  publish endpoint to defend.
- The "no cross-tenant anything" invariant now covers every hosted component, not
  just the data plane.

**Costs and risks.**

- An FGA object-ref migration: re-key existing bare objects and move every checker
  call-site to the prefixed form. Done once, guarded by a test.
- Deleting `CatalogFanout` changes new-tenant behavior to empty. Onboarding must
  enable the starter components explicitly.
- Changing a platform component's egress or targets needs a release. The later
  within-ceiling narrowing removes this for per-engagement targets.
- Build-from-source raises the bar to add a first-party component: a signed image
  plus a manifest PR, both through the release gate.

## Alternatives considered

- **Keep the auto-on fan-out.** Rejected — every publish becomes a fleet-wide change
  with maximal blast radius. This is the behavior that surprised the owner.
- **Bare object ref (strip the kind everywhere).** Rejected — an agent and a tool of
  the same name collapse into one FGA object and merge grants.
- **A live `platform_operator`-gated publish RPC or UI.** Rejected — a high-value
  privileged write endpoint to defend forever. The release gate gives the same
  control with a far smaller attack surface.
- **A separate GitOps catalog repo synced by Argo.** Rejected for now — the embedded
  image is more immutable and reuses the existing release signing. A GitOps catalog
  is a good later extension for a self-hosted customer that adds its own components
  (the `tenant_published` track).
- **Author-supplied component images.** Rejected — running an unvetted binary in
  every tenant is a supply-chain break.

## Status

Proposed. Extends [ADR-0014](0014-connectors-run-on-toolhive-behind-connectorinstance.md)
to all four component kinds.
