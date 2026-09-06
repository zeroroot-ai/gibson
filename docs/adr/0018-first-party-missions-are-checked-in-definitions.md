# First-party missions are checked-in definitions, not catalog components

A **Mission** gibson ships — the Scan mission the always-on agent originates on
every pipeline — needs a home in the repository, a way to reach the daemon, and a
way for a person to run it by hand. This ADR decides that home. It builds on
[ADR-0015](0015-platform-component-catalog.md) (the platform component catalog)
and [ADR-0017](0017-tools-are-manifest-seeded-components.md) (tools joined it),
and it deliberately declines to extend either.

## Context

Every first-party thing gibson ships now lives in one place:
`internal/platform/componentcatalog/manifests/*.yaml`, embedded in the signed
image, seeded `platform_enabled` at boot, switched on per tenant by
`tenant_enabled`, and dispatched only when `can_execute` passes. Four kinds ride
that path — agent, tool, plugin, connector — and `authz.ComponentObject` renders
each as `component:<kind>/<name>` against the single FGA `component` type
(ADR-0046/0067).

The Scan mission is the first first-party **Mission**, and the obvious cheap move
is a fifth kind: `kind: mission` in the same catalog, `component:mission/scan`,
gated the same way. We are not doing that.

A Mission is not a component. `CONTEXT.md` defines a **Mission** as a *Work-graph
scoped to a tenant — the unit of identity, goal, and accounting*. A component is
the opposite end of that relationship: the thing a mission **dispatches**. The
catalog's whole vocabulary assumes the dispatched end. `tenant_enabled` means "this
tenant may run this component"; `can_execute` gates a dispatch; a `WorkloadSpec`
pins an image by signed digest and declares an egress ceiling. A Mission has no
image, no egress of its own, and is never dispatched — it is authored, launched,
and accounted for. Gating one on `can_execute` would be a category error, and it
would put a work-graph and the tools it calls behind the same tuple, so revoking a
tool would read as revoking the mission that uses it.

There is a second reason, and it is the one that actually bites. The always-on
agent already builds this mission: `scanMissionDefinition` in the zerocool watch
loop constructs the full definition as protojson and sends it on
`CreateMission`. If gibson also checked in a definition, the same mission would
exist twice, in two languages, drifting apart the first time either side changed.
That is precisely the parallel codepath ADR-0027 forbids.

## Decision

**First-party missions live in their own embedded catalog,
`internal/platform/missioncatalog`, and are the single definition of the mission
they describe.**

1. **A separate package, not a fifth component kind.** `missioncatalog` embeds
   `missions/*.cue` and loads them at boot the way `componentcatalog` loads
   manifests. It shares the loading shape, not the authorization model: no
   `platform_enabled`, no `tenant_enabled`, no `component:` object. The kinds in
   `authz.ComponentObject` stay at four.

2. **CUE is the authoring format**, matching how a person authors any mission
   (`gibson mission submit`, the dashboard's CUE editor, the shipped templates).
   A first-party mission is an ordinary mission definition that happens to be
   checked in, so it stays readable by the same tools and validated by the same
   `ValidateMissionCUE` path. It gets no private schema.

3. **One definition, and the agent references it.** The checked-in definition is
   authoritative. `scanMissionDefinition` on the agent side is replaced by a
   reference to the mission by name plus its parameters, so there is exactly one
   place the fan-out is described. A person runs the same definition by hand for
   rehearsal.

4. **Authorization is unchanged and stays where it already is.** A mission is not
   gated; the components it dispatches are, node by node, exactly as they are
   today. A tenant that has not enabled `tool/trivy` gets a failed Trivy node and
   a mission that still runs its other nodes — the failure is legible and local,
   which is what fail-closed per component buys.

## Consequences

- There are now two embedded catalogs. That is the cost, and it is the honest
  one: they answer different questions, and collapsing them would mean teaching
  the component vocabulary a case it does not mean.
- A first-party mission cannot be turned off per tenant. Nothing needs that yet —
  a mission nobody originates never runs — and the per-component gates already
  bound what any mission can do. If per-tenant mission control is ever needed, it
  is a new relation on a new object type, not a fifth component kind.
- The agent and the daemon must agree on the parameter names a checked-in mission
  takes. That contract is stated in the definition itself and is the thing to
  change carefully.

## Considered options

1. **`kind: mission` in the component catalog.** Cheapest, and the reason this ADR
   exists. Rejected: it models a work-graph as a dispatchable component, puts a
   mission and its tools behind one tuple, and leaves `WorkloadSpec` fields
   meaningless on a kind that has no image.
2. **No gibson-side definition; the agent keeps building it.** Also cheap, and it
   is the status quo. Rejected: the mission is then invisible to anyone reading
   gibson, unrunnable by hand, and versioned with an agent image rather than with
   the daemon that executes it.
3. **A database-backed mission template table.** Rejected: a first-party mission
   ships with the image that runs it, the same as every other first-party thing;
   putting it in a table makes it mutable runtime state and invites drift between
   environments.
