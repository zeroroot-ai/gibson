# Sandboxed agent dispatch and the platform-agent isolation model

A platform agent is a first-party agent that gibson ships and runs for many
tenants — the flagship is `zerocool`, an opencode-driven coding agent. This ADR
decides how such an agent runs so that one compromised run can never reach
another tenant. It amends [ADR-0015](0015-platform-component-catalog.md)
(decisions 6, 7, 8) and extends `ADR-0010`
(untrusted execution is always sandboxed) to the agent process itself.

## Context

ADR-0015 said an agent is an external gRPC component hosted exactly like a
plugin: a long-lived workload that registers with a SPIFFE SVID and polls a work
queue. Tracing the code proved that model is the wrong foundation for a
code-executing agent.

1. **A long-lived shared worker is a cross-tenant surface.** One `zerocool`
   process serving every tenant's dispatches holds many tenants' per-dispatch
   grants over its lifetime. The per-dispatch capability-grant JWT scopes
   *authorization* per task, but it does not isolate the *process*. opencode runs
   arbitrary tool code. A code-execution compromise inside that shared process
   (prompt injection into a code-running tool, or an opencode defect) can read
   other tenants' in-flight work and harvest their grants. Authorization scoping
   is not process isolation.

2. **The isolated primitive already exists — for tools, not agents.** A
   `DispatchMode=SANDBOXED` tool runs in an ephemeral Setec sandbox per call, with
   the tenant's egress envelope, torn down after. The harness explicitly refuses
   the same for an agent: *"there is no sandboxed agent dispatch, so an untrusted
   agent must not run in-process under setec-only — deny it."* So a code-executing
   agent either runs unsandboxed in the shared worker or is denied.

3. **opencode is already headless and structured.** The dispatched agent runs
   `opencode run --format json`, which emits structured NDJSON events. There is no
   PTY and no interactive terminal in the running agent. A browser view of it is
   therefore a read-only render of structured events, not a shell.

## Decision

**1. A code-executing agent is dispatched as an ephemeral, per-mission-run Setec
sandbox — not a long-lived worker.** For an agent whose content trust is
untrusted, or whose manifest sets `dispatchMode: sandboxed`, the dispatch path
launches a fresh Setec sandbox for that one mission run, waits for the terminal
result, and lets it be torn down. A trusted first-party agent path is unchanged.
This generalizes the sandboxed-tool launch (ADR-0010) to the agent process. The
long-lived SVID-poll worker of ADR-0015 decision 6 is not built.

**2. The sandbox holds only that run's scope — nothing standing.** The daemon
injects into the sandbox the per-dispatch capability-grant JWT, scoped to that one
tenant and mission run with a short TTL, plus the tenant's egress envelope. The
agent has no standing tenant membership and no standing cross-tenant identity. The
grant reaches only the components that tenant has enabled and the mission target.
A compromise is contained to one tenant's one run, and the grant dies when the run
ends.

**3. Dispatch is gated on `tenant_enabled`.** Before a mission dispatches to an
agent, the daemon checks `can_execute` on the canonical `component:<kind>/<name>`
for the calling tenant. A tenant that has not enabled the agent is denied. Today
dispatch discovery keys only off live registrations and never consults the
enablement tuples, so a tenant could reach a component it never enabled. This
closes that gap.

**4. The isolation backend is a per-SandboxClass knob; the default is gVisor.**
Setec offers four backends. The default is `gvisor` — a user-space kernel that
contains a code-execution escape (only a filtered syscall subset reaches the host
kernel), needs no KVM, runs on ordinary managed-Kubernetes nodes, and costs about
40 MiB per sandbox. `runc` (shared host kernel, no escape containment) is for kind
and dev only. `kata-fc` and `kata-qemu` (microVMs) give a VM boundary but need
`/dev/kvm`, so they need bare-metal or nested-virt nodes; they are held for a
future high-assurance tenant tier. The backend is selected per SandboxClass, so
one cluster serves dev and production side by side.

**5. Cross-tenant network reach is blocked on every backend.** Each sandbox runs in
a `tenant-<id>` namespace under the namespace default-deny NetworkPolicy, which
severs private-range traffic in both directions. This holds regardless of the
compute backend. So even `runc`, which does not contain a kernel escape, does not
give a leaked run a path to another tenant over the network. The backend choice
governs escape containment; the namespace policy governs network reach.

**6. The browser console is read-only.** A tenant may watch its running agents in
the dashboard. The view renders the live structured NDJSON events into the existing
xterm terminal panel. There is no input path and no PTY, so "the viewer cannot
escape into the terminal" is a structural property, not a hardening task. A human
who wants to drive an agent interactively runs it locally. The stream surface
enumerates every running instance for the tenant and streams each one, so a tenant
with several concurrent runs sees them all. Enumeration and every per-instance
stream are authorized to the caller's tenant; a foreign instance id returns
not-found, never data. No client-side tenant filtering — the server enforces it.

**7. The agent's model and budget are resolved at dispatch, not baked in.** The
signed catalog manifest does not pin a model string. The dispatch path resolves the
newest available model for the tenant, and budget follows the tenant's default
through the entitlements seam. So the signed manifest does not go stale as models
ship, and a tenant's own budget bounds its runs.

**8. Concurrency is unbounded for now.** A tenant may run any number of agent
instances at once. This is deliberate for launch. A per-tenant concurrency cap,
plan- or entitlement-gated, is the first governance knob to add when cost or
resource abuse matters — an unbounded tenant can otherwise launch sandboxes without
limit.

## Consequences

**Good.**

- One compromised run reaches one tenant's one mission run — the strongest
  containment the platform can offer a code-executing agent.
- The isolation primitive (Setec sandboxed launch) is reused, not reinvented.
- gVisor gives real escape containment on ordinary nodes, so isolation does not
  force bare-metal spend.
- The read-only console cannot become a shell, by construction.
- Cost versus isolation is a per-SandboxClass dial, so dev, standard, and
  high-assurance tenants coexist in one cluster.

**Costs and risks.**

- A per-run sandbox is heavier than a shared worker: a launch per mission run
  instead of a resident process. Setec's pre-warm pool targets sub-100ms cold
  starts to soften this.
- gVisor needs the `runsc` binary and a `gvisor` RuntimeClass on the nodes. This is
  node preparation, not a node-type change.
- Unbounded concurrency lets one tenant consume node capacity until the governance
  knob lands.
- `runc` on a dev cluster does not contain a kernel escape. It is dev-only for that
  reason, and the default is gVisor.

## Alternatives considered

- **Long-lived shared SVID-poll worker (ADR-0015 decision 6 as written).**
  Rejected — one process serving all tenants is a cross-tenant surface under a
  code-execution compromise, which is the exact threat a code-running agent raises.
- **Per-tenant materialized agent principal.** Rejected — it duplicates the FGA
  subject per tenant and still leaves a shared process unless paired with a
  per-tenant sandbox, which is what this ADR does directly.
- **A raw PTY or interactive terminal into the sandbox.** Rejected — it would put a
  shell in the browser and make escape-prevention a permanent hardening burden. The
  read-only structured console removes the shell entirely.
- **microVM (`kata-fc`) as the default.** Rejected as the default — it needs
  `/dev/kvm`, so bare-metal or nested-virt nodes, which the estate does not require
  for the containment gVisor already gives. Kept as a per-tier option.

## Status

Proposed. Amends [ADR-0015](0015-platform-component-catalog.md) decisions 6, 7,
and 8. Tracked by the epic gibson#1593.

**Amended by [ADR-0019](0019-banks-of-always-on-agents.md) (2026-09-01).**
Decision 1 above — one mission run, one ephemeral sandbox — holds for a
one-shot dispatch. It does not hold for a bank member, which is a long-lived
sandbox owned by one principal that serves many dispatches over its life. Every
other decision here is unchanged for a member: the isolation backend, the
network posture, the tenant-enablement gate and the read-only console apply the
same way. Decision 2 is applied per turn rather than per run: a member holds a
base grant for lifetime RPCs, and every input carries the task grant of its own
dispatch. See [`docs/architecture/banks.md`](../architecture/banks.md).
