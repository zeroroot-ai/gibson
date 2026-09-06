# Untrusted execution is setec-isolated in hosted deployments; placement is a per-grant policy gated by deployment shape

> Realizes the open-core "ADR-0052" placeholder referenced by `gibson#813` (the
> 0050–0058 open-core-rearchitecture set was settled 2026-06-19 but left unfiled;
> this is its gibson-local landing, in the dispatch-ADR series next to ADR-0009).
> Status: **Accepted** (2026-06-24).

## Context

Gibson runs agent/tool/code execution that is, in the general case, **untrusted**:
third-party tools (`nmap`, `httpx`, `nuclei`, …) and customer-authored components
process attacker-controlled input. Today three signals already exist, spread
across the right seams:

- **`ComponentInfo.ContentTrust`** ∈ {`TRUSTED`, `UNTRUSTED`} — an *intrinsic*
  property of a component, on its descriptor (`internal/platform/component/registry.go`).
- **`ComponentInfo.DispatchMode`** ∈ {`SANDBOXED`, `AGENT`, `PLUGIN`} — *how*
  `harness.CallToolProto` routes a call. `SANDBOXED` dispatches to setec's
  `SandboxService.Launch` (`internal/engine/harness/sandboxed/Executor`).
- The invariant **`content_trust=UNTRUSTED ⇒ dispatch_mode=SANDBOXED`**, plus FGA
  for *execute permission* and the closed **entitlements seam** for plan/billing.

But `CallToolProto` has **four** dispatch paths and only one is isolated:
`dispatch_mode=SANDBOXED` (setec) is path 1; paths 2a (direct gRPC to a remote
tool's `grpc_endpoint`), 2b (`callToolViaWorkQueue` to a remote pod), and 3
(`registryAdapter` fallback gRPC) reach a tool **without** going through setec.
`gibson#813` (E10) requires "no in-process untrusted execution; all tool/code
exec via SandboxService," but left the *placement policy* — who isolates, where,
and whether it can be opted out of — undefined. This ADR pins it.

The sharpening constraint from the product owner: **a customer must not be able
to execute tools inside the hosted SaaS product unless it is in setec.**

## Decision

### 1. Hard SaaS invariant (non-bypassable)

In the **hosted** deployment (multi-tenant, our infrastructure), no untrusted
tool or code executes anywhere except inside a setec sandbox. The dispatch policy
there is binary: **setec, or denied.** There is no customer-cluster-attested,
customer-self-sandbox, or unsandboxed mode in SaaS. This is **not**
entitlement-gated in the relaxing direction: a tenant that does not pay for
sandboxed execution **loses the capability** (untrusted execution is denied),
they are never downgraded to running unsandboxed on our infra.

### 2. Two layers: an intrinsic floor and a per-grant placement policy

- **Floor — intrinsic, on the descriptor.** `ContentTrust=UNTRUSTED` means
  "this MUST be isolated *somewhere*." Non-bypassable; a property of the
  component, identical for every tenant. (Unspecified is treated as `TRUSTED`
  only for first-party, daemon-shipped components; customer/third-party
  components default `UNTRUSTED`.)

- **Placement — per component-grant, scoped by deployment shape.** An isolation
  mode chosen on the capability grant:
  `isolation ∈ { hosted_sandbox, customer_cluster_attested, customer_self_sandbox, on_prem_sandbox_endpoint }`.
  **In SaaS the only permitted value is `hosted_sandbox`** (setec on our infra).
  The other three are valid **only** in customer-operated (on-prem / self-hosted)
  deployments, where the customer owns the isolation boundary — including
  `on_prem_sandbox_endpoint`, which reuses the same setec `SandboxService` v1
  contract pointed at a customer-run setec.

### 3. Seam ownership — no single store holds the matrix

| Concern | Seam |
|---|---|
| May principal X execute component Y | **FGA** (`component` execute relations / deny scopes) |
| Is this code intrinsically untrusted (the floor) | **Component descriptor** (`ContentTrust`) |
| Is hosted-sandbox in their plan / do they pay | **Entitlements seam** (closed billing, ADR-0003/0050/0054) |
| Which isolation mode applies | **Component-grant** (`isolation` enum, gated by deployment shape) |
| Concrete placement mechanics (setec endpoint, image, egress, resources) | **Registry / config** |

FGA stays the *permission* authority. It does **not** hold placement mechanics,
and — following the `plans-and-quotas-simplification` precedent that deleted the
unenforced `has_sso`/`has_audit_logs`/… feature-flag relations — it does not hold
plan flags either; entitlement-to-a-mode lives in the entitlements seam.

### 4. The chokepoint: a fail-closed dispatch-policy gate

A single dispatch-policy decision sits in front of every execution path (the
natural home is a consolidated `internal/sandbox` / dispatch package):

```
decide(contentTrust, dispatchMode, deploymentShape) →
    UNTRUSTED ∧ shape=SaaS              ⇒ require DISPATCH_MODE_SANDBOXED, else DENY
    UNTRUSTED ∧ shape=on-prem           ⇒ require grant.isolation ∈ {the four}, resolve endpoint
    TRUSTED  (first-party only)          ⇒ in-process / gRPC permitted
```

`CallToolProto`'s bypass paths (2a/2b/3) become **unreachable for UNTRUSTED
components in SaaS** — the gate runs before path selection and fail-closes to
"setec or deny" when any input is unknown.

### 5. Deployment-shape signal

Per the one-code-path rule (`GIBSON_MODE` was deleted; no multi-valued mode
enum), the SaaS-vs-on-prem signal is a **dedicated single-purpose flag**
validated at config load, modeled on `GIBSON_STRICT_TENANT` — e.g.
`GIBSON_UNTRUSTED_EXEC` ∈ {`setec-only`, `customer-isolation`}, **fail-closed to
`setec-only`** when unset or invalid. It gates only this decision; it is not a
revived deployment mode.

## Considered and rejected

- **Encode the placement matrix in FGA tuples.** Rejected: FGA is an
  authz/relationship engine. Placement mechanics (endpoint/image/egress) are not
  relationships, and the project already removed unenforced feature-flag
  relations from the model. FGA keeps the execute-permission gate only.
- **Let "won't pay for sandboxing" downgrade to unsandboxed in SaaS.** Rejected:
  violates the hard invariant. Non-payment denies the capability; it never
  relaxes isolation on our infra.
- **Treat remote-gRPC / WorkQueue tools as "already isolated" in SaaS.**
  Rejected: a separately-deployed gRPC tool is still our-infra untrusted
  execution unless it is a setec sandbox. "Deployed elsewhere" ≠ "isolated."
- **A global deployment-mode enum (`GIBSON_MODE` redux).** Rejected: violates the
  one-code-path rule. A single-purpose, fail-closed flag suffices.
- **Per-tenant opt-out of sandboxing in SaaS.** Rejected: same invariant.

## Consequences

- SaaS dispatch is fail-closed and trivially auditable: an `UNTRUSTED` component
  either runs in setec or returns a typed deny — no escape hatch, no per-tenant
  special-casing.
- On-prem flexibility is preserved without a second isolation engine: the
  `isolation` enum + a customer-pointed setec endpoint lets self-hosted operators
  own their boundary (and reuse our setec contract).
- `gibson#813` reduces to three sliceable pieces: (a) implement the fail-closed
  dispatch-policy gate keyed on `(ContentTrust, deploymentShape)`; (b) route
  every `CallToolProto` path (and the agent-delegation / code-exec / plugin
  paths) through it so UNTRUSTED-in-SaaS bypass is structurally impossible;
  (c) prove it with the E3 execution round-trip test — an `UNTRUSTED` tool can
  *only* complete via setec, and is denied when the sandbox is unavailable.
- The daemon must obtain `deploymentShape` from the new fail-closed flag before
  it serves any execution RPC; ambiguity resolves to `setec-only`.
- AC-3 of `gibson#813` (E3 round-trip) depends on the setec#63 privileged-KVM
  runner, so the final verification slice is Lane-B/C-gated even though the
  v1 `SandboxService` contract (setec#64) is already closed.
