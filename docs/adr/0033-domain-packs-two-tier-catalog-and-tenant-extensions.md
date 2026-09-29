# Domain Packs are two-tier: curated catalog packs and tenant extensions

Domain knowledge lives at two tiers. A **tenant extension** is discovered by a
tenant's own agents, approved by the tenant owner, and live in that one tenant as
event-sourced state. A **catalog pack** is curated by the platform owner, shipped
as SDK-sourced content via release/rollout, shared across tenants, and entitlement
-gated (free or paid). A tenant may nominate an extension upstream as a
**contribution** (a PR into the SDK). Builds on
[ADR-0024](0024-discoverable-taxonomy-and-ontology.md) /
[ADR-0025](0025-domain-packs.md). See [`CONTEXT.md`](../../CONTEXT.md). Issues:
#361, #362, #274, #281, #282.

## Context

The platform owner wants central control over what packs exist (and to charge for
them later), but also wants tenant agents to capture extension ideas so the model
grows without the owner developing in isolation, with the tenant owner seeing
every proposal. Those reconcile only if content lives at two tiers with different
scope, source, and control.

## Decision

1. **Two tiers.** *Tenant extension*: event-sourced, live in one tenant only,
   private, free. *Catalog pack*: SDK source of truth, versioned, shipped via
   release/rollout, shared, entitlement-gated. A pack is **pure data** — taxonomy
   / ontology structure + CEL predicates ([ADR-0031](0031-settlement-predicates-are-cel-over-a-gibson-environment.md))
   — never code.

2. **Lifecycle with a gate at every transition.** Agent captures →
   **proposal** (through the ValidIdentifier safety gate; `PromotionGate` observes
   recurrence and de-dupes) → **explicit tenant-owner approval** →
   **tenant extension** (live, per-tenant, mission-pinned) → owner "submit
   upstream" → **contribution** (a PR into the SDK, which anyone may open) →
   platform-owner review + merge + rollout → **catalog pack** → tenant enable
   toggle + entitlement check.

3. **Approval is explicit, human, per-proposal.** No auto-promotion: every
   proposal requires the tenant owner's approval before it goes live. Submit-
   upstream is available only from a live tenant extension (a tenant vouches for
   it by using it first).

4. **Content ships via rollout; enablement is an event.** Catalog-pack content
   never hot-reloads — it enters through the standard SDK → release → gibson bump
   → chart pin → Argo rollout pipeline, versioned and mission-pinned for replay
   ([ADR-0005](0005-belief-field-pgm.md) §5 discipline). Per-tenant
   enable/disable folds a `DomainPackEnabled` brain event (runtime state, not
   content). The core taxonomy/ontology stays SDK-embedded and always-on; the
   seed "main" pack is default-off.

5. **Commercial seam now, billing later.** A catalog pack carries `author`,
   `visibility`, and an optional `entitlement` key; enabling runs one entitlement
   check through the existing closed billing seam ([ADR-0003](0003-open-core-boundary.md)).
   Free by default; a future paid pack sets an entitlement key.

6. **Community contributions are safe by construction.** Because a pack is data
   (CEL + structure, bounded by ValidIdentifier and the gibson-owned CEL
   environment), accepting a PR from anyone injects no arbitrary code — the blast
   radius is bounded. Platform-owner PR review is the curation gate.

## Considered and rejected

- **Catalog-only (nothing live until the owner accepts it centrally).** Maximal
  control, but it bottlenecks every tenant's self-construction through the owner
  and defeats "onus on the agents."
- **Auto-promotion of proposals.** Rejected for v1: the owner wants to see and
  approve every proposal.
- **Hot-reloadable pack content.** Rejected: SDK is the source of truth; versioned
  rollouts keep replay deterministic and the supply chain auditable.

## Consequences

`DomainPack` grows technique→predicate (CEL) bindings and commercial metadata.
Three surfaces appear: a proposal/approval flow (tenant), a `DomainPackService`
catalog + enable/disable, and a contribution path (SDK PRs). The platform owner
holds absolute control over the shared, monetizable catalog without gating each
tenant's private extensions. A future pack marketplace is a config change, not a
re-architecture.
