# Open-core boundary: multi-tenant OSS brain, commercial payment gate only

gibson is **OSS and multi-tenant** — a company self-hosting gets real per-team tenancy with
the per-tenant isolation in [ADR-0001](0001-ecs-native-mission-brain.md). Multi-tenancy is a
feature, not the commercial moat. See [`CONTEXT.md`](../../CONTEXT.md).

The **only** commercial coupling is the **payment gate**, decoupled behind a pluggable
**Entitlements provider**:

- The budget enforcer and rate limiter (which stay in OSS — a self-hoster wants to cap a
  team's spend/concurrency) consume *"what are this tenant's limits / what's enabled?"* from
  the Entitlements provider. They never read plans or Stripe directly.
- **OSS** ships a permissive/config-driven provider (admin-set quotas; no payment).
- **Commercial** ships the plan + subscription (Stripe) provider.
- `BillingService`, Stripe, and `plans.yaml` live **entirely** in the commercial layer —
  never in OSS gibson. Today `internal/server/daemon/billing_service.go` is in the brain; it moves
  out.
- The **curated belief base model** ([ADR-0005](0005-belief-field-pgm.md)) is also a commercial
  asset (trained only on vendor red-team + public data; **never tenant data**). OSS ships
  without it / with a minimal default. Tenant labels never feed it — learning is intra-tenant
  ([ADR-0006](0006-closed-loop-learning.md)).

## Considered and rejected

- **Single-tenant OSS brain + closed multi-tenant control plane.** Rejected: OSS
  self-hosters legitimately have many teams wanting tenancy; multi-tenancy belongs in the
  OSS core. (A recalled design note had proposed this; it's wrong for the goal.)
- **Billing/plans baked into the brain (status quo).** Can't ship as OSS; couples the core
  to Stripe and a specific plan model.

## Consequences

- `BillingService` + Stripe + `plans.yaml` relocate to the commercial layer; the brain gains
  an Entitlements-provider interface with an OSS default impl.
- The split is small and clean: everything else (multi-tenancy, the World, the brain, the
  SDK) is OSS; only the payment-driven policy source is commercial.
