// Package admin contains cross-tenant platform-operator business logic for the
// Gibson daemon. Code in this package may span multiple tenant data-plane
// connections via internal/datapool/admin.AdminPool.
//
// # Scope
//
// This package is the ONLY location in the daemon where cross-tenant data
// access is permitted. It is guarded by:
//
//   - CODEOWNERS: changes require security review (platform-architecture +
//     security teams).
//   - gibsoncheck: the adminpoolacquire analyzer flags any usage of
//     AdminPool.Acquire or AdminConn construction outside this package and
//     internal/datapool/admin/.
//
// # What belongs here
//
// Business logic that legitimately aggregates data across tenants:
//   - Billing usage aggregation (sum of token usage across all tenants for
//     invoice generation).
//   - Fleet health metrics (p99 latency, error rate across all tenants for
//     SRE dashboards).
//   - Platform-operator reporting (capacity planning, tenant growth analytics).
//   - Cross-tenant migration runner coordination (delegated to gibson-migrate
//     CLI but logically lives in this domain).
//
// # What does NOT belong here
//
// Per-tenant code paths that happen to be called by a platform-operator. Those
// go through normal datapool.Pool.For(tenant) in the relevant handler package.
//
// # Current status (Phase E)
//
// Phase E introduces the admin pool infrastructure. The cross-tenant business
// logic is thin at this stage because:
//
//   - Billing aggregation: not yet implemented (planned post-Phase-F).
//   - Fleet metrics: the reconciler.CatalogFanout spans tenants at the FGA
//     layer only (no data-plane access) and stays in internal/reconciler/.
//   - IntelligenceService (graphrag/intelligence): operates on a shared Neo4j
//     driver in Phase D; the per-admin-pool wiring is a Phase D/Phase E
//     cross-spec concern tracked under the graphrag refactor.
//
// As Phase D DAO refactoring lands and billing/reporting RPCs are implemented,
// this package will grow. All additions require a CODEOWNERS review.
//
// Spec: database-per-tenant-data-plane, Phase E, task 5.2.
// Requirements: 11.5.
package admin
