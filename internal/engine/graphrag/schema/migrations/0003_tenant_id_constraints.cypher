// Migration 0003 — per-tenant database constraints (re-authored)
//
// Tenant isolation is now provided by the per-tenant Neo4j database
// (database-per-tenant-data-plane). The old tenant_id NOT NULL constraints
// and RANGE indexes have been removed.
//
// This migration is intentionally a no-op (no statements) so that existing
// deployments that have already applied migration 0003 continue to start
// cleanly. The ID is preserved to avoid the migrator re-running earlier
// migrations.
//
// The actual per-tenant schema (uniqueness constraints + indexes) is now
// applied by the tenant-operator provisioner from migrations/neo4j/
// at database-creation time, not by the daemon's schema migrator.
//
// Environments that previously had tenant_id NOT NULL constraints will
// find them satisfied vacuously (the per-tenant DB has no rows from other
// tenants, so no row can violate a tenant_id NOT NULL constraint on the
// old schema, and the constraints themselves are no longer created here).
