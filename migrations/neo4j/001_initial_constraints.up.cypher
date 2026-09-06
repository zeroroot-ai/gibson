// Phase D, Task 4.9: per-tenant Neo4j schema constraints and indexes.
// No tenant_id property — tenant isolation is provided by the per-tenant
// Neo4j database (database-per-tenant-data-plane, Requirement 2.6).
//
// Every tenant database receives these constraints/indexes on provisioning.
// All constraints use IF NOT EXISTS for idempotency.

// ---------------------------------------------------------------------------
// Uniqueness constraints
// ---------------------------------------------------------------------------

CREATE CONSTRAINT IF NOT EXISTS FOR (m:mission) REQUIRE m.id IS UNIQUE

CREATE CONSTRAINT IF NOT EXISTS FOR (r:mission_run) REQUIRE r.id IS UNIQUE

CREATE CONSTRAINT IF NOT EXISTS FOR (f:finding) REQUIRE f.id IS UNIQUE

CREATE CONSTRAINT IF NOT EXISTS FOR (h:host) REQUIRE h.id IS UNIQUE

CREATE CONSTRAINT IF NOT EXISTS FOR (p:port) REQUIRE p.id IS UNIQUE

CREATE CONSTRAINT IF NOT EXISTS FOR (s:service) REQUIRE s.id IS UNIQUE

CREATE CONSTRAINT IF NOT EXISTS FOR (e:endpoint) REQUIRE e.id IS UNIQUE

CREATE CONSTRAINT IF NOT EXISTS FOR (d:domain) REQUIRE d.id IS UNIQUE

CREATE CONSTRAINT IF NOT EXISTS FOR (sd:subdomain) REQUIRE sd.id IS UNIQUE

CREATE CONSTRAINT IF NOT EXISTS FOR (t:technology) REQUIRE t.id IS UNIQUE

CREATE CONSTRAINT IF NOT EXISTS FOR (c:certificate) REQUIRE c.id IS UNIQUE

CREATE CONSTRAINT IF NOT EXISTS FOR (ev:evidence) REQUIRE ev.id IS UNIQUE

CREATE CONSTRAINT IF NOT EXISTS FOR (tc:technique) REQUIRE tc.id IS UNIQUE

CREATE CONSTRAINT IF NOT EXISTS FOR (cs:compliance_signal) REQUIRE cs.id IS UNIQUE

// ---------------------------------------------------------------------------
// Migration tracking node uniqueness
// ---------------------------------------------------------------------------

CREATE CONSTRAINT IF NOT EXISTS FOR (n:_GibsonSchemaMigration) REQUIRE n.migration_id IS UNIQUE

// ---------------------------------------------------------------------------
// Performance indexes
// ---------------------------------------------------------------------------

CREATE INDEX IF NOT EXISTS FOR (n) ON (n.id)

CREATE INDEX IF NOT EXISTS FOR (n) ON (n.mission_run_id)

CREATE INDEX IF NOT EXISTS FOR (n:mission_run) ON (n.id)

CREATE INDEX IF NOT EXISTS FOR (n:mission) ON (n.id)

CREATE INDEX IF NOT EXISTS FOR (n) ON (n.discovered_by)

CREATE INDEX IF NOT EXISTS FOR (n:mission) ON (n.name, n.target_id)
