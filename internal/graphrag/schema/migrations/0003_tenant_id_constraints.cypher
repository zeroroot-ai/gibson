// Migration 0003 — tenant_id NOT NULL constraints + range indexes
//
// Applies a NOT NULL constraint and a RANGE index on tenant_id for every
// tenant-scoped label written by the GraphLoader (loader/loader.go).
//
// Labels are taken directly from the taxonomy (taxonomy/core.yaml v4.0.0)
// and the GraphLoader node-type strings. They are all lowercase, matching
// the CREATE (n:<nodeType>) Cypher in loadProtoNodes.
//
// IF NOT EXISTS guards make every statement safe to re-run (idempotent).
// Do NOT drop existing indexes or constraints; only additions are made here.
//
// Labels covered: host, port, service, endpoint, domain, subdomain,
//                 technology, certificate, finding, evidence,
//                 technique, compliance_signal

CREATE CONSTRAINT IF NOT EXISTS FOR (n:host) REQUIRE n.tenant_id IS NOT NULL

CREATE RANGE INDEX IF NOT EXISTS FOR (n:host) ON (n.tenant_id)

CREATE CONSTRAINT IF NOT EXISTS FOR (n:port) REQUIRE n.tenant_id IS NOT NULL

CREATE RANGE INDEX IF NOT EXISTS FOR (n:port) ON (n.tenant_id)

CREATE CONSTRAINT IF NOT EXISTS FOR (n:service) REQUIRE n.tenant_id IS NOT NULL

CREATE RANGE INDEX IF NOT EXISTS FOR (n:service) ON (n.tenant_id)

CREATE CONSTRAINT IF NOT EXISTS FOR (n:endpoint) REQUIRE n.tenant_id IS NOT NULL

CREATE RANGE INDEX IF NOT EXISTS FOR (n:endpoint) ON (n.tenant_id)

CREATE CONSTRAINT IF NOT EXISTS FOR (n:domain) REQUIRE n.tenant_id IS NOT NULL

CREATE RANGE INDEX IF NOT EXISTS FOR (n:domain) ON (n.tenant_id)

CREATE CONSTRAINT IF NOT EXISTS FOR (n:subdomain) REQUIRE n.tenant_id IS NOT NULL

CREATE RANGE INDEX IF NOT EXISTS FOR (n:subdomain) ON (n.tenant_id)

CREATE CONSTRAINT IF NOT EXISTS FOR (n:technology) REQUIRE n.tenant_id IS NOT NULL

CREATE RANGE INDEX IF NOT EXISTS FOR (n:technology) ON (n.tenant_id)

CREATE CONSTRAINT IF NOT EXISTS FOR (n:certificate) REQUIRE n.tenant_id IS NOT NULL

CREATE RANGE INDEX IF NOT EXISTS FOR (n:certificate) ON (n.tenant_id)

CREATE CONSTRAINT IF NOT EXISTS FOR (n:finding) REQUIRE n.tenant_id IS NOT NULL

CREATE RANGE INDEX IF NOT EXISTS FOR (n:finding) ON (n.tenant_id)

CREATE CONSTRAINT IF NOT EXISTS FOR (n:evidence) REQUIRE n.tenant_id IS NOT NULL

CREATE RANGE INDEX IF NOT EXISTS FOR (n:evidence) ON (n.tenant_id)

CREATE CONSTRAINT IF NOT EXISTS FOR (n:technique) REQUIRE n.tenant_id IS NOT NULL

CREATE RANGE INDEX IF NOT EXISTS FOR (n:technique) ON (n.tenant_id)

CREATE CONSTRAINT IF NOT EXISTS FOR (n:compliance_signal) REQUIRE n.tenant_id IS NOT NULL

CREATE RANGE INDEX IF NOT EXISTS FOR (n:compliance_signal) ON (n.tenant_id)
