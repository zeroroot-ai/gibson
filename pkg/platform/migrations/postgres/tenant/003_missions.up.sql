-- Phase D, Task 4.8: per-tenant missions table.
-- No tenant_id column — the tenant is implied by which database this table lives in.
-- Missions are stored as JSON documents in the document column for flexibility.

-- The missions_name_trgm_idx below uses gin_trgm_ops, which requires the pg_trgm
-- extension. On kind/CNPG pg_trgm is inherited from template1, but a fresh
-- Aurora/RDS tenant database does not have it, so the index creation failed with
-- "operator class gin_trgm_ops does not exist" and left schema_migrations dirty
-- at version 3 — permanently blocking tenant data-plane provisioning (gibson#738).
-- pg_trgm is a trusted extension (PG13+), so the tenant database owner
-- can create it without superuser. Make the migration self-contained.
CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE TABLE IF NOT EXISTS missions (
    id          UUID        PRIMARY KEY,
    name        TEXT        NOT NULL,
    status      TEXT        NOT NULL DEFAULT 'pending',
    document    JSONB       NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Index to support listing by status.
CREATE INDEX IF NOT EXISTS missions_status_idx ON missions (status);

-- Index to support listing by name.
CREATE INDEX IF NOT EXISTS missions_name_idx ON missions (name);

-- Index to support full-text search on mission name.
CREATE INDEX IF NOT EXISTS missions_name_trgm_idx ON missions USING gin (name gin_trgm_ops);

COMMENT ON TABLE missions IS 'Tenant-scoped mission records. One row per mission instance. No tenant_id — isolation is by database.';
COMMENT ON COLUMN missions.id IS 'Mission UUID, globally unique.';
COMMENT ON COLUMN missions.name IS 'Human-readable mission name.';
COMMENT ON COLUMN missions.status IS 'Lifecycle state: pending, running, paused, completed, failed, cancelled.';
COMMENT ON COLUMN missions.document IS 'Full mission JSON document.';
