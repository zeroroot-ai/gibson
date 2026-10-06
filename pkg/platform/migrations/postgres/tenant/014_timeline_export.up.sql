-- 014_timeline_export.up.sql
--
-- The export and the retention of the Timeline history (ADR-0163 decision 4,
-- owner decision D31, gibson#992).
--
-- Retention follows the audit log. Postgres keeps each timeline_events row for
-- the audit retention period of the tenant (13 months at least, platform
-- table audit_retention_tenant). The export writes each row to the audit/
-- prefix of the durable bucket (ADR-0113). Retention removes only a row that
-- the export wrote and that is older than the period.
--
-- timeline_export — one row for the tenant.
--
-- Per-tenant database, so there is no tenant_id column (migration 010).

CREATE TABLE IF NOT EXISTS timeline_export (
    -- One row only: the key is always TRUE.
    id               BOOLEAN     PRIMARY KEY DEFAULT TRUE CHECK (id),
    -- The stream id of the last row that is in the bucket. -1, -1 is before
    -- each row: Redis assigns no negative part.
    exported_ms      BIGINT      NOT NULL DEFAULT -1,
    exported_seq     BIGINT      NOT NULL DEFAULT -1,
    -- The range that a write started and did not finish. After a restart the
    -- export writes this same range again, under the same object name.
    pending_first_ms  BIGINT,
    pending_first_seq BIGINT,
    pending_last_ms   BIGINT,
    pending_last_seq  BIGINT,
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
