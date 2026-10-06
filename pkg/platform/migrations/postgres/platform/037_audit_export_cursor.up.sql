-- audit export: the position of the export of each tenant.
--
-- The exporter writes each audit_log row of a tenant, in chain order, to the
-- audit/ prefix of the durable bucket (ADR-0113, gibson#764).
-- audit_export_cursor holds, for each tenant, the last chain_seq that is in
-- the bucket. pending_first and pending_last name the range that the
-- exporter writes now. After a restart the exporter writes that range again
-- under the same object name, so no record is written under two names.
--
-- Retention removes only rows at or below exported_seq. See
-- internal/platform/audit/export.go and retention.go.

CREATE TABLE IF NOT EXISTS audit_export_cursor (
    tenant_id     TEXT        PRIMARY KEY,
    exported_seq  BIGINT      NOT NULL DEFAULT 0 CHECK (exported_seq >= 0),
    pending_first BIGINT,
    pending_last  BIGINT,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK ((pending_first IS NULL) = (pending_last IS NULL)),
    CHECK (pending_first IS NULL OR pending_first <= pending_last)
);

COMMENT ON TABLE audit_export_cursor IS
    'Export position of the audit chain of each tenant: the last chain_seq in the durable bucket, and the range being written.';
