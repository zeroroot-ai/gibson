-- audit retention: a longer period for one tenant.
--
-- The install sets the retention period of audit_log with
-- GIBSON_AUDIT_RETENTION_MONTHS (13 months by default, and never less). A
-- tenant admin can set a longer period for the tenant with
-- TenantService.SetAuditRetention. Retention uses the longer of the two
-- periods (gibson#676). See internal/platform/audit/retention.go.

CREATE TABLE IF NOT EXISTS audit_retention_tenant (
    tenant_id  TEXT        PRIMARY KEY,
    months     INTEGER     NOT NULL CHECK (months >= 13),
    updated_by TEXT        NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE audit_retention_tenant IS
    'Audit retention period of one tenant, in months. Retention keeps the rows of the tenant for the longer of this period and the period of the install.';
