-- Phase D, Task 4.8: per-tenant findings table.
-- No tenant_id column — the tenant is implied by which database this table lives in.

CREATE TABLE IF NOT EXISTS findings (
    id          UUID        PRIMARY KEY,
    mission_id  UUID        NOT NULL,
    severity    TEXT        NOT NULL DEFAULT 'info',
    title       TEXT        NOT NULL,
    document    JSONB       NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Index to support listing by mission.
CREATE INDEX IF NOT EXISTS findings_mission_idx ON findings (mission_id);

-- Index to support filtering by severity.
CREATE INDEX IF NOT EXISTS findings_severity_idx ON findings (severity);

-- Combined index for mission + severity queries.
CREATE INDEX IF NOT EXISTS findings_mission_severity_idx ON findings (mission_id, severity);

COMMENT ON TABLE findings IS 'Tenant-scoped security findings. One row per finding. No tenant_id — isolation is by database.';
COMMENT ON COLUMN findings.id IS 'Finding UUID, globally unique.';
COMMENT ON COLUMN findings.mission_id IS 'UUID of the mission that produced this finding.';
COMMENT ON COLUMN findings.severity IS 'Severity level: critical, high, medium, low, info.';
COMMENT ON COLUMN findings.title IS 'Short title for the finding.';
COMMENT ON COLUMN findings.document IS 'Full finding JSON document (EnhancedFinding).';
