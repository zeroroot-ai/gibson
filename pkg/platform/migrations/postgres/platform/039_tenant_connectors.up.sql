-- gibson#662: the connectors each tenant enabled.
--
-- A row is what a tenant WANTS: one connector of the catalog, for that
-- tenant. ConnectorService writes the row. The connector operator reads the
-- desired state from the daemon, makes the ConnectorInstance, and reports
-- phase, discovered_tools and last_error back. The daemon makes no
-- Kubernetes call (ADR-0023).
CREATE TABLE IF NOT EXISTS tenant_connectors (
    tenant_id        TEXT        NOT NULL,
    connector_id     TEXT        NOT NULL,
    phase            TEXT        NOT NULL DEFAULT 'Pending',
    discovered_tools INTEGER     NOT NULL DEFAULT 0,
    last_error       TEXT        NOT NULL DEFAULT '',
    enabled_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reported_at      TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, connector_id)
);
