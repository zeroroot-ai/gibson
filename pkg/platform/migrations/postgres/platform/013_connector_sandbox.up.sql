-- gibson#722 (PRD gibson#721): inventory of running per-tenant connector
-- sandboxes. The on-enable reconciler reads this to stay idempotent (exactly
-- one sandbox per (tenant, connector)) and to locate sandboxes to tear down
-- when a connector is disabled (gibson#723).
CREATE TABLE connector_sandbox (
    tenant_id      TEXT        NOT NULL,
    connector_name TEXT        NOT NULL,
    sandbox_id     TEXT        NOT NULL,
    launched_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, connector_name)
);
COMMENT ON TABLE connector_sandbox IS
    'Inventory of running per-tenant connector setec sandboxes (gibson#721). One row per (tenant, connector); sandbox_id is the setec sandbox handle.';
