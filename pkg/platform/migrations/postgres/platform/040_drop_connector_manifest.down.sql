-- Restores the table of migration 012 (gibson#722).
CREATE TABLE connector_manifest (
    tenant_id      TEXT        NOT NULL,
    connector_name TEXT        NOT NULL,
    manifest_yaml  BYTEA       NOT NULL,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, connector_name)
);
COMMENT ON TABLE connector_manifest IS
    'Raw connector manifest YAML, keyed by (tenant, connector). Source of truth the on-enable sandbox reconciler (gibson#721) launches from; component_install only keeps a manifest_hash.';
