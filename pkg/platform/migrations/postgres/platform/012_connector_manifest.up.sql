-- gibson#722 (PRD gibson#721): persist the raw connector manifest YAML so the
-- on-enable reconciler can launch a per-tenant setec sandbox from it.
-- component_install stores only a manifest_hash; the launcher needs the full
-- manifest. Keyed by (tenant_id, connector_name). A tenant's own row holds the
-- manifest it registered (BYO); the system tenant's row holds a shared
-- (platform_enabled) connector's published definition (gibson#725).
CREATE TABLE connector_manifest (
    tenant_id      TEXT        NOT NULL,
    connector_name TEXT        NOT NULL,
    manifest_yaml  BYTEA       NOT NULL,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, connector_name)
);
COMMENT ON TABLE connector_manifest IS
    'Raw connector manifest YAML, keyed by (tenant, connector). Source of truth the on-enable sandbox reconciler (gibson#721) launches from; component_install only keeps a manifest_hash.';
