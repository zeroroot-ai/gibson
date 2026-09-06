-- secrets-broker Spec, Phase 7, Task 15: tenant_secrets_broker_config table.
--
-- Stores per-tenant broker configuration with the provider type and an
-- envelope-encrypted JSON config blob. The config column holds the
-- per-tenant auth credentials (Vault tokens, AWS keys, GCP SA JSON, Azure
-- client secrets) encrypted under the system-tenant KEK via the same
-- AES-Key-Wrap + AES-256-GCM envelope used elsewhere in the daemon.
--
-- AAD for the config blob: "tenant_secrets_broker_config:<tenant_id>"
--
-- This table lives in the operator-shared (dashboard) Postgres as an interim
-- home; migration to the tenant control-plane store is deferred until that
-- store ships per the tenant-control-plane-foundation spec.
--
-- created_by / updated_by record the operator principal that last modified
-- the row (actor_id from the request context, or "system" for daemon-internal
-- writes such as default-provider initialisation).

CREATE TABLE tenant_secrets_broker_config (
    tenant_id   UUID        NOT NULL PRIMARY KEY,
    provider    TEXT        NOT NULL,
    config      BYTEA       NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by  TEXT        NOT NULL,
    updated_by  TEXT        NOT NULL
);

COMMENT ON TABLE tenant_secrets_broker_config IS 'Per-tenant secrets broker configuration. The config column is an envelope-encrypted JSON blob containing provider-specific connection parameters.';
COMMENT ON COLUMN tenant_secrets_broker_config.tenant_id IS 'The tenant this broker config belongs to.';
COMMENT ON COLUMN tenant_secrets_broker_config.provider IS 'Provider type: postgres | vault | awssm | gcpsm | azurekv.';
COMMENT ON COLUMN tenant_secrets_broker_config.config IS 'Envelope-encrypted JSON: AES-Key-Wrap DEK + AES-256-GCM. AAD = "tenant_secrets_broker_config:<tenant_id>".';
COMMENT ON COLUMN tenant_secrets_broker_config.created_by IS 'Actor principal who created this row.';
COMMENT ON COLUMN tenant_secrets_broker_config.updated_by IS 'Actor principal who last updated this row.';
