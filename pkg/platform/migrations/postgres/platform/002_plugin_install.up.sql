-- plugin-runtime Spec 2, Phase 7, Task 13: plugin_install table.
--
-- Stores persistent state for every registered plugin install. Transient
-- runtime state (address, last_heartbeat_at, status) is maintained in Redis
-- with a 90-second TTL refreshed on each Heartbeat call. When the Redis key
-- expires the install is treated as unreachable and excluded from dispatch.
--
-- This table lives in the operator-shared (dashboard) Postgres — the same
-- instance as tenant_secrets_broker_config — as an interim home until the
-- tenant control-plane store ships per the tenant-control-plane-foundation spec.
--
-- The UNIQUE constraint on (tenant_id, plugin_name, host_id) enforces that the
-- same physical host (identified by its Ed25519 host-key JWK thumbprint) can
-- only have one registered install of a given plugin per tenant at a time.
-- Idempotent re-registration updates the existing row via ON CONFLICT upsert.
--
-- declared_methods is a JSONB array of method-name strings, e.g.:
--   ["scan", "fingerprint"]
-- It is stored in JSONB so that the PluginInvoke handler can perform a fast
-- method-membership check without deserializing a full descriptor set.
--
-- proto_descriptor_set is the serialised google.protobuf.FileDescriptorSet
-- (wire-format bytes) uploaded at registration so the daemon can dispatch
-- typed invocations without trusting the plugin's claimed shape mid-flight.

CREATE TABLE plugin_install (
    id                   UUID        NOT NULL,
    tenant_id            UUID        NOT NULL,
    plugin_name          TEXT        NOT NULL,
    version              TEXT        NOT NULL,
    manifest_hash        TEXT        NOT NULL,
    declared_methods     JSONB       NOT NULL DEFAULT '[]',
    proto_descriptor_set BYTEA       NOT NULL DEFAULT '',
    host_id              TEXT        NOT NULL,
    runtime_mode         TEXT        NOT NULL DEFAULT 'process',
    setec_required       BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by           TEXT        NOT NULL,

    CONSTRAINT plugin_install_pkey PRIMARY KEY (id),
    CONSTRAINT plugin_install_unique_host
        UNIQUE (tenant_id, plugin_name, host_id)
);

CREATE INDEX idx_plugin_install_tenant_name
    ON plugin_install (tenant_id, plugin_name);

COMMENT ON TABLE plugin_install IS
    'Persistent registry for plugin installs. Transient runtime state (address, heartbeat, status) is tracked in Redis with a 90-second TTL.';
COMMENT ON COLUMN plugin_install.id IS
    'UUID assigned by the daemon at registration time.';
COMMENT ON COLUMN plugin_install.tenant_id IS
    'Tenant that owns this plugin install.';
COMMENT ON COLUMN plugin_install.plugin_name IS
    'Canonical plugin name from the manifest metadata.name field.';
COMMENT ON COLUMN plugin_install.version IS
    'Plugin version from manifest metadata.version (semver).';
COMMENT ON COLUMN plugin_install.manifest_hash IS
    'SHA-256 hex digest of the raw manifest YAML bytes uploaded at registration.';
COMMENT ON COLUMN plugin_install.declared_methods IS
    'JSON array of method-name strings from manifest spec.methods[].name.';
COMMENT ON COLUMN plugin_install.proto_descriptor_set IS
    'Serialized google.protobuf.FileDescriptorSet wire bytes for typed dispatch.';
COMMENT ON COLUMN plugin_install.host_id IS
    'RFC 7638 JWK thumbprint of the registered Ed25519 host key.';
COMMENT ON COLUMN plugin_install.runtime_mode IS
    'Runtime mode: process | pod | setec.';
COMMENT ON COLUMN plugin_install.setec_required IS
    'True when the manifest declares spec.policy.setec_required: true.';
COMMENT ON COLUMN plugin_install.created_by IS
    'Actor principal (host_id or user subject) that registered this install.';
