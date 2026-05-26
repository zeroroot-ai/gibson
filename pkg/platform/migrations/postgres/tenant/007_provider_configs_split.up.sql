-- 007_provider_configs_split.up.sql
--
-- Splits provider config storage so that plaintext metadata lives in its own
-- table and credentials flow exclusively through the secrets broker.
--
-- provider_configs      — plaintext metadata (type, model, flags, timestamps)
-- provider_config_meta  — key/value rows: __default pointer + __fallback_chain JSON
--
-- Credentials migrate out of tenant_secrets (old key "provider_config:<name>")
-- into the secrets broker (keys "provider_cred:<name>:<field>") on first read
-- per record — see internal/providerconfig/store_broker.go (lazy migration).
--
-- Spec: secrets-broker, Phase 2 Task 4.2; github.com/zero-day-ai/gibson#423.

CREATE TABLE IF NOT EXISTS provider_configs (
    id            TEXT        NOT NULL DEFAULT gen_random_uuid()::TEXT,
    name          TEXT        PRIMARY KEY,
    type          TEXT        NOT NULL,
    default_model TEXT        NOT NULL DEFAULT '',
    is_default    BOOLEAN     NOT NULL DEFAULT FALSE,
    enabled       BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS provider_config_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

COMMENT ON TABLE provider_configs IS 'Plaintext LLM provider config metadata. Credentials live in the secrets broker under provider_cred:<name>:<field>.';
COMMENT ON TABLE provider_config_meta IS 'Tenant-scoped provider config key/value metadata: __default (provider name) and __fallback_chain (JSON array).';
