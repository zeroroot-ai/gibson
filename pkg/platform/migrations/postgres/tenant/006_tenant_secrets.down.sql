-- secrets-broker Spec, Phase 2, Task 4.1: rollback — drop tenant_secrets,
-- recreate empty credentials and provider_configs tables.
--
-- Matches the original schemas from 001_credentials.up.sql and
-- 002_provider_configs.up.sql. No data is restored — pre-release.

DROP TABLE IF EXISTS tenant_secrets;

CREATE TABLE IF NOT EXISTS credentials (
    name        TEXT        PRIMARY KEY,
    envelope    BYTEA       NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE credentials IS 'Tenant-scoped encrypted credentials. One row per named credential. Envelope uses AES-Key-Wrap DEK + AES-256-GCM.';
COMMENT ON COLUMN credentials.name IS 'Logical name for the credential (e.g. "openai-prod").';
COMMENT ON COLUMN credentials.envelope IS 'Binary envelope: wrapped_dek(40B) || nonce(12B) || aad_len(2B) || aad || ciphertext_with_tag.';

CREATE TABLE IF NOT EXISTS provider_configs (
    provider    TEXT        NOT NULL,
    name        TEXT        NOT NULL,
    envelope    BYTEA       NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (provider, name)
);

CREATE INDEX IF NOT EXISTS provider_configs_provider_idx ON provider_configs (provider);

COMMENT ON TABLE provider_configs IS 'Tenant-scoped encrypted LLM provider configs. One row per (provider, name). Envelope uses AES-Key-Wrap DEK + AES-256-GCM.';
COMMENT ON COLUMN provider_configs.provider IS 'Provider type identifier (e.g. "openai", "anthropic").';
COMMENT ON COLUMN provider_configs.name IS 'Logical name for this provider config (e.g. "prod-openai").';
COMMENT ON COLUMN provider_configs.envelope IS 'Binary envelope: wrapped_dek(40B) || nonce(12B) || aad_len(2B) || aad || ciphertext_with_tag.';
