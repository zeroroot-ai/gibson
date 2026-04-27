-- Phase C, Task 3.3: per-tenant provider_configs table.
-- No tenant_id column — the tenant is implied by which database this table lives in.
-- The envelope column stores: wrapped_dek (40B) || nonce (12B) || aad_len (2B) || aad || ciphertext_with_tag
-- AAD = "providerconfig:<provider>:<name>" to prevent row-swap attacks.

CREATE TABLE IF NOT EXISTS provider_configs (
    provider    TEXT        NOT NULL,
    name        TEXT        NOT NULL,
    envelope    BYTEA       NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (provider, name)
);

-- Index to support listing by provider.
CREATE INDEX IF NOT EXISTS provider_configs_provider_idx ON provider_configs (provider);

COMMENT ON TABLE provider_configs IS 'Tenant-scoped encrypted LLM provider configs. One row per (provider, name). Envelope uses AES-Key-Wrap DEK + AES-256-GCM.';
COMMENT ON COLUMN provider_configs.provider IS 'Provider type identifier (e.g. "openai", "anthropic").';
COMMENT ON COLUMN provider_configs.name IS 'Logical name for this provider config (e.g. "prod-openai").';
COMMENT ON COLUMN provider_configs.envelope IS 'Binary envelope: wrapped_dek(40B) || nonce(12B) || aad_len(2B) || aad || ciphertext_with_tag.';
