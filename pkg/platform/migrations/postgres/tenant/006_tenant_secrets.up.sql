-- secrets-broker Spec, Phase 2, Task 4.1: unified tenant_secrets table.
--
-- Drops the two pre-release tables (credentials, provider_configs) and creates
-- the single unified tenant_secrets table.  No data preservation is needed —
-- this is a pre-release migration confirmed by the user.
--
-- The envelope column stores the same format as the old credentials table:
--   wrapped_dek (40B) || nonce (12B) || aad_len (2B) || aad || ciphertext_with_tag
-- AAD = "secret:<name>" (provider-agnostic; replaces the old "credential:<name>").
-- See internal/datapool/envelope/ for the envelope format.

DROP TABLE IF EXISTS credentials;
DROP TABLE IF EXISTS provider_configs;

CREATE TABLE tenant_secrets (
    name        TEXT        PRIMARY KEY,
    envelope    BYTEA       NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE tenant_secrets IS 'Unified tenant-scoped encrypted secrets. One row per named secret. Envelope uses AES-Key-Wrap DEK + AES-256-GCM.';
COMMENT ON COLUMN tenant_secrets.name IS 'Logical name for the secret (e.g. "cred:openai-prod", "provider_config:anthropic:default").';
COMMENT ON COLUMN tenant_secrets.envelope IS 'Binary envelope: wrapped_dek(40B) || nonce(12B) || aad_len(2B) || aad || ciphertext_with_tag. AAD = "secret:<name>".';
