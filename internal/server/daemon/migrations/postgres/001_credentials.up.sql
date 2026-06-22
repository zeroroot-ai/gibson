-- Phase C, Task 3.2: per-tenant credentials table.
-- No tenant_id column — the tenant is implied by which database this table lives in.
-- The envelope column stores: wrapped_dek (40B) || nonce (12B) || aad_len (2B) || aad || ciphertext_with_tag
-- See internal/datapool/envelope/ for the envelope format.

CREATE TABLE IF NOT EXISTS credentials (
    name        TEXT        PRIMARY KEY,
    envelope    BYTEA       NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE credentials IS 'Tenant-scoped encrypted credentials. One row per named credential. Envelope uses AES-Key-Wrap DEK + AES-256-GCM.';
COMMENT ON COLUMN credentials.name IS 'Logical name for the credential (e.g. "openai-prod").';
COMMENT ON COLUMN credentials.envelope IS 'Binary envelope: wrapped_dek(40B) || nonce(12B) || aad_len(2B) || aad || ciphertext_with_tag.';
