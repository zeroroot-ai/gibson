-- Bootstrap-credential consumption record (ADR-0045, gibson#648).
--
-- ADR-0045 specifies the enrollment credential as ONE-TIME: a component
-- exchanges it for a persistent Ed25519 host key on first registration and
-- never presents it again. Nothing recorded that exchange, so the invariant was
-- documented but not enforced — the same credential registered a new, fully
-- independent component identity on every presentation.
--
-- This table is that record. RegisterCapabilityGrant inserts one row per
-- accepted enrollment inside the SAME transaction as the host upsert and the
-- agent insert: the primary key makes the second presentation of a credential a
-- conflict, the conflict aborts the transaction, and no identity is written.
--
-- token_hash is the SHA-256 (hex) of the presented credential, never the
-- credential itself: the row must be worthless to anyone who reads the table.
-- Hashing the whole credential rather than storing its `jti` also keeps the
-- record derivable at the point of use without a second, unverified parse of
-- the token — an Ed25519 JWS is deterministic and every claim is covered by the
-- signature, so one credential has exactly one hash.
CREATE TABLE IF NOT EXISTS capability_grant_bootstrap_consumptions (
    token_hash  TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL,
    host_id     TEXT NOT NULL,
    agent_id    TEXT NOT NULL,
    consumed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Retention sweep index. A credential cannot outlive the 24h maximum bootstrap
-- TTL, so a consumption row older than that can never match a still-valid
-- credential; enrollment prunes past a 48h margin so the table stays bounded
-- without a separate job.
CREATE INDEX IF NOT EXISTS idx_capability_grant_bootstrap_consumptions_consumed_at
    ON capability_grant_bootstrap_consumptions(consumed_at);
