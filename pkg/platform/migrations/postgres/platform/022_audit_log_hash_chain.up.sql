-- audit_log: create the table the daemon's audit Writer has always written to,
-- and give it a per-tenant hash chain so an altered or deleted record is
-- detectable.
--
-- Two problems are fixed here.
--
-- 1. The table had no DDL anywhere in the repo. internal/platform/audit/
--    writer.go INSERTs into audit_log and query.go SELECTs from it, but the
--    only CREATE TABLE was inside an integration test's own container setup.
--    The column set below is that contract, verbatim: id/created_at are
--    server-defaulted, decision is NULLable (Writer stores an empty Decision
--    as NULL), and metadata is BYTEA because Writer passes a []byte parameter
--    through lib/pq — a JSONB column rejects that without an explicit cast.
--
-- 2. Nothing linked one record to the next, so deleting or editing a row left
--    no trace. Each row now carries chain_seq / prev_hash / entry_hash, where
--    entry_hash = SHA-256 over a length-prefixed encoding of the row's own
--    fields plus prev_hash. Deleting a row breaks both the chain_seq run and
--    the successor's prev_hash link; editing a field breaks that row's
--    entry_hash. The chain is built and verified in Go — see chain.go.
--
-- Limits, stated plainly so nobody over-trusts this: an unkeyed hash chain
-- detects tampering by an actor who cannot rewrite the whole tail of a
-- tenant's chain. An actor with unrestricted write access to the table can
-- recompute the chain end-to-end. Detecting that needs the chain head
-- anchored somewhere the actor cannot reach (external notarisation or a
-- signing key held off-box), which this migration does not attempt.

CREATE TABLE IF NOT EXISTS audit_log (
    id          BIGSERIAL   PRIMARY KEY,
    tenant_id   TEXT        NOT NULL,
    actor_id    TEXT        NOT NULL,
    actor_type  TEXT        NOT NULL,
    action      TEXT        NOT NULL,
    target_type TEXT,
    target_id   TEXT,
    decision    TEXT,
    metadata    BYTEA       NOT NULL DEFAULT '\x7b7d'::bytea,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Chain columns are added separately (and nullably) so the migration is
-- correct against an environment where audit_log was provisioned
-- out-of-band before this migration existed.
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS chain_seq  BIGINT;
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS prev_hash  BYTEA;
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS entry_hash BYTEA;

COMMENT ON COLUMN audit_log.chain_seq IS
    'Per-tenant chain position, 1-based and gapless. NULL marks a row written before this migration: such rows are outside the chain and VerifyChain reports them as unchained rather than as verified.';
COMMENT ON COLUMN audit_log.prev_hash IS
    'entry_hash of the preceding row in this tenant chain; 32 zero bytes for the first row.';
COMMENT ON COLUMN audit_log.entry_hash IS
    'SHA-256 over the length-prefixed encoding of prev_hash plus this row''s own fields. Recomputed by audit.Query.VerifyChain.';

-- Rejects a second row claiming a chain position already taken, so two
-- concurrent writers fork the chain loudly (constraint violation) instead of
-- silently. Partial, because pre-migration rows carry NULL chain_seq.
CREATE UNIQUE INDEX IF NOT EXISTS audit_log_tenant_chain_seq_key
    ON audit_log (tenant_id, chain_seq)
    WHERE chain_seq IS NOT NULL;

-- Serves Query.List, which always filters on tenant_id and orders by
-- created_at DESC.
CREATE INDEX IF NOT EXISTS audit_log_tenant_created_at_idx
    ON audit_log (tenant_id, created_at DESC);
