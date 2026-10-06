-- audit retention: the anchor of each hash chain.
--
-- Postgres audit_log is the durable copy of each audit record. Retention
-- removes the rows that are older than the retention period (13 months by
-- default, and never less).
--
-- audit_chain_anchor records where the hash chain of a tenant starts after
-- retention removed its oldest rows: the position of the oldest row that
-- remains, and the hash that this row points at. The writer and the verifier
-- start from the anchor. See internal/platform/audit/chain.go and
-- retention.go.

CREATE TABLE IF NOT EXISTS audit_chain_anchor (
    tenant_id TEXT        PRIMARY KEY,
    first_seq BIGINT      NOT NULL CHECK (first_seq >= 1),
    prev_hash BYTEA       NOT NULL CHECK (octet_length(prev_hash) = 32),
    pruned_at TIMESTAMPTZ NOT NULL
);

COMMENT ON TABLE audit_chain_anchor IS
    'Start of the audit hash chain of a tenant after retention: the chain_seq of the oldest row that remains, and the prev_hash of that row.';
