-- Revert the audit_log hash chain.
--
-- The chain columns and their indexes go; the table itself does NOT. A down
-- migration that dropped audit_log would destroy the record this whole
-- change exists to protect, and would do it in exactly the situation where
-- someone is rolling back under pressure. Re-running the up migration is
-- safe against the surviving table (every statement is IF NOT EXISTS).

DROP INDEX IF EXISTS audit_log_tenant_chain_seq_key;
DROP INDEX IF EXISTS audit_log_tenant_created_at_idx;

ALTER TABLE audit_log DROP COLUMN IF EXISTS entry_hash;
ALTER TABLE audit_log DROP COLUMN IF EXISTS prev_hash;
ALTER TABLE audit_log DROP COLUMN IF EXISTS chain_seq;
