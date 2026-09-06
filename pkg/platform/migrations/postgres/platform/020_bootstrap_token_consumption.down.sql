-- Reverses 020_bootstrap_token_consumption.up.sql.
--
-- Dropping the table restores unlimited reuse of an enrollment credential, so
-- this direction exists for migration symmetry only.
DROP INDEX IF EXISTS idx_capability_grant_bootstrap_consumptions_consumed_at;
DROP TABLE IF EXISTS capability_grant_bootstrap_consumptions;
