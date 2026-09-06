-- 021_signup_verification.down.sql
--
-- Dropping the table also drops its indexes. Rolling back re-opens signup to
-- unverified addresses, so this is a development convenience, not something to
-- run against a live control plane.
DROP TABLE IF EXISTS signup_verification;
