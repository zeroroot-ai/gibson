-- WARNING: a rollback turns every unknown ceiling into the empty list, and an
-- empty list allows every capability of the principal on a re-registration.
-- Enroll the affected hosts again with a bootstrap token after a rollback.
UPDATE capability_grant_hosts SET capability_ceiling = '[]'::jsonb WHERE capability_ceiling IS NULL;
ALTER TABLE capability_grant_hosts ALTER COLUMN capability_ceiling SET DEFAULT '[]'::jsonb;
ALTER TABLE capability_grant_hosts ALTER COLUMN capability_ceiling SET NOT NULL;
