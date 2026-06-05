-- Reverse 009_capability_grant_principal.up.sql.
ALTER TABLE capability_grant_agents
    DROP COLUMN IF EXISTS principal_ref;
