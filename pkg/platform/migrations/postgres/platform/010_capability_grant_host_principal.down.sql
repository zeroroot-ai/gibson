-- Reverse 010_capability_grant_host_principal.up.sql.
ALTER TABLE capability_grant_hosts
    DROP COLUMN IF EXISTS principal_ref;
