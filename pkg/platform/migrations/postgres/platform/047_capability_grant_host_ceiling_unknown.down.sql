UPDATE capability_grant_hosts SET capability_ceiling = '[]'::jsonb WHERE capability_ceiling IS NULL;
ALTER TABLE capability_grant_hosts ALTER COLUMN capability_ceiling SET DEFAULT '[]'::jsonb;
ALTER TABLE capability_grant_hosts ALTER COLUMN capability_ceiling SET NOT NULL;
