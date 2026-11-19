-- 021_outside_agent_ca_bundle.down.sql — drop the CA bundle column of outside agents.
ALTER TABLE outside_agents DROP COLUMN IF EXISTS ca_bundle_secret;
