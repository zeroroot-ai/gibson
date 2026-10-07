-- What a host may become on re-registration.
--
-- A host that proves its key again (host+jwt) states no bootstrap credential.
-- The daemon therefore keeps the agent name and the capability ceiling of the
-- credential that enrolled the host, on the host row, and applies them on each
-- re-registration. The request body supplies neither.
--
-- A host row that exists before this migration gets the name of its newest
-- agent. Its ceiling is not recoverable, so it stays empty (no ceiling) until
-- the host enrolls again with a bootstrap token.
ALTER TABLE capability_grant_hosts
    ADD COLUMN IF NOT EXISTS agent_name TEXT NOT NULL DEFAULT '';
ALTER TABLE capability_grant_hosts
    ADD COLUMN IF NOT EXISTS capability_ceiling JSONB NOT NULL DEFAULT '[]'::jsonb;

UPDATE capability_grant_hosts h
SET    agent_name = COALESCE((
           SELECT a.name
           FROM   capability_grant_agents a
           WHERE  a.host_id = h.id AND a.tenant_id = h.tenant_id
           ORDER  BY a.created_at DESC
           LIMIT  1), '')
WHERE  h.agent_name = '';
