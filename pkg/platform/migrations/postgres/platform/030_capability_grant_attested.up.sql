-- How a component enrolled (ADR-0066).
--
-- A component enrolls with a SPIRE JWT-SVID (a workload the platform attests,
-- in the cluster) or with a bootstrap token a tenant admin made (a workload
-- on the tenant's own machine). The daemon treats the two differently, so the
-- answer has to be a recorded fact and not a guess from the principal name.
--
-- The host row holds the fact. An agent row copies it from its host when the
-- agent enrolls, the same way it carries principal_ref. A row that exists
-- before this migration is not attested until the workload enrolls again.
ALTER TABLE capability_grant_hosts
    ADD COLUMN IF NOT EXISTS attested BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE capability_grant_agents
    ADD COLUMN IF NOT EXISTS attested BOOLEAN NOT NULL DEFAULT FALSE;
