-- Capability Grant host principal reference (epic unified-cg-identity, gibson#648).
--
-- Re-registration: a component that already holds a persisted Ed25519 host key
-- re-registers by signing a host+jwt (iss = host id) instead of presenting a
-- bootstrap token. The daemon verifies it against the host's stored public key
-- and re-issues a Capability Grant — but the new agent still needs the SAME
-- typed FGA principal so ext-authz can authorize it (the descriptor serves
-- principal_ref by kid). The agent+jwt sub/kid is per-agent, so the stable
-- principal must live on the HOST and be copied to each (re)registered agent.
-- migration 009 added principal_ref to capability_grant_agents; this adds it to
-- capability_grant_hosts so re-registration can reuse it without a bootstrap
-- token. Populated by RegisterCapabilityGrant on first registration.
ALTER TABLE capability_grant_hosts
    ADD COLUMN IF NOT EXISTS principal_ref TEXT NOT NULL DEFAULT '';
