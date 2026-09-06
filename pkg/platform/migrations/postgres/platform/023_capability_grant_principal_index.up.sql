-- Index the lookup HasActiveGrant runs on every capability-gated RPC
-- (gibson#1186 slice C: mission:delegate / mission:originate). It resolves
-- the caller by (tenant_id, principal_ref) — the CG-JWT's verified identity —
-- rather than by the capability_grant_agents primary key, which the caller's
-- per-RPC token does not carry. Without this index that lookup is a sequential
-- scan of every agent this tenant has ever enrolled.
CREATE INDEX IF NOT EXISTS idx_capability_grant_agents_tenant_principal
    ON capability_grant_agents (tenant_id, principal_ref);
