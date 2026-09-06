-- Capability Grant agent principal reference (epic unified-cg-identity, ADR-0045).
--
-- ext-authz verifies a component's self-signed per-RPC agent+jwt by kid (=the
-- agent row id) and then runs its NORMAL per-method FGA check on the principal.
-- The FGA principal is the typed `<kind>_principal:<zitadel-sa-account-id>` ref
-- minted at enrollment — NOT the capability_grant_agents row id (which is the
-- agent+jwt `sub`). The daemon's per-kid key endpoint returns this principal_ref
-- + tenant as the authoritative descriptor (option A); ext-authz trusts no
-- caller-asserted principal/tenant. Persist the ref so the descriptor can serve
-- it. Populated by RegisterCapabilityGrant from the verified bootstrap claims.
ALTER TABLE capability_grant_agents
    ADD COLUMN IF NOT EXISTS principal_ref TEXT NOT NULL DEFAULT '';
