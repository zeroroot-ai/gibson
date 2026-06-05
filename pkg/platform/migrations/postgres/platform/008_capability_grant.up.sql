-- Capability Grant Protocol store (gibson#648, ADR-0045).
--
-- These tables back internal/capabilitygrant.CapabilityGrantStore — host /
-- agent registration and resolved per-agent capability grants. The DDL was
-- previously only in internal/capabilitygrant/migrations.go
-- (RunCapabilityGrantMigrations), which has no caller, so the tables were never
-- created and RegisterCapabilityGrant failed at runtime. Move it into the
-- standard golang-migrate platform migration set so it is applied at daemon
-- startup like every other platform table.

CREATE TABLE IF NOT EXISTS capability_grant_hosts (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    user_id         TEXT,
    display_name    TEXT NOT NULL DEFAULT '',
    public_key_jwk  JSONB NOT NULL,
    status          TEXT NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'pending', 'revoked')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS capability_grant_agents (
    id              TEXT PRIMARY KEY,
    host_id         TEXT NOT NULL REFERENCES capability_grant_hosts(id),
    tenant_id       TEXT NOT NULL,
    user_id         TEXT,
    name            TEXT NOT NULL DEFAULT '',
    mode            TEXT NOT NULL CHECK (mode IN ('delegated', 'autonomous')),
    public_key_jwk  JSONB NOT NULL,
    status          TEXT NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'pending', 'expired', 'revoked', 'rejected')),
    session_ttl_s   INT NOT NULL DEFAULT 3600,
    max_lifetime_s  INT NOT NULL DEFAULT 86400,
    last_active_at  TIMESTAMPTZ,
    expires_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_capability_grant_agents_host   ON capability_grant_agents(host_id);
CREATE INDEX IF NOT EXISTS idx_capability_grant_agents_tenant ON capability_grant_agents(tenant_id);

CREATE TABLE IF NOT EXISTS capability_grant_grants (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id        TEXT NOT NULL REFERENCES capability_grant_agents(id) ON DELETE CASCADE,
    capability_name TEXT NOT NULL,
    component_ref   TEXT NOT NULL,
    constraints     JSONB NOT NULL DEFAULT '{}',
    status          TEXT NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'pending', 'revoked')),
    granted_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(agent_id, capability_name)
);

CREATE INDEX IF NOT EXISTS idx_capability_grant_grants_agent ON capability_grant_grants(agent_id);
