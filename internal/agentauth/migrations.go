// Package agentauth — migrations.go
//
// RunAgentAuthMigrations creates all Agent Auth Protocol tables and their
// indexes if they do not already exist. The DDL is idempotent — safe to run
// on every daemon startup regardless of whether the tables were previously
// created.
//
// This function does NOT use any migration framework or ORM. It executes raw
// SQL using ExecContext and uses IF NOT EXISTS guards throughout.
package agentauth

import (
	"context"
	"database/sql"
	"fmt"
)

// agentAuthHostsDDL is the idempotent DDL for the agent_auth_hosts table.
//
// Hosts represent end-user machines or CI runners that register with the
// Gibson platform. Each host holds a public JWK used to verify challenge
// responses and to sign agent registration requests.
//
// Status values:
//
//	active  — host is registered and its key is trusted
//	pending — registration received but not yet approved
//	revoked — explicitly revoked; retained for audit purposes
const agentAuthHostsDDL = `
CREATE TABLE IF NOT EXISTS agent_auth_hosts (
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
`

// agentAuthAgentsDDL is the idempotent DDL for the agent_auth_agents table.
//
// Agents are LLM-driven workers that register under a host. The public JWK
// is used to verify capability grant assertions. Session and lifetime TTLs
// control when the agent's credentials expire.
//
// Status values:
//
//	active   — agent is operational
//	pending  — registration received, awaiting host / user approval
//	expired  — session TTL elapsed; re-registration required
//	revoked  — explicitly revoked; retained for audit
//	rejected — registration was denied
//
// Mode values:
//
//	delegated  — acts on behalf of a user; scoped to their permissions
//	autonomous — acts with its own granted capability set
const agentAuthAgentsDDL = `
CREATE TABLE IF NOT EXISTS agent_auth_agents (
    id              TEXT PRIMARY KEY,
    host_id         TEXT NOT NULL REFERENCES agent_auth_hosts(id),
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

CREATE INDEX IF NOT EXISTS idx_agent_auth_agents_host   ON agent_auth_agents(host_id);
CREATE INDEX IF NOT EXISTS idx_agent_auth_agents_tenant ON agent_auth_agents(tenant_id);
`

// agentAuthGrantsDDL is the idempotent DDL for the agent_auth_grants table.
//
// Grants record which capabilities (tool/plugin/agent invocations) an agent
// is permitted to exercise, along with optional JSON constraints (e.g. scope
// restrictions or parameter guards). A composite UNIQUE constraint prevents
// duplicate grants for the same capability on the same agent.
//
// Status values:
//
//	active  — grant is in force
//	pending — awaiting approval (used when manual review is required)
//	revoked — grant was rescinded; retained for audit
const agentAuthGrantsDDL = `
CREATE TABLE IF NOT EXISTS agent_auth_grants (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id        TEXT NOT NULL REFERENCES agent_auth_agents(id) ON DELETE CASCADE,
    capability_name TEXT NOT NULL,
    component_ref   TEXT NOT NULL,
    constraints     JSONB NOT NULL DEFAULT '{}',
    status          TEXT NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'pending', 'revoked')),
    granted_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(agent_id, capability_name)
);

CREATE INDEX IF NOT EXISTS idx_agent_auth_grants_agent ON agent_auth_grants(agent_id);
`

// RunAgentAuthMigrations executes all Agent Auth Protocol DDL against the
// given database.
//
// It is safe to call on every daemon startup — all statements use IF NOT
// EXISTS guards so they are no-ops when the schema is already in place.
//
// Returns an error only when the DDL execution itself fails (e.g. permission
// denied, syntax error). The caller (provisioner.RunMigrations) decides
// whether to propagate or degrade gracefully.
func RunAgentAuthMigrations(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx, agentAuthHostsDDL); err != nil {
		return fmt.Errorf("agentauth: RunAgentAuthMigrations: agent_auth_hosts: %w", err)
	}
	if _, err := db.ExecContext(ctx, agentAuthAgentsDDL); err != nil {
		return fmt.Errorf("agentauth: RunAgentAuthMigrations: agent_auth_agents: %w", err)
	}
	if _, err := db.ExecContext(ctx, agentAuthGrantsDDL); err != nil {
		return fmt.Errorf("agentauth: RunAgentAuthMigrations: agent_auth_grants: %w", err)
	}
	return nil
}
