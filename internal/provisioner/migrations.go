// Package provisioner — migrations.go
//
// RunMigrations creates all Gibson dashboard tables and their indexes if they
// do not already exist. The DDL is idempotent — safe to run on every daemon
// startup regardless of whether the tables were previously created.
//
// This function does NOT use any migration framework or ORM. It executes raw
// SQL using a single ExecContext call and uses IF NOT EXISTS guards throughout.
package provisioner

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/zero-day-ai/gibson/internal/agentauth"
	"github.com/zero-day-ai/gibson/internal/audit"
)

// tenantProvisioningDDL is the idempotent DDL for the tenant_provisioning table
// and its indexes. Running this multiple times is safe.
const tenantProvisioningDDL = `
CREATE TABLE IF NOT EXISTS tenant_provisioning (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id                 TEXT NOT NULL,
    tenant_slug             TEXT NOT NULL UNIQUE,
    org_name                TEXT NOT NULL DEFAULT '',
    email                   TEXT NOT NULL DEFAULT '',
    plan                    TEXT NOT NULL DEFAULT 'free',
    status                  TEXT NOT NULL DEFAULT 'requested'
                            CHECK (status IN ('requested','provisioning','active','suspended','deprovisioned','failed')),
    stripe_customer_id      TEXT,
    stripe_subscription_id  TEXT,
    trial_ends_at           TIMESTAMPTZ,
    current_step            TEXT NOT NULL DEFAULT '',
    step_statuses           JSONB NOT NULL DEFAULT '{}',
    error                   TEXT NOT NULL DEFAULT '',
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at            TIMESTAMPTZ,
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_tenant_provisioning_user_id
    ON tenant_provisioning(user_id);

CREATE INDEX IF NOT EXISTS idx_tenant_provisioning_status
    ON tenant_provisioning(status);
`

// apiKeysDDL is the idempotent DDL for the api_keys table and its indexes.
//
// Key material is never stored in plaintext — only the SHA-256 hash of the
// raw token is persisted. The key_hash index enables O(1) authentication
// lookups. The tenant index supports ListKeys queries.
//
// Status values:
//   - active   — key is usable
//   - revoked  — explicitly revoked; retained for audit
//   - consumed — single-use key that has been used (max_uses reached)
//   - expired  — key that has passed its expires_at timestamp
const apiKeysDDL = `
CREATE TABLE IF NOT EXISTS api_keys (
    key_id          TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    key_hash        TEXT NOT NULL,
    name            TEXT NOT NULL DEFAULT '',
    created_by      TEXT NOT NULL DEFAULT '',
    allowed_kinds   TEXT[] NOT NULL DEFAULT '{}',
    allowed_names   TEXT[] NOT NULL DEFAULT '{}',
    capabilities    TEXT[] NOT NULL DEFAULT '{}',
    status          TEXT NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'revoked', 'consumed', 'expired')),
    max_uses        INT,
    use_count       INT NOT NULL DEFAULT 0,
    expires_at      TIMESTAMPTZ,
    last_used_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_api_keys_tenant ON api_keys(tenant_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
`

// RunMigrations executes all Gibson dashboard DDL against the given database.
//
// It is safe to call on every daemon startup — all statements use IF NOT EXISTS
// guards so no-op when the schema is already in place.
//
// Returns an error only when the DDL execution itself fails (e.g. permission
// denied, syntax error). Transient connectivity errors are returned to the
// caller so they can decide whether to retry or degrade gracefully.
func RunMigrations(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx, tenantProvisioningDDL); err != nil {
		return fmt.Errorf("provisioner: RunMigrations: tenant_provisioning: %w", err)
	}
	if _, err := db.ExecContext(ctx, apiKeysDDL); err != nil {
		return fmt.Errorf("provisioner: RunMigrations: api_keys: %w", err)
	}
	if err := agentauth.RunAgentAuthMigrations(ctx, db); err != nil {
		return fmt.Errorf("provisioner: RunMigrations: agent_auth: %w", err)
	}
	if err := audit.RunAuditMigrations(ctx, db); err != nil {
		return fmt.Errorf("provisioner: RunMigrations: audit: %w", err)
	}
	return nil
}
