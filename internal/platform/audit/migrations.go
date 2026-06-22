// Package audit — migrations.go
//
// RunAuditMigrations creates the audit_log table and its indexes if they do
// not already exist. The DDL is idempotent — safe to run on every daemon
// startup regardless of whether the schema was previously applied.
//
// This file does NOT use any migration framework or ORM. It executes raw SQL
// via ExecContext and uses IF NOT EXISTS guards throughout.
package audit

import (
	"context"
	"database/sql"
	"fmt"
)

// auditLogDDL is the idempotent DDL for the audit_log table.
//
// Every authorization decision, grant change, and agent lifecycle event is
// written here. The table is append-only by convention — no UPDATE or DELETE
// paths exist in the Writer.
//
// actor_type values:
//
//	user   — a human user authenticated via OIDC or API key
//	agent  — an LLM-driven Gibson agent
//	system — the daemon itself (background processes, provisioning)
//
// decision values (nullable):
//
//	allow  — FGA check returned allowed
//	deny   — FGA check returned denied
//	""     — not an authorization event (lifecycle, grant changes, etc.)
const auditLogDDL = `
CREATE TABLE IF NOT EXISTS audit_log (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       TEXT NOT NULL,
    actor_id        TEXT NOT NULL,
    actor_type      TEXT NOT NULL DEFAULT 'user'
                    CHECK (actor_type IN ('user', 'agent', 'system')),
    action          TEXT NOT NULL,
    target_type     TEXT NOT NULL DEFAULT '',
    target_id       TEXT NOT NULL DEFAULT '',
    decision        TEXT,
    metadata        JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_audit_log_tenant ON audit_log(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_actor  ON audit_log(actor_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_target ON audit_log(target_type, target_id, created_at DESC);
`

// RunAuditMigrations executes the audit_log DDL against the given database.
//
// It is safe to call on every daemon startup — all statements use IF NOT
// EXISTS guards so they are no-ops when the schema is already in place.
//
// Returns an error only when the DDL execution itself fails (e.g. permission
// denied, syntax error). The caller (provisioner.RunMigrations) decides
// whether to propagate or degrade gracefully.
func RunAuditMigrations(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx, auditLogDDL); err != nil {
		return fmt.Errorf("audit: RunAuditMigrations: audit_log: %w", err)
	}
	return nil
}
