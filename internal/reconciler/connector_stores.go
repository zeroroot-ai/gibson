package reconciler

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/zeroroot-ai/sdk/auth"
)

// systemTenantID is the connector-manifest owner for shared (platform_enabled)
// connectors. A tenant enabling a shared connector has no manifest row of its
// own; ConnectorManifest falls back to this owner so the per-tenant sandbox
// launches from the one published definition (gibson#725 persists it here).
const systemTenantID = "_system"

// PostgresConnectorManifestStore persists raw connector manifest YAML keyed by
// (tenant, connector) in the connector_manifest table (migration 012). It is
// the source of truth the on-enable reconciler launches from; component_install
// keeps only a manifest_hash. It satisfies ManifestSource.
type PostgresConnectorManifestStore struct {
	db *sql.DB
}

// NewPostgresConnectorManifestStore constructs the store over an open DB.
func NewPostgresConnectorManifestStore(db *sql.DB) *PostgresConnectorManifestStore {
	return &PostgresConnectorManifestStore{db: db}
}

// Put upserts the manifest for (tenant, connector). Called at connector
// register time (BYO) and at shared publish (gibson#725, owner = _system).
func (s *PostgresConnectorManifestStore) Put(ctx context.Context, tenant auth.TenantID, connector string, manifestYAML []byte) error {
	if connector == "" {
		return fmt.Errorf("connector manifest store: connector name must not be empty")
	}
	if len(manifestYAML) == 0 {
		return fmt.Errorf("connector manifest store: manifest must not be empty")
	}
	const q = `
		INSERT INTO connector_manifest (tenant_id, connector_name, manifest_yaml, updated_at)
		VALUES ($1, $2, $3, now())
		ON CONFLICT (tenant_id, connector_name)
		DO UPDATE SET manifest_yaml = EXCLUDED.manifest_yaml, updated_at = now()`
	if _, err := s.db.ExecContext(ctx, q, tenant.String(), connector, manifestYAML); err != nil {
		return fmt.Errorf("connector manifest store: upsert (%s, %s): %w", tenant.String(), connector, err)
	}
	return nil
}

// ConnectorManifest returns the manifest for (tenant, connector), falling back
// to the _system owner so a tenant that enabled a shared connector launches
// from the published definition. found is false when no manifest is on record
// under either owner. Satisfies ManifestSource.
func (s *PostgresConnectorManifestStore) ConnectorManifest(ctx context.Context, tenant auth.TenantID, connector string) ([]byte, bool, error) {
	// Tenant's own manifest first (BYO), then the shared definition (_system).
	for _, owner := range []string{tenant.String(), systemTenantID} {
		const q = `SELECT manifest_yaml FROM connector_manifest WHERE tenant_id = $1 AND connector_name = $2`
		var yaml []byte
		err := s.db.QueryRowContext(ctx, q, owner, connector).Scan(&yaml)
		if err == nil {
			return yaml, true, nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, false, fmt.Errorf("connector manifest store: get (%s, %s): %w", owner, connector, err)
		}
	}
	return nil, false, nil
}

// PostgresConnectorSandboxInventory is the durable record of which
// (tenant, connector) currently has which running setec sandbox
// (connector_sandbox table, migration 013). List drives reconciler
// idempotency; Put records a launch. It satisfies Inventory.
type PostgresConnectorSandboxInventory struct {
	db *sql.DB
}

// NewPostgresConnectorSandboxInventory constructs the inventory over an open DB.
func NewPostgresConnectorSandboxInventory(db *sql.DB) *PostgresConnectorSandboxInventory {
	return &PostgresConnectorSandboxInventory{db: db}
}

// List returns every recorded (tenant, connector) -> sandbox mapping.
func (s *PostgresConnectorSandboxInventory) List(ctx context.Context) ([]InventoryEntry, error) {
	const q = `SELECT tenant_id, connector_name, sandbox_id FROM connector_sandbox`
	rows, err := s.db.QueryContext(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("connector sandbox inventory: list: %w", err)
	}
	defer rows.Close()

	var out []InventoryEntry
	for rows.Next() {
		var tenantID, connector, sandboxID string
		if err := rows.Scan(&tenantID, &connector, &sandboxID); err != nil {
			return nil, fmt.Errorf("connector sandbox inventory: scan: %w", err)
		}
		tid, err := auth.NewTenantID(tenantID)
		if err != nil {
			// A malformed tenant id in the table is corruption, not a reason to
			// drop the whole inventory and re-launch everything — skip the row.
			continue
		}
		out = append(out, InventoryEntry{Tenant: tid, Connector: connector, SandboxID: sandboxID})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("connector sandbox inventory: rows: %w", err)
	}
	return out, nil
}

// Put records (upserts) the sandbox for a (tenant, connector). One row per
// pair keeps the reconciler idempotent.
func (s *PostgresConnectorSandboxInventory) Put(ctx context.Context, e InventoryEntry) error {
	if e.Connector == "" || e.SandboxID == "" {
		return fmt.Errorf("connector sandbox inventory: connector and sandbox_id must not be empty")
	}
	const q = `
		INSERT INTO connector_sandbox (tenant_id, connector_name, sandbox_id, launched_at)
		VALUES ($1, $2, $3, now())
		ON CONFLICT (tenant_id, connector_name)
		DO UPDATE SET sandbox_id = EXCLUDED.sandbox_id, launched_at = now()`
	if _, err := s.db.ExecContext(ctx, q, e.Tenant.String(), e.Connector, e.SandboxID); err != nil {
		return fmt.Errorf("connector sandbox inventory: upsert (%s, %s): %w", e.Tenant.String(), e.Connector, err)
	}
	return nil
}
