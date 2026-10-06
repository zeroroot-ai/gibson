// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

// plugin_admin_adapters.go wires the concrete daemon dependencies into the
// narrow interfaces declared by internal/admin.PluginsAdminConfig so that
// NewPluginsAdminServer can be called from buildGRPCServer.
//
// One thin adapter lives here: componentInstallRegistryReaderAdapter wraps
// the component_install table and the transient install status in Redis to
// satisfy the admin.PluginRegistryReader interface (ListAll, Get).
//
// No new external dependencies are introduced — every adapter is backed by
// an already-constructed daemon field wired in buildGRPCServer.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/zeroroot-ai/gibson/internal/platform/component"
	"github.com/zeroroot-ai/gibson/internal/server/admin"
	"github.com/zeroroot-ai/sdk/auth"
)

// ---------------------------------------------------------------------------
// 1. componentInstallRegistryReaderAdapter
// ---------------------------------------------------------------------------

// componentInstallRegistryReaderAdapter adapts the daemon's platformDB (same Postgres
// instance the ComponentInstallRegistry uses) to admin.PluginRegistryReader. We query
// the plugin_install table directly so we can implement the ListAll and Get
// operations needed by the admin surface without extending the
// component.ComponentInstallRegistry interface.
//
// The adapter is read-only. Metadata comes from Postgres; the status comes
// from the Redis key the ComponentInstallRegistry refreshes on every
// heartbeat, so the admin surface and dispatch agree on it.
type componentInstallRegistryReaderAdapter struct {
	db *sql.DB
	// redis holds the transient status the install registry writes on
	// every heartbeat (component.InstallStatus). The admin surface reads it
	// so ListPluginInstalls shows the status the plugin last reported:
	// serving, degraded after a secret revocation, or unreachable once the
	// TTL lapsed (gibson#154).
	redis redis.UniversalClient
}

var _ admin.PluginRegistryReader = (*componentInstallRegistryReaderAdapter)(nil)

// ListAll returns all plugin_install rows for the given tenant. It does not
// check Redis transient state — the admin surface needs the full list including
// installs whose hosts are currently offline.
func (a *componentInstallRegistryReaderAdapter) ListAll(ctx context.Context, tenant auth.TenantID) ([]admin.ComponentInstallInfo, error) {
	const q = `
SELECT id, tenant_id, component_name, version, declared_methods,
       principal_ref, created_at
FROM   component_install
WHERE  tenant_id = $1
ORDER BY created_at`

	rows, err := a.db.QueryContext(ctx, q, tenant.String())
	if err != nil {
		return nil, fmt.Errorf("plugin registry reader: list all for tenant %s: %w", tenant, err)
	}
	defer rows.Close() //nolint:errcheck

	var out []admin.ComponentInstallInfo
	for rows.Next() {
		var (
			info        admin.ComponentInstallInfo
			tenantIDStr string
			methodsJSON []byte
			createdAt   time.Time
		)
		if err := rows.Scan(
			&info.InstallID, &tenantIDStr, &info.Name, &info.Version,
			&methodsJSON, &info.PrincipalRef, &createdAt,
		); err != nil {
			return nil, fmt.Errorf("plugin registry reader: scan row: %w", err)
		}
		info.TenantID = tenantIDStr
		info.CreatedAt = createdAt
		a.fillStatus(ctx, &info)
		if len(methodsJSON) > 0 {
			if jsonErr := json.Unmarshal(methodsJSON, &info.DeclaredMethods); jsonErr != nil {
				// Non-fatal: log by returning an empty methods slice.
				info.DeclaredMethods = nil
			}
		}
		out = append(out, info)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("plugin registry reader: iterate rows: %w", err)
	}
	return out, nil
}

// Get returns a single plugin_install row by install ID and tenant.
func (a *componentInstallRegistryReaderAdapter) Get(ctx context.Context, tenant auth.TenantID, installID string) (*admin.ComponentInstallInfo, error) {
	const q = `
SELECT id, tenant_id, component_name, version, declared_methods,
       principal_ref, created_at
FROM   component_install
WHERE  tenant_id  = $1
AND    id         = $2
LIMIT 1`

	var (
		info        admin.ComponentInstallInfo
		tenantIDStr string
		methodsJSON []byte
		createdAt   time.Time
	)
	err := a.db.QueryRowContext(ctx, q, tenant.String(), installID).Scan(
		&info.InstallID, &tenantIDStr, &info.Name, &info.Version,
		&methodsJSON, &info.PrincipalRef, &createdAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, admin.ErrInstallNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("plugin registry reader: get install %s: %w", installID, err)
	}
	info.TenantID = tenantIDStr
	info.CreatedAt = createdAt
	a.fillStatus(ctx, &info)
	if len(methodsJSON) > 0 {
		_ = json.Unmarshal(methodsJSON, &info.DeclaredMethods)
	}
	return &info, nil
}

// fillStatus copies the install's transient status out of Redis. An absent
// key is an install no heartbeat refreshed within the TTL: unreachable.
func (a *componentInstallRegistryReaderAdapter) fillStatus(ctx context.Context, info *admin.ComponentInstallInfo) {
	st, addr, hb, _ := component.InstallStatus(ctx, a.redis, info.InstallID)
	info.Status = string(st)
	info.Address = addr
	info.LastHeartbeatAt = hb
}
