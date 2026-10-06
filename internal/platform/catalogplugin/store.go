// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package catalogplugin keeps the catalog plugins each tenant enabled
// (gibson#815). A row is what a tenant wants: one instance of the plugin for
// that tenant. The tenant operator runs the instance and reports its state.
package catalogplugin

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// PhasePending is the phase of an enabled plugin before the tenant operator
// reported on its instance.
const PhasePending = "Pending"

// ErrAlreadyEnabled is returned by Enable when the tenant already enabled the
// plugin.
var ErrAlreadyEnabled = errors.New("catalogplugin: the tenant already enabled this plugin")

// ErrNotEnabled is returned by Disable when the tenant did not enable the
// plugin.
var ErrNotEnabled = errors.New("catalogplugin: the tenant did not enable this plugin")

// Plugin is one catalog plugin a tenant enabled.
type Plugin struct {
	TenantID  string
	PluginID  string
	Phase     string
	LastError string
}

// Store reads and writes tenant_catalog_plugins.
type Store struct {
	db *sql.DB
}

// NewStore returns a Store over the platform database.
func NewStore(db *sql.DB) *Store {
	return &Store{db: db}
}

// Enable records that tenantID wants one instance of pluginID. It returns
// ErrAlreadyEnabled when the row exists.
func (s *Store) Enable(ctx context.Context, tenantID, pluginID string) (Plugin, error) {
	if tenantID == "" || pluginID == "" {
		return Plugin{}, errors.New("catalogplugin: Enable: tenant and plugin are required")
	}
	const query = `
INSERT INTO tenant_catalog_plugins (tenant_id, plugin_id)
VALUES ($1, $2)
ON CONFLICT (tenant_id, plugin_id) DO NOTHING`
	res, err := s.db.ExecContext(ctx, query, tenantID, pluginID)
	if err != nil {
		return Plugin{}, fmt.Errorf("catalogplugin: Enable %s/%s: %w", tenantID, pluginID, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return Plugin{}, fmt.Errorf("catalogplugin: Enable %s/%s: rows affected: %w", tenantID, pluginID, err)
	}
	if n == 0 {
		return Plugin{}, ErrAlreadyEnabled
	}
	return Plugin{TenantID: tenantID, PluginID: pluginID, Phase: PhasePending}, nil
}

// Disable removes pluginID from what tenantID wants. It returns ErrNotEnabled
// when no row exists.
func (s *Store) Disable(ctx context.Context, tenantID, pluginID string) error {
	if tenantID == "" || pluginID == "" {
		return errors.New("catalogplugin: Disable: tenant and plugin are required")
	}
	const query = `DELETE FROM tenant_catalog_plugins WHERE tenant_id = $1 AND plugin_id = $2`
	res, err := s.db.ExecContext(ctx, query, tenantID, pluginID)
	if err != nil {
		return fmt.Errorf("catalogplugin: Disable %s/%s: %w", tenantID, pluginID, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("catalogplugin: Disable %s/%s: rows affected: %w", tenantID, pluginID, err)
	}
	if n == 0 {
		return ErrNotEnabled
	}
	return nil
}

// List returns the plugins tenantID enabled, in plugin id order. The tenant
// predicate is the isolation boundary of this read.
func (s *Store) List(ctx context.Context, tenantID string) ([]Plugin, error) {
	if tenantID == "" {
		return nil, errors.New("catalogplugin: List: tenant is required")
	}
	const query = `
SELECT tenant_id, plugin_id, phase, last_error
FROM   tenant_catalog_plugins
WHERE  tenant_id = $1
ORDER BY plugin_id`
	rows, err := s.db.QueryContext(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("catalogplugin: List %s: %w", tenantID, err)
	}
	defer func() { _ = rows.Close() }()

	var out []Plugin
	for rows.Next() {
		var p Plugin
		if err := rows.Scan(&p.TenantID, &p.PluginID, &p.Phase, &p.LastError); err != nil {
			return nil, fmt.Errorf("catalogplugin: List %s: scan: %w", tenantID, err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("catalogplugin: List %s: %w", tenantID, err)
	}
	return out, nil
}

// ListAll returns every enabled plugin of every tenant, in (tenant, plugin)
// order. It has no tenant predicate on purpose: only the tenant operator
// reads it, through an RPC that every other caller is refused.
func (s *Store) ListAll(ctx context.Context) ([]Plugin, error) {
	const query = `
SELECT tenant_id, plugin_id, phase, last_error
FROM   tenant_catalog_plugins
ORDER BY tenant_id, plugin_id`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("catalogplugin: ListAll: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []Plugin
	for rows.Next() {
		var p Plugin
		if err := rows.Scan(&p.TenantID, &p.PluginID, &p.Phase, &p.LastError); err != nil {
			return nil, fmt.Errorf("catalogplugin: ListAll: scan: %w", err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("catalogplugin: ListAll: %w", err)
	}
	return out, nil
}

// IsEnabled reports whether tenantID enabled pluginID. The daemon asks it
// before it accepts the identity of a plugin instance, so an instance of a
// plugin that the tenant did not enable, or disabled, gets no credential.
func (s *Store) IsEnabled(ctx context.Context, tenantID, pluginID string) (bool, error) {
	if tenantID == "" || pluginID == "" {
		return false, errors.New("catalogplugin: IsEnabled: tenant and plugin are required")
	}
	const query = `
SELECT EXISTS (
  SELECT 1 FROM tenant_catalog_plugins WHERE tenant_id = $1 AND plugin_id = $2
)`
	var enabled bool
	if err := s.db.QueryRowContext(ctx, query, tenantID, pluginID).Scan(&enabled); err != nil {
		return false, fmt.Errorf("catalogplugin: IsEnabled %s/%s: %w", tenantID, pluginID, err)
	}
	return enabled, nil
}

// ReportStatus records the state the tenant operator reports for one tenant's
// instance. It returns false when the tenant did not enable the plugin: a
// report never creates a row, because a row is what a tenant wants.
func (s *Store) ReportStatus(ctx context.Context, tenantID, pluginID, phase, lastError string) (bool, error) {
	if tenantID == "" || pluginID == "" || phase == "" {
		return false, errors.New("catalogplugin: ReportStatus: tenant, plugin and phase are required")
	}
	const query = `
UPDATE tenant_catalog_plugins
SET    phase = $3, last_error = $4, reported_at = NOW()
WHERE  tenant_id = $1 AND plugin_id = $2`
	res, err := s.db.ExecContext(ctx, query, tenantID, pluginID, phase, lastError)
	if err != nil {
		return false, fmt.Errorf("catalogplugin: ReportStatus %s/%s: %w", tenantID, pluginID, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("catalogplugin: ReportStatus %s/%s: rows affected: %w", tenantID, pluginID, err)
	}
	return n > 0, nil
}
