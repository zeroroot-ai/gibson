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
