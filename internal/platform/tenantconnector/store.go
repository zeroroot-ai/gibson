// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package tenantconnector keeps the connectors each tenant enabled
// (gibson#662). A row is what a tenant wants: one connector of the catalog for
// that tenant. The connector operator makes the ConnectorInstance and reports
// its state. The daemon makes no Kubernetes call (ADR-0023).
package tenantconnector

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// PhasePending is the phase of an enabled connector before the connector
// operator reported on it.
const PhasePending = "Pending"

// ErrAlreadyEnabled is returned by Enable when the tenant already enabled the
// connector.
var ErrAlreadyEnabled = errors.New("tenantconnector: the tenant already enabled this connector")

// ErrNotEnabled is returned by Disable when the tenant did not enable the
// connector.
var ErrNotEnabled = errors.New("tenantconnector: the tenant did not enable this connector")

// Connector is one connector a tenant enabled, with the state that the
// connector operator reported last.
type Connector struct {
	TenantID        string
	ConnectorID     string
	Phase           string
	DiscoveredTools int32
	LastError       string
}

// Status is a report of the connector operator about one connector.
type Status struct {
	Phase           string
	DiscoveredTools int32
	LastError       string
}

// Store reads and writes tenant_connectors.
type Store struct {
	db *sql.DB
}

// NewStore returns a Store over the platform database.
func NewStore(db *sql.DB) *Store {
	return &Store{db: db}
}

func required(op, tenantID, connectorID string) error {
	if tenantID == "" || connectorID == "" {
		return fmt.Errorf("tenantconnector: %s: tenant and connector are required", op)
	}
	return nil
}

// Enable records that tenantID wants connectorID. It returns
// ErrAlreadyEnabled when the row exists.
func (s *Store) Enable(ctx context.Context, tenantID, connectorID string) (Connector, error) {
	if err := required("Enable", tenantID, connectorID); err != nil {
		return Connector{}, err
	}
	n, err := s.insert(ctx, tenantID, connectorID)
	if err != nil {
		return Connector{}, err
	}
	if n == 0 {
		return Connector{}, ErrAlreadyEnabled
	}
	return Connector{TenantID: tenantID, ConnectorID: connectorID, Phase: PhasePending}, nil
}

// Adopt records a connector that exists in the cluster from the time when the
// daemon wrote ConnectorInstances itself. The connector operator calls it once
// for each such instance, so the table holds the connectors that tenants
// enabled before it existed. A row that exists stays as it is.
func (s *Store) Adopt(ctx context.Context, tenantID, connectorID string) error {
	if err := required("Adopt", tenantID, connectorID); err != nil {
		return err
	}
	_, err := s.insert(ctx, tenantID, connectorID)
	return err
}

func (s *Store) insert(ctx context.Context, tenantID, connectorID string) (int64, error) {
	const query = `
INSERT INTO tenant_connectors (tenant_id, connector_id)
VALUES ($1, $2)
ON CONFLICT (tenant_id, connector_id) DO NOTHING`
	res, err := s.db.ExecContext(ctx, query, tenantID, connectorID)
	if err != nil {
		return 0, fmt.Errorf("tenantconnector: insert %s/%s: %w", tenantID, connectorID, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("tenantconnector: insert %s/%s: rows affected: %w", tenantID, connectorID, err)
	}
	return n, nil
}

// Disable removes the wish. It returns ErrNotEnabled when no row exists.
func (s *Store) Disable(ctx context.Context, tenantID, connectorID string) error {
	if err := required("Disable", tenantID, connectorID); err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM tenant_connectors WHERE tenant_id = $1 AND connector_id = $2`, tenantID, connectorID)
	if err != nil {
		return fmt.Errorf("tenantconnector: Disable %s/%s: %w", tenantID, connectorID, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("tenantconnector: Disable %s/%s: rows affected: %w", tenantID, connectorID, err)
	}
	if n == 0 {
		return ErrNotEnabled
	}
	return nil
}

const selectColumns = `tenant_id, connector_id, phase, discovered_tools, last_error`

// List returns the connectors of one tenant, in connector order.
func (s *Store) List(ctx context.Context, tenantID string) ([]Connector, error) {
	if tenantID == "" {
		return nil, errors.New("tenantconnector: List: tenant is required")
	}
	return s.query(ctx, "List",
		`SELECT `+selectColumns+` FROM tenant_connectors WHERE tenant_id = $1 ORDER BY connector_id`, tenantID)
}

// ListAll returns every enabled connector of every tenant, in (tenant,
// connector) order. It has no tenant predicate on purpose: only the connector
// operator reads it, through an RPC that every other caller is refused.
func (s *Store) ListAll(ctx context.Context) ([]Connector, error) {
	return s.query(ctx, "ListAll",
		`SELECT `+selectColumns+` FROM tenant_connectors ORDER BY tenant_id, connector_id`)
}

func (s *Store) query(ctx context.Context, op, query string, args ...any) ([]Connector, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("tenantconnector: %s: %w", op, err)
	}
	defer func() { _ = rows.Close() }()

	var out []Connector
	for rows.Next() {
		var c Connector
		if err := rows.Scan(&c.TenantID, &c.ConnectorID, &c.Phase, &c.DiscoveredTools, &c.LastError); err != nil {
			return nil, fmt.Errorf("tenantconnector: %s: scan: %w", op, err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("tenantconnector: %s: %w", op, err)
	}
	return out, nil
}

// ReportStatus records the state that the connector operator reports for one
// connector. It returns false when the tenant did not enable the connector: a
// report never creates a row, because a row is what a tenant wants.
func (s *Store) ReportStatus(ctx context.Context, tenantID, connectorID string, st Status) (bool, error) {
	if err := required("ReportStatus", tenantID, connectorID); err != nil {
		return false, err
	}
	if st.Phase == "" {
		return false, errors.New("tenantconnector: ReportStatus: phase is required")
	}
	res, err := s.db.ExecContext(ctx, `
UPDATE tenant_connectors
SET    phase = $3, discovered_tools = $4, last_error = $5, reported_at = NOW()
WHERE  tenant_id = $1 AND connector_id = $2`,
		tenantID, connectorID, st.Phase, st.DiscoveredTools, st.LastError)
	if err != nil {
		return false, fmt.Errorf("tenantconnector: ReportStatus %s/%s: %w", tenantID, connectorID, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("tenantconnector: ReportStatus %s/%s: rows affected: %w", tenantID, connectorID, err)
	}
	return n > 0, nil
}
