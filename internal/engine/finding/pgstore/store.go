// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package pgstore keeps the full finding in the findings table of the database
// of the tenant (migration 004). The tenant is the database that the pool
// selects, so the table has no tenant column and a read cannot reach the
// finding of another tenant.
//
// This package is separate from package finding because the data pool imports
// the brain, and the brain imports package finding.
package pgstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/finding"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/sdk/auth"
)

// conn is the handle of one tenant database for the life of one call.
// It is an interface so that the logic of the store runs in a test without a
// container.
type conn interface {
	SQL() datapool.SQL
	InTx(ctx context.Context, fn func(datapool.SQL) error) error
	Release()
}

// conns hands out one conn for a tenant.
type conns interface {
	For(ctx context.Context, tenantID string) (conn, error)
}

// PoolFunc returns the data pool of the daemon. The pool starts after some
// callers of the store exist, so a caller passes a function and the store
// calls it on first use.
type PoolFunc func() datapool.Pool

// Store implements finding.FindingStore on the database of the tenant.
type Store struct {
	conns conns
}

// New builds the store over the per-tenant data pool.
func New(pool PoolFunc) *Store {
	return &Store{conns: poolConns{pool: pool}}
}

var _ finding.FindingStore = (*Store)(nil)

// poolConns adapts the data pool to conns.
type poolConns struct{ pool PoolFunc }

func (p poolConns) For(ctx context.Context, tenantID string) (conn, error) {
	var pool datapool.Pool
	if p.pool != nil {
		pool = p.pool()
	}
	if pool == nil {
		return nil, errors.New("finding store: the data pool is not ready")
	}
	tid, err := auth.NewTenantID(tenantID)
	if err != nil {
		return nil, fmt.Errorf("finding store: invalid tenant %q: %w", tenantID, err)
	}
	c, err := pool.For(ctx, tid)
	if err != nil {
		return nil, fmt.Errorf("finding store: acquire conn for %s: %w", tenantID, err)
	}
	return c, nil
}

// findingRow holds the values that the store writes to the columns of the
// findings table.
type findingRow struct {
	id        string
	missionID *string
	severity  string
	title     string
	document  []byte
	createdAt time.Time
	updatedAt time.Time
}

func newFindingRow(f finding.EnhancedFinding) (findingRow, error) {
	if err := f.ID.Validate(); err != nil {
		return findingRow{}, fmt.Errorf("finding store: finding ID: %w", err)
	}
	var missionID *string
	if f.MissionID != "" {
		if err := f.MissionID.Validate(); err != nil {
			return findingRow{}, fmt.Errorf("finding store: mission ID: %w", err)
		}
		m := f.MissionID.String()
		missionID = &m
	}
	doc, err := json.Marshal(f)
	if err != nil {
		return findingRow{}, fmt.Errorf("finding store: marshal finding: %w", err)
	}
	created := f.CreatedAt
	if created.IsZero() {
		created = time.Now().UTC()
	}
	updated := f.UpdatedAt
	if updated.IsZero() {
		updated = created
	}
	return findingRow{
		id:        f.ID.String(),
		missionID: missionID,
		severity:  string(f.Severity),
		title:     f.Title,
		document:  doc,
		createdAt: created,
		updatedAt: updated,
	}, nil
}

const upsertFindingSQL = `
INSERT INTO findings (id, mission_id, severity, title, document, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (id) DO UPDATE SET
	mission_id = EXCLUDED.mission_id,
	severity   = EXCLUDED.severity,
	title      = EXCLUDED.title,
	document   = EXCLUDED.document,
	updated_at = EXCLUDED.updated_at`

// Store writes the finding as one row. A second Store of the same ID replaces
// the row.
func (s *Store) Store(ctx context.Context, tenantID string, f finding.EnhancedFinding) error {
	row, err := newFindingRow(f)
	if err != nil {
		return err
	}
	c, err := s.conns.For(ctx, tenantID)
	if err != nil {
		return err
	}
	defer c.Release()
	if _, err := c.SQL().Exec(ctx, upsertFindingSQL,
		row.id, row.missionID, row.severity, row.title, row.document, row.createdAt, row.updatedAt); err != nil {
		return fmt.Errorf("finding store: write finding %s: %w", row.id, err)
	}
	return nil
}

// Get returns the finding with the ID, or finding.ErrNotFound.
func (s *Store) Get(ctx context.Context, tenantID string, id types.ID) (*finding.EnhancedFinding, error) {
	if err := id.Validate(); err != nil {
		return nil, fmt.Errorf("finding store: finding ID: %w", err)
	}
	c, err := s.conns.For(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	defer c.Release()
	var doc []byte
	if err := c.SQL().QueryRow(ctx, `SELECT document FROM findings WHERE id = $1`, id.String()).Scan(&doc); err != nil {
		if errors.Is(err, datapool.ErrNoRows) {
			return nil, fmt.Errorf("%w: %s", finding.ErrNotFound, id)
		}
		return nil, fmt.Errorf("finding store: read finding %s: %w", id, err)
	}
	return decodeFinding(doc)
}

// List returns the findings of a mission that match the filter. A nil filter
// matches each finding.
func (s *Store) List(
	ctx context.Context, tenantID string, missionID types.ID, filter *finding.FindingFilter,
) ([]finding.EnhancedFinding, error) {
	if err := missionID.Validate(); err != nil {
		return nil, fmt.Errorf("finding store: mission ID: %w", err)
	}
	all, err := s.query(ctx, tenantID,
		`SELECT document FROM findings WHERE mission_id = $1 ORDER BY created_at, id`, missionID.String())
	if err != nil {
		return nil, err
	}
	out := make([]finding.EnhancedFinding, 0, len(all))
	for _, f := range all {
		if filter.Matches(f) {
			out = append(out, f)
		}
	}
	return out, nil
}

// ListBySeverity returns each finding of the tenant with the severity.
func (s *Store) ListBySeverity(
	ctx context.Context, tenantID string, severity agent.FindingSeverity,
) ([]finding.EnhancedFinding, error) {
	return s.query(ctx, tenantID,
		`SELECT document FROM findings WHERE severity = $1 ORDER BY created_at, id`, string(severity))
}

func (s *Store) query(ctx context.Context, tenantID, sql string, args ...any) ([]finding.EnhancedFinding, error) {
	c, err := s.conns.For(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	defer c.Release()
	rows, err := c.SQL().Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("finding store: list findings: %w", err)
	}
	defer rows.Close()
	out := []finding.EnhancedFinding{}
	for rows.Next() {
		var doc []byte
		if err := rows.Scan(&doc); err != nil {
			return nil, fmt.Errorf("finding store: scan finding: %w", err)
		}
		f, err := decodeFinding(doc)
		if err != nil {
			return nil, err
		}
		out = append(out, *f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("finding store: list findings: %w", err)
	}
	return out, nil
}

func decodeFinding(doc []byte) (*finding.EnhancedFinding, error) {
	var f finding.EnhancedFinding
	if err := json.Unmarshal(doc, &f); err != nil {
		return nil, fmt.Errorf("finding store: decode finding: %w", err)
	}
	return &f, nil
}
