// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build integration
// +build integration

// store_integration_test.go runs the finding store against a real Postgres
// (testcontainers). It applies the shipped migrations, so it proves that the
// migrations and the store agree. The test skips when Docker is not available.
package pgstore_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/finding"
	"github.com/zeroroot-ai/gibson/internal/engine/finding/pgstore"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/tests/testhelpers"
	"github.com/zeroroot-ai/sdk/auth"
)

type tenantPool struct{ pg *pgxpool.Pool }

func (p *tenantPool) For(_ context.Context, tenant auth.TenantID) (*datapool.Conn, error) {
	return &datapool.Conn{Tenant: tenant, Postgres: p.pg}, nil
}
func (p *tenantPool) Admin(context.Context) (*datapool.AdminConn, error) { return nil, nil }
func (p *tenantPool) SetAdminPool(datapool.AdminAcquirer)                {}
func (p *tenantPool) Close() error                                       { return nil }

func newStore(t *testing.T) (*pgstore.Store, *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	pgTLS := testhelpers.StartPostgresTLS(t, testhelpers.PostgresOptions{
		User: "testuser", Password: "testpass", Database: "testdb",
	})
	var pool *pgxpool.Pool
	require.Eventually(t, func() bool {
		var err error
		pool, err = pgxpool.New(ctx, pgTLS.DSN)
		if err != nil {
			return false
		}
		return pool.Ping(ctx) == nil
	}, 30*time.Second, 200*time.Millisecond, "Postgres not ready")
	t.Cleanup(pool.Close)

	base := filepath.Join("..", "..", "..", "..", "pkg", "platform", "migrations", "postgres", "tenant")
	for _, name := range []string{"004_findings.up.sql", "017_findings_mission_nullable.up.sql"} {
		up, err := os.ReadFile(filepath.Join(base, name))
		require.NoError(t, err, "read %s", name)
		_, err = pool.Exec(ctx, string(up))
		require.NoError(t, err, "apply %s", name)
	}
	tp := &tenantPool{pg: pool}
	return pgstore.New(func() datapool.Pool { return tp }), pool
}

func TestStore_Integration_RoundTrip(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()
	mission := types.NewID()
	now := time.Now().UTC().Truncate(time.Millisecond)

	mk := func(m types.ID, title string, sev agent.FindingSeverity, at time.Time) finding.EnhancedFinding {
		f := finding.NewEnhancedFinding(agent.NewFinding(title, "d", sev), m, "recon")
		f.CreatedAt = at
		return f
	}
	a := mk(mission, "a", agent.SeverityHigh, now)
	b := mk(mission, "b", agent.SeverityLow, now.Add(time.Second))
	orphan := mk("", "orphan", agent.SeverityHigh, now.Add(2*time.Second))
	for _, f := range []finding.EnhancedFinding{a, b, orphan} {
		require.NoError(t, s.Store(ctx, "acme", f))
	}

	var rows int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM findings`).Scan(&rows))
	assert.Equal(t, 3, rows, "one row for each finding")

	got, err := s.Get(ctx, "acme", a.ID)
	require.NoError(t, err)
	assert.Equal(t, "a", got.Title)

	list, err := s.List(ctx, "acme", mission, nil)
	require.NoError(t, err)
	require.Len(t, list, 2)
	assert.Equal(t, "a", list[0].Title)

	high, err := s.ListBySeverity(ctx, "acme", agent.SeverityHigh)
	require.NoError(t, err)
	assert.Len(t, high, 2)

	_, err = s.Get(ctx, "acme", types.NewID())
	require.ErrorIs(t, err, finding.ErrNotFound)
}
