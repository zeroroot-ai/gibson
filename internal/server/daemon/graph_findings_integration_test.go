// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build integration
// +build integration

package daemon

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"
	migratepg "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/finding"
	"github.com/zeroroot-ai/gibson/internal/engine/finding/pgstore"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/pkg/platform/migrations"
	graphpb "github.com/zeroroot-ai/sdk/api/gen/gibson/graph/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

type pgTenantPool struct{ pg *pgxpool.Pool }

func (p *pgTenantPool) For(_ context.Context, tenant auth.TenantID) (*datapool.Conn, error) {
	return &datapool.Conn{Tenant: tenant, Postgres: p.pg}, nil
}
func (p *pgTenantPool) Admin(context.Context) (*datapool.AdminConn, error) { return nil, nil }
func (p *pgTenantPool) SetAdminPool(datapool.AdminAcquirer)                {}
func (p *pgTenantPool) Close() error                                       { return nil }

// newFindingsDB makes a fresh database with every tenant migration applied. The
// test reads FINDING_TEST_PG_DSN and skips if it is not set.
func newFindingsDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()
	adminDSN := os.Getenv("FINDING_TEST_PG_DSN")
	if adminDSN == "" {
		t.Skip("FINDING_TEST_PG_DSN is not set")
	}
	admin, err := pgxpool.New(ctx, adminDSN)
	require.NoError(t, err)
	t.Cleanup(admin.Close)
	name := "gfind_" + strings.ReplaceAll(types.NewID().String(), "-", "")
	_, err = admin.Exec(ctx, "CREATE DATABASE "+name)
	require.NoError(t, err)
	cfg, err := pgxpool.ParseConfig(adminDSN)
	require.NoError(t, err)
	cfg.ConnConfig.Database = name
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	db := stdlib.OpenDB(*cfg.ConnConfig)
	t.Cleanup(func() { _ = db.Close() })
	src, err := migrations.NewTenantSource()
	require.NoError(t, err)
	driver, err := migratepg.WithInstance(db, &migratepg.Config{DatabaseName: name})
	require.NoError(t, err)
	m, err := migrate.NewWithInstance("iofs", src, name, driver)
	require.NoError(t, err)
	require.NoError(t, m.Up())
	return pool
}

func TestGraphService_Integration_FindingReadsComeFromPostgres(t *testing.T) {
	pg := newFindingsDB(t)
	tp := &pgTenantPool{pg: pg}
	srv := graphServerWithPool(func() datapool.Pool { return tp })
	ctx := graphTenantCtx()
	store := pgstore.New(func() datapool.Pool { return tp })

	m := types.NewID()
	now := time.Now().UTC()
	for i, sev := range []agent.FindingSeverity{agent.SeverityHigh, agent.SeverityHigh, agent.SeverityLow} {
		f := finding.NewEnhancedFinding(
			agent.NewFinding("finding "+string(rune('a'+i)), "d", sev).WithCategory("injection"), m, "recon")
		f.CreatedAt = now.Add(time.Duration(i) * time.Second)
		require.NoError(t, store.Store(ctx, "test-graph-tenant", f))
	}

	// Page size 999 is clamped, and the three findings come back, newest first.
	resp, err := srv.GetFindings(ctx, &graphpb.GetFindingsRequest{PageSize: 999})
	require.NoError(t, err)
	require.Len(t, resp.GetFindings(), 3)
	assert.Equal(t, uint64(3), resp.GetTotal())
	assert.Equal(t, "finding c", resp.GetFindings()[0].GetName())
	assert.Equal(t, m.String(), resp.GetFindings()[0].GetMissionId())
	assert.Equal(t, "low", resp.GetFindings()[0].GetSeverity())

	// A page of one has a next token.
	page, err := srv.GetFindings(ctx, &graphpb.GetFindingsRequest{PageSize: 1})
	require.NoError(t, err)
	assert.Len(t, page.GetFindings(), 1)
	assert.True(t, page.GetTruncated())
	assert.NotEmpty(t, page.GetNextPageToken())

	high, err := srv.GetFindings(ctx, &graphpb.GetFindingsRequest{SeverityFilter: "high", MissionId: m.String()})
	require.NoError(t, err)
	assert.Len(t, high.GetFindings(), 2)

	none, err := srv.GetFindings(ctx, &graphpb.GetFindingsRequest{MissionId: "not-a-uuid"})
	require.NoError(t, err)
	assert.Empty(t, none.GetFindings())

	counts, err := srv.GetFindingCounts(ctx, &graphpb.GetFindingCountsRequest{GroupBy: graphpb.FindingCountGroupBy_SEVERITY})
	require.NoError(t, err)
	require.Len(t, counts.GetBuckets(), 2)
	assert.Equal(t, "high", counts.GetBuckets()[0].GetLabel())
	assert.Equal(t, uint64(2), counts.GetBuckets()[0].GetCount())

	series, err := srv.GetFindingTimeSeries(ctx, &graphpb.GetFindingTimeSeriesRequest{Days: 7})
	require.NoError(t, err)
	require.Len(t, series.GetPoints(), 7, "the series is padded to the days asked for")
	var sum uint64
	for _, p := range series.GetPoints() {
		sum += p.GetCount()
	}
	assert.Equal(t, uint64(3), sum)
}
