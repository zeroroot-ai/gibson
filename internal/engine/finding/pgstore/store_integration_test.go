// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build integration
// +build integration

// store_integration_test.go runs the finding store against a real Postgres
// server that FINDING_TEST_PG_DSN names. It applies the shipped migrations with
// the migration runner, so it proves that the migrations and the store agree.
package pgstore_test

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
	typespb "github.com/zeroroot-ai/sdk/api/gen/gibson/types/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

type tenantPool struct{ pg *pgxpool.Pool }

func (p *tenantPool) For(_ context.Context, tenant auth.TenantID) (*datapool.Conn, error) {
	return &datapool.Conn{Tenant: tenant, Postgres: p.pg}, nil
}
func (p *tenantPool) Admin(context.Context) (*datapool.AdminConn, error) { return nil, nil }
func (p *tenantPool) SetAdminPool(datapool.AdminAcquirer)                {}
func (p *tenantPool) Close() error                                       { return nil }

// adminDSNEnv names the DSN of a Postgres server that the test may create
// databases on. The test skips when it is not set.
const adminDSNEnv = "FINDING_TEST_PG_DSN"

// newStore makes a fresh database, applies every tenant migration with the
// migration runner of the repo, and returns a store on it.
func newStore(t *testing.T) (*pgstore.Store, *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	adminDSN := os.Getenv(adminDSNEnv)
	if adminDSN == "" {
		t.Skipf("%s is not set", adminDSNEnv)
	}
	admin, err := pgxpool.New(ctx, adminDSN)
	require.NoError(t, err)
	t.Cleanup(admin.Close)
	dbName := "findings_" + strings.ReplaceAll(types.NewID().String(), "-", "")
	_, err = admin.Exec(ctx, "CREATE DATABASE "+dbName)
	require.NoError(t, err)

	cfg, err := pgxpool.ParseConfig(adminDSN)
	require.NoError(t, err)
	cfg.ConnConfig.Database = dbName
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	db := stdlib.OpenDB(*cfg.ConnConfig)
	t.Cleanup(func() { _ = db.Close() })
	src, err := migrations.NewTenantSource()
	require.NoError(t, err)
	driver, err := migratepg.WithInstance(db, &migratepg.Config{DatabaseName: dbName})
	require.NoError(t, err)
	m, err := migrate.NewWithInstance("iofs", src, dbName, driver)
	require.NoError(t, err)
	require.NoError(t, m.Up(), "the tenant migrations apply")

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

func TestStore_Integration_EvidenceRowsAndCascade(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()
	f := finding.NewEnhancedFinding(agent.NewFinding("a", "d", agent.SeverityHigh), types.NewID(), "recon")
	f.Evidence = []*typespb.Evidence{
		{
			Title: "tool call httpx (call-1)", Type: typespb.EvidenceType_EVIDENCE_TYPE_LOG, Content: "recorded",
			Tier: typespb.EvidenceTier_EVIDENCE_TIER_RECORDED, ToolCallId: "call-1",
			Metadata: map[string]string{"tool_name": "httpx"},
		},
		{Title: "dialogue", Type: typespb.EvidenceType_EVIDENCE_TYPE_CONVERSATION, Content: "hello",
			Tier: typespb.EvidenceTier_EVIDENCE_TIER_TYPED},
	}
	require.NoError(t, s.Store(ctx, "acme", f))

	got, err := s.GetWithEvidence(ctx, "acme", f.ID)
	require.NoError(t, err)
	require.Len(t, got.Evidence, 2)
	assert.Equal(t, typespb.EvidenceTier_EVIDENCE_TIER_RECORDED, got.Evidence[0].GetTier())
	assert.Equal(t, "call-1", got.Evidence[0].GetToolCallId())
	assert.Equal(t, "recorded", got.Evidence[0].GetContent())
	assert.Equal(t, typespb.EvidenceTier_EVIDENCE_TIER_TYPED, got.Evidence[1].GetTier())

	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM finding_evidence WHERE finding_id = $1`, f.ID.String()).Scan(&n))
	assert.Equal(t, 2, n, "one row for each item")

	var digestOK bool
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT content_sha256 = sha256(convert_to(content, 'UTF8')) FROM finding_evidence
		 WHERE finding_id = $1 AND position = 0`, f.ID.String()).Scan(&digestOK))
	assert.True(t, digestOK, "the hash is the SHA-256 of the content")

	// A tier 1 item with no tool call breaks the CHECK of the table.
	_, err = pool.Exec(ctx, `INSERT INTO finding_evidence
		(finding_id, position, tier, tool_call_id, type, content, content_sha256)
		VALUES ($1, 9, 1, NULL, 'EVIDENCE_TYPE_LOG', 'x', sha256('x'))`, f.ID.String())
	require.Error(t, err)

	// The store refuses an invalid item and writes no finding row.
	bad := finding.NewEnhancedFinding(agent.NewFinding("b", "d", agent.SeverityLow), types.NewID(), "recon")
	bad.Evidence = []*typespb.Evidence{{Content: "x", Tier: typespb.EvidenceTier_EVIDENCE_TIER_RECORDED}}
	require.Error(t, s.Store(ctx, "acme", bad))
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM findings WHERE id = $1`, bad.ID.String()).Scan(&n))
	assert.Zero(t, n)

	// The delete of a finding deletes its evidence rows.
	_, err = pool.Exec(ctx, `DELETE FROM findings WHERE id = $1`, f.ID.String())
	require.NoError(t, err)
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM finding_evidence`).Scan(&n))
	assert.Zero(t, n, "the delete cascades")
}

// TestStore_Integration_TransactionRollback makes the database refuse an
// evidence row after the finding row was written. A NUL byte is valid in a Go
// string and invalid in Postgres text. The finding row must not stay.
func TestStore_Integration_TransactionRollback(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()
	f := finding.NewEnhancedFinding(agent.NewFinding("a", "d", agent.SeverityHigh), types.NewID(), "recon")
	f.Evidence = []*typespb.Evidence{
		{Title: "ok", Content: "fine", Tier: typespb.EvidenceTier_EVIDENCE_TIER_TYPED},
		{Title: "bad", Content: "nul\x00byte", Tier: typespb.EvidenceTier_EVIDENCE_TIER_TYPED},
	}

	err := s.Store(ctx, "acme", f)

	require.Error(t, err)
	var n int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM findings`).Scan(&n))
	assert.Zero(t, n, "no finding row")
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM finding_evidence`).Scan(&n))
	assert.Zero(t, n, "no evidence row")
}

// TestStore_Integration_SizeLimit proves the 1 MiB refusal. The item at the
// limit is stored whole. The item over the limit fails the submit.
func TestStore_Integration_SizeLimit(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()
	mk := func(size int) finding.EnhancedFinding {
		f := finding.NewEnhancedFinding(agent.NewFinding("a", "d", agent.SeverityHigh), types.NewID(), "recon")
		f.Evidence = []*typespb.Evidence{{
			Content: strings.Repeat("x", size), Tier: typespb.EvidenceTier_EVIDENCE_TIER_RECORDED, ToolCallId: "call-1",
		}}
		return f
	}

	over := mk(finding.MaxEvidenceContentBytes + 1)
	require.ErrorIs(t, s.Store(ctx, "acme", over), finding.ErrEvidenceTooLarge)
	var n int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM findings`).Scan(&n))
	assert.Zero(t, n, "nothing written")

	at := mk(finding.MaxEvidenceContentBytes)
	require.NoError(t, s.Store(ctx, "acme", at))
	got, err := s.GetWithEvidence(ctx, "acme", at.ID)
	require.NoError(t, err)
	require.Len(t, got.Evidence, 1)
	assert.Len(t, got.Evidence[0].GetContent(), finding.MaxEvidenceContentBytes, "stored whole, never truncated")
}
