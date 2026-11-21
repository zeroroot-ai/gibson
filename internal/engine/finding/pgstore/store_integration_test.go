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
	pool, m := newMigratedDB(t)
	require.NoError(t, m.Up(), "the tenant migrations apply")
	tp := &tenantPool{pg: pool}
	return pgstore.New(func() datapool.Pool { return tp }), pool
}

// newMigratedDB makes a fresh database and returns a pool on it and the
// migration runner of the repo, with no migration applied yet.
func newMigratedDB(t *testing.T) (*pgxpool.Pool, *migrate.Migrate) {
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
	return pool, m
}

// Migration 023 maps the old statuses to the four of ADR-0178 and keeps the
// old value, and its down step restores it (review m11).
func TestMigration023_MapsTheOldStatuses(t *testing.T) {
	pool, m := newMigratedDB(t)
	ctx := context.Background()
	require.NoError(t, m.Migrate(22))
	want := map[string]string{"confirmed": "open", "resolved": "fixed", "false_positive": "open", "fixing": "fixing"}
	ids := map[string]string{}
	for old := range want {
		id := types.NewID().String()
		ids[old] = id
		_, err := pool.Exec(ctx, `INSERT INTO findings (id, mission_id, title, document) VALUES ($1, $2, 't', $3)`,
			id, types.NewID().String(), `{"status":"`+old+`"}`)
		require.NoError(t, err)
	}
	status := func(id string) string {
		var s string
		require.NoError(t, pool.QueryRow(ctx, `SELECT document->>'status' FROM findings WHERE id = $1`, id).Scan(&s))
		return s
	}
	require.NoError(t, m.Migrate(23))
	for old, id := range ids {
		assert.Equal(t, want[old], status(id), "up: %s", old)
	}
	require.NoError(t, m.Migrate(22))
	for old, id := range ids {
		assert.Equal(t, old, status(id), "down: %s", old)
	}
}

// Confidences reads the confidence of each finding of a list in one read. A
// finding with no row and an ID that is no UUID are left out (review m9).
func TestStore_Integration_Confidences(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	f := finding.NewEnhancedFinding(agent.NewFinding("a", "d", agent.SeverityHigh), types.NewID(), "recon")
	f.Check = finding.Check{Kind: finding.CheckScan}
	f.Confidence = 0.7
	require.NoError(t, s.Store(ctx, "acme", f))
	got, err := s.Confidences(ctx, "acme", []types.ID{f.ID, types.NewID(), "not-a-uuid"})
	require.NoError(t, err)
	assert.Equal(t, map[types.ID]float64{f.ID: 0.7}, got)
}

func TestStore_Integration_EvidenceRowsAndCascade(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()
	f := finding.NewEnhancedFinding(agent.NewFinding("a", "d", agent.SeverityHigh), types.NewID(), "recon")
	f.Check = finding.Check{Kind: finding.CheckScan}
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
	bad.Check = finding.Check{Kind: finding.CheckScan}
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
	f.Check = finding.Check{Kind: finding.CheckScan}
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
		f.Check = finding.Check{Kind: finding.CheckScan}
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

// TestStore_Integration_FindAndFindWithEvidence checks the list queries against
// a real Postgres: each filter, the total, the order, the page, and the rule
// that a list returns no evidence while FindWithEvidence returns all of it.
func TestStore_Integration_FindAndFindWithEvidence(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	m1, m2 := types.NewID(), types.NewID()
	now := time.Now().UTC().Truncate(time.Millisecond)
	mk := func(m types.ID, title, desc, cat string, sev agent.FindingSeverity, at time.Time) finding.EnhancedFinding {
		f := finding.NewEnhancedFinding(agent.NewFinding(title, desc, sev).WithCategory(cat), m, "recon")
		f.Check = finding.Check{Kind: finding.CheckScan}
		f.CreatedAt = at
		return f
	}
	a := mk(m1, "SQL injection", "login form", "injection", agent.SeverityCritical, now)
	b := mk(m1, "Open redirect", "100% of links", "redirect", agent.SeverityMedium, now.Add(time.Second))
	c := mk(m2, "XSS", "search box", "Injection", agent.SeverityHigh, now.Add(2*time.Second))
	a.Evidence = []*typespb.Evidence{
		{Title: "t1", Content: "recorded", Tier: typespb.EvidenceTier_EVIDENCE_TIER_RECORDED, ToolCallId: "call-1"},
		{Title: "t2", Content: "typed", Tier: typespb.EvidenceTier_EVIDENCE_TIER_TYPED},
	}
	for _, f := range []finding.EnhancedFinding{a, b, c} {
		require.NoError(t, s.Store(ctx, "acme", f))
	}

	titles := func(fs []finding.EnhancedFinding) []string {
		out := make([]string, len(fs))
		for i, f := range fs {
			out[i] = f.Title
		}
		return out
	}

	all, total, err := s.Find(ctx, "acme", pgstore.Query{})
	require.NoError(t, err)
	assert.Equal(t, 3, total)
	assert.Equal(t, []string{"XSS", "Open redirect", "SQL injection"}, titles(all), "newest first")
	for _, f := range all {
		assert.Empty(t, f.Evidence, "a list holds no evidence")
	}

	byMission, total, err := s.Find(ctx, "acme", pgstore.Query{MissionID: m1})
	require.NoError(t, err)
	assert.Equal(t, 2, total)
	assert.Equal(t, []string{"Open redirect", "SQL injection"}, titles(byMission))

	bySev, _, err := s.Find(ctx, "acme", pgstore.Query{Severities: []string{"critical", "high"}})
	require.NoError(t, err)
	assert.Equal(t, []string{"XSS", "SQL injection"}, titles(bySev))

	byCat, _, err := s.Find(ctx, "acme", pgstore.Query{Category: "injection"})
	require.NoError(t, err)
	assert.Equal(t, []string{"XSS", "SQL injection"}, titles(byCat), "the category match ignores case")

	bySearch, _, err := s.Find(ctx, "acme", pgstore.Query{Search: "LOGIN"})
	require.NoError(t, err)
	assert.Equal(t, []string{"SQL injection"}, titles(bySearch))
	wild, _, err := s.Find(ctx, "acme", pgstore.Query{Search: "100%"})
	require.NoError(t, err)
	assert.Equal(t, []string{"Open redirect"}, titles(wild), "a percent sign in the search is text")
	none, total, err := s.Find(ctx, "acme", pgstore.Query{Search: "%"})
	require.NoError(t, err)
	assert.Equal(t, 1, total, "only the finding that holds a percent sign matches")
	assert.Equal(t, []string{"Open redirect"}, titles(none))

	byID, _, err := s.Find(ctx, "acme", pgstore.Query{IDs: []types.ID{a.ID, c.ID}})
	require.NoError(t, err)
	assert.Len(t, byID, 2)

	page, total, err := s.Find(ctx, "acme", pgstore.Query{Limit: 1, Offset: 1})
	require.NoError(t, err)
	assert.Equal(t, 3, total, "the total ignores the page")
	assert.Equal(t, []string{"Open redirect"}, titles(page))

	withEvidence, _, err := s.FindWithEvidence(ctx, "acme", pgstore.Query{MissionID: m1})
	require.NoError(t, err)
	require.Len(t, withEvidence, 2)
	assert.Empty(t, withEvidence[0].Evidence, "Open redirect has none")
	require.Len(t, withEvidence[1].Evidence, 2)
	assert.Equal(t, typespb.EvidenceTier_EVIDENCE_TIER_RECORDED, withEvidence[1].Evidence[0].GetTier())
	assert.Equal(t, "call-1", withEvidence[1].Evidence[0].GetToolCallId())
	assert.Equal(t, typespb.EvidenceTier_EVIDENCE_TIER_TYPED, withEvidence[1].Evidence[1].GetTier())
}

func TestStore_Integration_CountsAndDailyCounts(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	m := types.NewID()
	now := time.Now().UTC()
	mk := func(sev agent.FindingSeverity, cat string, at time.Time) finding.EnhancedFinding {
		f := finding.NewEnhancedFinding(agent.NewFinding("t", "d", sev).WithCategory(cat), m, "recon")
		f.Check = finding.Check{Kind: finding.CheckScan}
		f.CreatedAt = at
		return f
	}
	for _, f := range []finding.EnhancedFinding{
		mk(agent.SeverityHigh, "injection", now),
		mk(agent.SeverityHigh, "", now.Add(-time.Hour)),
		mk(agent.SeverityLow, "injection", now.AddDate(0, 0, -10)),
	} {
		require.NoError(t, s.Store(ctx, "acme", f))
	}

	bySev, err := s.CountBy(ctx, "acme", "severity", 0)
	require.NoError(t, err)
	assert.Equal(t, []pgstore.Bucket{{Label: "high", Count: 2}, {Label: "low", Count: 1}}, bySev)

	byCat, err := s.CountBy(ctx, "acme", "category", 0)
	require.NoError(t, err)
	assert.Equal(t, []pgstore.Bucket{{Label: "injection", Count: 2}, {Label: "unknown", Count: 1}}, byCat)

	windowed, err := s.CountBy(ctx, "acme", "severity", 24*time.Hour)
	require.NoError(t, err)
	assert.Equal(t, []pgstore.Bucket{{Label: "high", Count: 2}}, windowed)

	_, err = s.CountBy(ctx, "acme", "mission", 0)
	require.Error(t, err)

	daily, err := s.DailyCounts(ctx, "acme", 5)
	require.NoError(t, err)
	var sum uint64
	for _, n := range daily {
		sum += n
	}
	assert.Equal(t, uint64(2), sum, "the finding of ten days ago is outside five days")
}

// A second submit of one finding keeps the status, the check and the priority
// that the daemon set, on a real Postgres (gibson#1448, ADR-0178).
func TestStore_Integration_ASecondSubmitKeepsTheFieldsOfTheDaemon(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	f := finding.NewEnhancedFinding(agent.NewFinding("open port", "d", agent.SeverityHigh), types.NewID(), "intake")
	f.Check = finding.Check{Kind: finding.CheckTool, Ref: "wiz/r-1"}
	require.NoError(t, s.Store(ctx, "acme", f))
	_, err := s.SetStatus(ctx, "acme", f.ID, finding.StatusFixing)
	require.NoError(t, err)
	_, err = s.SetPriority(ctx, "acme", f.ID, finding.PriorityP1, "kev")
	require.NoError(t, err)

	again := f
	again.Title = "open port 22"
	again.Status = finding.StatusOpen
	again.Priority, again.PriorityRule = "", ""
	require.NoError(t, s.Store(ctx, "acme", again))

	got, err := s.Get(ctx, "acme", f.ID)
	require.NoError(t, err)
	assert.Equal(t, "open port 22", got.Title)
	assert.Equal(t, finding.StatusFixing, got.Status)
	assert.Equal(t, finding.PriorityP1, got.Priority)
	assert.Equal(t, finding.CheckTool, got.Check.Kind)
}
