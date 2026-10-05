// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build integration
// +build integration

// Retention against a real Postgres (testcontainers). These tests prove the
// rules that a mock cannot: which rows a run removes, and that the hash
// chain of a tenant still verifies after the run.
package audit

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeAged writes n events for a tenant with WriteSync, then moves their
// created_at to the given time. The move is a test device: the chain hash
// commits to created_at, so the test computes the hash again for each moved
// row, in chain order, as the writer does.
func writeAged(t *testing.T, db *sql.DB, w *Writer, tenant string, n int, age time.Time) {
	t.Helper()
	ctx := context.Background()
	for i := 0; i < n; i++ {
		require.NoError(t, w.WriteSync(ctx, auditTestEvent(tenant, "aged.event")))
	}
	rechainFrom(t, db, tenant, age)
}

// rechainFrom sets created_at of each row of the tenant that was written in
// the last minute to at, and writes the chain again from the first row, so
// the stored hashes match the stored fields.
func rechainFrom(t *testing.T, db *sql.DB, tenant string, at time.Time) {
	t.Helper()
	_, err := db.ExecContext(context.Background(),
		`UPDATE audit_log SET created_at = $2 WHERE tenant_id = $1 AND created_at > now() - interval '1 minute'`,
		tenant, at.UTC().Truncate(time.Microsecond))
	require.NoError(t, err)
	rechainAll(t, db, tenant)
}

func mustVerify(t *testing.T, db *sql.DB, tenant string) ChainReport {
	t.Helper()
	report, err := NewQuery(db).VerifyChain(context.Background(), tenant)
	require.NoError(t, err)
	return report
}

// TestRetention_RemovesOnlyRowsOlderThanThePeriod: three rows are 14 months
// old, and two rows are 12 months old. A run with the default of 13 months
// removes the three. The two inside the period stay readable, and the chain
// verifies from its anchor.
func TestRetention_RemovesOnlyRowsOlderThanThePeriod(t *testing.T) {
	db := setupAuditPostgres(t)
	ctx := context.Background()
	w := NewWriter(db, auditSilentLogger())
	now := time.Now().UTC()

	writeAged(t, db, w, "acme", 3, now.AddDate(0, -14, 0))
	require.NoError(t, w.WriteSync(ctx, auditTestEvent("acme", "inside.one")))
	require.NoError(t, w.WriteSync(ctx, auditTestEvent("acme", "inside.two")))
	// Age the two new rows to 12 months. The first three keep 14 months.
	_, err := db.ExecContext(ctx,
		`UPDATE audit_log SET created_at = $2 WHERE tenant_id = $1 AND chain_seq > 3`,
		"acme", now.AddDate(0, -12, 0).Truncate(time.Microsecond))
	require.NoError(t, err)
	rechainAll(t, db, "acme")
	require.True(t, mustVerify(t, db, "acme").Intact(), "the fixture chain must verify before the run")

	// A second tenant with new rows only. The run must not touch it.
	require.NoError(t, w.WriteSync(ctx, auditTestEvent("beta", "new.event")))

	r, err := NewRetention(db, MinRetentionMonths, auditSilentLogger())
	require.NoError(t, err)
	removed, err := r.Prune(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(3), removed, "retention must remove the three rows that are older than 13 months")

	// The rows inside the period are readable.
	entries, total, err := NewQuery(db).List(ctx, "acme", Filters{}, 10, 0)
	require.NoError(t, err)
	require.Equal(t, 2, total)
	actions := []string{entries[0].Action, entries[1].Action}
	assert.ElementsMatch(t, []string{"inside.one", "inside.two"}, actions)
	assert.Equal(t, 1, countRows(t, db, "beta"), "a tenant with no old row keeps each row")

	// The chain verifies from the anchor.
	report := mustVerify(t, db, "acme")
	assert.True(t, report.Intact(), "the chain must verify after retention: %+v", report)
	assert.Equal(t, int64(4), report.FirstSeq)
	assert.Equal(t, 2, report.Chained)

	// The writer extends the same chain, and it still verifies.
	require.NoError(t, w.WriteSync(ctx, auditTestEvent("acme", "after.retention")))
	report = mustVerify(t, db, "acme")
	assert.True(t, report.Intact(), "%+v", report)
	assert.Equal(t, 3, report.Chained)

	// A second run removes nothing.
	removed, err = r.Prune(ctx)
	require.NoError(t, err)
	assert.Zero(t, removed)
}

// TestRetention_ALongerPeriodKeepsTheRows: the install has 24 months. Rows
// that are 14 months old stay.
func TestRetention_ALongerPeriodKeepsTheRows(t *testing.T) {
	db := setupAuditPostgres(t)
	ctx := context.Background()
	w := NewWriter(db, auditSilentLogger())

	writeAged(t, db, w, "acme", 3, time.Now().UTC().AddDate(0, -14, 0))

	r, err := NewRetention(db, 24, auditSilentLogger())
	require.NoError(t, err)
	removed, err := r.Prune(ctx)
	require.NoError(t, err)
	assert.Zero(t, removed)
	assert.Equal(t, 3, countRows(t, db, "acme"))
	assert.True(t, mustVerify(t, db, "acme").Intact())
}

// TestRetention_EachRowOld_WriterContinuesTheChain: retention removes each
// row of a tenant. The next record continues the chain from the anchor, and
// the chain verifies.
func TestRetention_EachRowOld_WriterContinuesTheChain(t *testing.T) {
	db := setupAuditPostgres(t)
	ctx := context.Background()
	w := NewWriter(db, auditSilentLogger())

	writeAged(t, db, w, "acme", 3, time.Now().UTC().AddDate(0, -20, 0))

	r, err := NewRetention(db, MinRetentionMonths, auditSilentLogger())
	require.NoError(t, err)
	removed, err := r.Prune(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(3), removed)
	assert.Zero(t, countRows(t, db, "acme"))

	// "acme" has no row now, so Prune does not list it. The anchor stays.
	require.NoError(t, w.WriteSync(ctx, auditTestEvent("acme", "first.after")))
	report := mustVerify(t, db, "acme")
	assert.True(t, report.Intact(), "%+v", report)
	assert.Equal(t, int64(4), report.FirstSeq, "the new row continues at position 4, not at position 1")
	assert.Equal(t, 1, report.Chained)
}

// rechainAll writes the chain of a tenant again from its first row, after a
// test changed created_at.
func rechainAll(t *testing.T, db *sql.DB, tenant string) {
	t.Helper()
	ctx := context.Background()
	rows, err := db.QueryContext(ctx, `
SELECT chain_seq, actor_id, actor_type, action, COALESCE(target_type, ''), COALESCE(target_id, ''),
       COALESCE(decision, ''), metadata, created_at
FROM audit_log WHERE tenant_id = $1 ORDER BY chain_seq ASC`, tenant)
	require.NoError(t, err)
	var chain []chainRow
	for rows.Next() {
		r := chainRow{TenantID: tenant}
		require.NoError(t, rows.Scan(&r.Seq, &r.ActorID, &r.ActorType, &r.Action,
			&r.TargetType, &r.TargetID, &r.Decision, &r.Metadata, &r.CreatedAt))
		chain = append(chain, r)
	}
	require.NoError(t, rows.Close())
	require.NoError(t, rows.Err())

	prev := chainGenesis()
	for _, r := range chain {
		r.PrevHash = prev
		r.EntryHash = computeEntryHash(r)
		_, err := db.ExecContext(ctx,
			`UPDATE audit_log SET prev_hash = $3, entry_hash = $4 WHERE tenant_id = $1 AND chain_seq = $2`,
			tenant, r.Seq, r.PrevHash, r.EntryHash)
		require.NoError(t, err)
		prev = r.EntryHash
	}
}
