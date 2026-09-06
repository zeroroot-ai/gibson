// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Tests for the audit_log hash chain. Hermetic — go-sqlmock stands in for
// Postgres, so no container is required.
//
// The load-bearing test is TestChain_RoundTrip_WriterOutputVerifies: it feeds
// the rows the Writer actually produced straight back into VerifyChain. If
// the two sides ever disagree about the canonical encoding, that test fails
// rather than the disagreement surfacing as a false tamper alarm in
// production.
package audit

import (
	"context"
	"database/sql/driver"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// argCapture is a sqlmock.Argument that matches anything and records what it
// saw, so a test can inspect the exact parameters the Writer sent.
type argCapture struct{ seen *[]driver.Value }

func (a argCapture) Match(v driver.Value) bool {
	*a.seen = append(*a.seen, v)
	return true
}

// captureArgs returns n matchers that all append into seen.
func captureArgs(n int, seen *[]driver.Value) []driver.Value {
	out := make([]driver.Value, n)
	for i := range out {
		out[i] = argCapture{seen: seen}
	}
	return out
}

// capturedRows reslices the flat INSERT parameter list into chainRows.
func capturedRows(t *testing.T, seen []driver.Value) []chainRow {
	t.Helper()
	const cols = 12
	require.Zero(t, len(seen)%cols, "captured %d args, not a multiple of %d", len(seen), cols)

	str := func(v driver.Value) string {
		if v == nil {
			return ""
		}
		s, ok := v.(string)
		require.True(t, ok, "expected string arg, got %T", v)
		return s
	}

	rows := make([]chainRow, 0, len(seen)/cols)
	for i := 0; i < len(seen); i += cols {
		rows = append(rows, chainRow{
			TenantID:   str(seen[i]),
			ActorID:    str(seen[i+1]),
			ActorType:  str(seen[i+2]),
			Action:     str(seen[i+3]),
			TargetType: str(seen[i+4]),
			TargetID:   str(seen[i+5]),
			Decision:   str(seen[i+6]),
			Metadata:   seen[i+7].([]byte),
			CreatedAt:  seen[i+8].(time.Time),
			Seq:        seen[i+9].(int64),
			PrevHash:   seen[i+10].([]byte),
			EntryHash:  seen[i+11].([]byte),
		})
	}
	return rows
}

// chainRowsToSQL turns chainRows into the result set VerifyChain reads.
func chainRowsToSQL(rows []chainRow) *sqlmock.Rows {
	out := sqlmock.NewRows([]string{
		"chain_seq", "prev_hash", "entry_hash", "actor_id", "actor_type",
		"action", "target_type", "target_id", "decision", "metadata", "created_at",
	})
	for _, r := range rows {
		out.AddRow(r.Seq, r.PrevHash, r.EntryHash, r.ActorID, r.ActorType,
			r.Action, r.TargetType, r.TargetID, r.Decision, r.Metadata, r.CreatedAt)
	}
	return out
}

// flushEvents runs Writer.flush against sqlmock and returns the rows it
// inserted. head is the tenant's pre-existing chain head (nil = empty chain).
func flushEvents(t *testing.T, tenant string, head *chainRow, events []Event) []chainRow {
	t.Helper()

	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	var seen []driver.Value

	mock.ExpectBegin()
	mock.ExpectExec("pg_advisory_xact_lock").
		WithArgs(tenantAdvisoryKey(tenant)).
		WillReturnResult(sqlmock.NewResult(0, 0))

	headRows := sqlmock.NewRows([]string{"chain_seq", "entry_hash"})
	if head != nil {
		headRows.AddRow(head.Seq, head.EntryHash)
	}
	mock.ExpectQuery("ORDER  BY chain_seq DESC").
		WithArgs(tenant).
		WillReturnRows(headRows)

	mock.ExpectExec("INSERT INTO audit_log").
		WithArgs(captureArgs(12*len(events), &seen)...).
		WillReturnResult(sqlmock.NewResult(0, int64(len(events))))
	mock.ExpectCommit()

	w := NewWriter(db, silentLogger())
	require.NoError(t, w.flush(context.Background(), events))
	require.NoError(t, mock.ExpectationsWereMet())

	return capturedRows(t, seen)
}

// verify runs VerifyChain over a fixed set of rows.
func verify(t *testing.T, tenant string, unchained int, rows []chainRow) ChainReport {
	t.Helper()

	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	mock.ExpectQuery("COUNT").
		WithArgs(tenant).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(unchained))
	mock.ExpectQuery("ORDER  BY chain_seq ASC").
		WithArgs(tenant).
		WillReturnRows(chainRowsToSQL(rows))

	report, err := NewQuery(db).VerifyChain(context.Background(), tenant)
	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
	return report
}

// threeEvents is the fixture most tests chain.
func threeEvents(tenant string) []Event {
	return []Event{
		{TenantID: tenant, ActorID: "u1", ActorType: "user", Action: "grant_created", TargetType: "component", TargetID: "c1", Decision: "allow"},
		{TenantID: tenant, ActorID: "u2", ActorType: "user", Action: "grant_revoked", TargetType: "component", TargetID: "c2", Decision: "deny"},
		{TenantID: tenant, ActorID: "u3", ActorType: "system", Action: "agent_registered", TargetType: "agent", TargetID: "a1"},
	}
}

// ---------------------------------------------------------------------------
// Chain construction
// ---------------------------------------------------------------------------

// TestChain_WriterLinksEachRowToItsPredecessor is the mutation target for
// "break the chain link": if flush stops threading prevHash forward, the
// prev_hash assertion below fails.
func TestChain_WriterLinksEachRowToItsPredecessor(t *testing.T) {
	rows := flushEvents(t, "acme", nil, threeEvents("acme"))
	require.Len(t, rows, 3)

	assert.Equal(t, chainGenesis(), rows[0].PrevHash,
		"first row in a tenant chain must anchor at the genesis hash")

	for i, r := range rows {
		assert.Equal(t, int64(i+1), r.Seq, "chain positions must be 1-based and gapless")
		assert.Len(t, r.EntryHash, chainHashLen)
		assert.Equal(t, computeEntryHash(r), r.EntryHash,
			"row %d does not reproduce its own entry_hash", i)
		if i > 0 {
			assert.Equal(t, rows[i-1].EntryHash, r.PrevHash,
				"row %d prev_hash must be row %d entry_hash", i, i-1)
		}
	}
}

// TestChain_ContinuesFromExistingHead proves a flush appends to whatever the
// tenant's chain already holds rather than restarting at genesis.
func TestChain_ContinuesFromExistingHead(t *testing.T) {
	head := chainRow{Seq: 41, EntryHash: []byte("0123456789abcdef0123456789abcdef")}
	require.Len(t, head.EntryHash, chainHashLen)

	rows := flushEvents(t, "acme", &head, threeEvents("acme")[:2])
	require.Len(t, rows, 2)

	assert.Equal(t, int64(42), rows[0].Seq)
	assert.Equal(t, head.EntryHash, rows[0].PrevHash)
	assert.Equal(t, int64(43), rows[1].Seq)
}

// TestChain_RefusesToExtendCorruptHead: a truncated stored hash means the
// chain is already broken. Appending to it would paper over the break, so
// the flush fails instead.
func TestChain_RefusesToExtendCorruptHead(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	mock.ExpectBegin()
	mock.ExpectExec("pg_advisory_xact_lock").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("ORDER  BY chain_seq DESC").
		WillReturnRows(sqlmock.NewRows([]string{"chain_seq", "entry_hash"}).
			AddRow(int64(7), []byte("too-short")))
	mock.ExpectRollback()

	w := NewWriter(db, silentLogger())
	err = w.flush(context.Background(), threeEvents("acme")[:1])
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refusing to extend a corrupt chain")
}

// TestChain_CanonicalEncodingIsInjective guards the length-prefixing. With a
// separator-joined encoding, an actor who controls `action` could shift a
// field boundary and make two different rows hash identically.
func TestChain_CanonicalEncodingIsInjective(t *testing.T) {
	base := chainRow{
		Seq: 1, TenantID: "acme", ActorID: "u1", ActorType: "user",
		Action: "a", TargetType: "b", TargetID: "c", Decision: "allow",
		Metadata: []byte("{}"), CreatedAt: time.Unix(1, 0).UTC(), PrevHash: chainGenesis(),
	}
	shifted := base
	shifted.Action = "ab"
	shifted.TargetType = ""

	assert.NotEqual(t, computeEntryHash(base), computeEntryHash(shifted),
		"two rows differing only in where a field boundary falls must not share a hash")
}

// TestChain_EveryHashedFieldChangesTheHash makes sure no field silently
// falls outside the chain's coverage — a field the hash ignores is a field
// an attacker can edit for free.
func TestChain_EveryHashedFieldChangesTheHash(t *testing.T) {
	base := chainRow{
		Seq: 3, TenantID: "acme", ActorID: "u1", ActorType: "user",
		Action: "grant_created", TargetType: "component", TargetID: "c1",
		Decision: "allow", Metadata: []byte(`{"k":1}`),
		CreatedAt: time.Unix(1700000000, 0).UTC(), PrevHash: chainGenesis(),
	}
	baseHash := computeEntryHash(base)

	mutations := map[string]func(*chainRow){
		"seq":         func(r *chainRow) { r.Seq = 4 },
		"tenant_id":   func(r *chainRow) { r.TenantID = "evil" },
		"actor_id":    func(r *chainRow) { r.ActorID = "u2" },
		"actor_type":  func(r *chainRow) { r.ActorType = "system" },
		"action":      func(r *chainRow) { r.Action = "grant_revoked" },
		"target_type": func(r *chainRow) { r.TargetType = "agent" },
		"target_id":   func(r *chainRow) { r.TargetID = "c2" },
		"decision":    func(r *chainRow) { r.Decision = "deny" },
		"metadata":    func(r *chainRow) { r.Metadata = []byte(`{"k":2}`) },
		"created_at":  func(r *chainRow) { r.CreatedAt = r.CreatedAt.Add(time.Microsecond) },
		"prev_hash":   func(r *chainRow) { r.PrevHash = computeEntryHash(base) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			m := base
			mutate(&m)
			assert.NotEqual(t, baseHash, computeEntryHash(m),
				"%s is not covered by the chain hash", name)
		})
	}
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

// TestChain_RoundTrip_WriterOutputVerifies is the anti-vacuous-guard test:
// the verifier must accept exactly what the writer produced.
func TestChain_RoundTrip_WriterOutputVerifies(t *testing.T) {
	rows := flushEvents(t, "acme", nil, threeEvents("acme"))

	report := verify(t, "acme", 0, rows)
	assert.True(t, report.Intact(), "writer output failed its own verifier: %+v", report)
	assert.Equal(t, 3, report.Chained)
	assert.Zero(t, report.Unchained)
}

// TestChain_AlteredRecordIsDetected: edit a stored field after the fact —
// exactly what a hash chain exists to catch.
func TestChain_AlteredRecordIsDetected(t *testing.T) {
	rows := flushEvents(t, "acme", nil, threeEvents("acme"))

	// Rewrite a deny into an allow, leaving every hash untouched.
	rows[1].Decision = "allow"

	report := verify(t, "acme", 0, rows)
	require.False(t, report.Intact(), "an edited audit record verified clean")
	assert.Equal(t, ChainBreakAltered, report.Break)
	assert.Equal(t, int64(2), report.BreakSeq)
}

// TestChain_DeletedRecordIsDetected: remove a row from the middle.
func TestChain_DeletedRecordIsDetected(t *testing.T) {
	rows := flushEvents(t, "acme", nil, threeEvents("acme"))
	surviving := []chainRow{rows[0], rows[2]}

	report := verify(t, "acme", 0, surviving)
	require.False(t, report.Intact(), "a deleted audit record verified clean")
	assert.Equal(t, ChainBreakMissing, report.Break)
	assert.Equal(t, int64(2), report.BreakSeq, "the gap starts at the deleted position")
}

// TestChain_ResequencedDeletionIsDetected: the more careful attacker deletes
// a row and renumbers the survivors so chain_seq stays gapless. The
// backward prev_hash link still does not close.
func TestChain_ResequencedDeletionIsDetected(t *testing.T) {
	rows := flushEvents(t, "acme", nil, threeEvents("acme"))
	surviving := []chainRow{rows[0], rows[2]}
	surviving[1].Seq = 2

	report := verify(t, "acme", 0, surviving)
	require.False(t, report.Intact(), "a resequenced deletion verified clean")
	assert.Equal(t, ChainBreakUnlinked, report.Break)
	assert.Equal(t, int64(2), report.BreakSeq)
}

// TestChain_SplicedRecordIsDetected: an inserted row cannot produce a
// prev_hash that matches its new predecessor without recomputing the tail.
func TestChain_SplicedRecordIsDetected(t *testing.T) {
	rows := flushEvents(t, "acme", nil, threeEvents("acme"))

	forged := rows[2]
	forged.Seq = 2
	forged.Action = "grant_created"
	forged.EntryHash = computeEntryHash(forged)

	spliced := []chainRow{rows[0], forged}

	report := verify(t, "acme", 0, spliced)
	require.False(t, report.Intact(), "a spliced audit record verified clean")
	assert.Equal(t, ChainBreakUnlinked, report.Break)
}

// TestChain_UnchainedRowsAreReportedNotAssumedGood: pre-migration rows are
// outside the chain. Reporting them as verified would be a lie.
func TestChain_UnchainedRowsAreReportedNotAssumedGood(t *testing.T) {
	rows := flushEvents(t, "acme", nil, threeEvents("acme")[:1])

	report := verify(t, "acme", 7, rows)
	assert.True(t, report.Intact())
	assert.Equal(t, 7, report.Unchained, "unchained rows must be surfaced, not swallowed")
}

// TestChain_EmptyChainVerifies keeps the zero case honest.
func TestChain_EmptyChainVerifies(t *testing.T) {
	report := verify(t, "acme", 0, nil)
	assert.True(t, report.Intact())
	assert.Zero(t, report.Chained)
}

// TestVerifyChain_RejectsEmptyTenant mirrors Query.List's tenant guard.
func TestVerifyChain_RejectsEmptyTenant(t *testing.T) {
	db, _, err := sqlmock.New()
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	_, err = NewQuery(db).VerifyChain(context.Background(), "")
	require.Error(t, err)
}

// TestChain_AdvisoryKeyIsStableAndTenantSpecific: the lock key must be the
// same on every replica for the same tenant, and different across tenants —
// otherwise the serialisation the chain depends on is not serialisation.
func TestChain_AdvisoryKeyIsStableAndTenantSpecific(t *testing.T) {
	first := tenantAdvisoryKey("acme")
	second := tenantAdvisoryKey("acme")
	assert.Equal(t, first, second)
	assert.NotEqual(t, first, tenantAdvisoryKey("acme2"))
}

// TestChain_MultiTenantBatchChainsEachTenantSeparately: one flush can carry
// several tenants; each must extend its own chain under its own lock.
func TestChain_MultiTenantBatchChainsEachTenantSeparately(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	var seen []driver.Value

	mock.ExpectBegin()
	// Tenants are locked in sorted order: "acme" before "beta".
	for _, tenant := range []string{"acme", "beta"} {
		mock.ExpectExec("pg_advisory_xact_lock").
			WithArgs(tenantAdvisoryKey(tenant)).
			WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectQuery("ORDER  BY chain_seq DESC").
			WithArgs(tenant).
			WillReturnRows(sqlmock.NewRows([]string{"chain_seq", "entry_hash"}))
	}
	mock.ExpectExec("INSERT INTO audit_log").
		WithArgs(captureArgs(12*3, &seen)...).
		WillReturnResult(sqlmock.NewResult(0, 3))
	mock.ExpectCommit()

	w := NewWriter(db, silentLogger())
	require.NoError(t, w.flush(context.Background(), []Event{
		{TenantID: "beta", ActorID: "u1", Action: "a1"},
		{TenantID: "acme", ActorID: "u2", Action: "a2"},
		{TenantID: "beta", ActorID: "u3", Action: "a3"},
	}))
	require.NoError(t, mock.ExpectationsWereMet())

	rows := capturedRows(t, seen)
	require.Len(t, rows, 3)

	byTenant := map[string][]chainRow{}
	for _, r := range rows {
		byTenant[r.TenantID] = append(byTenant[r.TenantID], r)
	}
	require.Len(t, byTenant["acme"], 1)
	require.Len(t, byTenant["beta"], 2)

	assert.Equal(t, int64(1), byTenant["acme"][0].Seq)
	assert.Equal(t, int64(1), byTenant["beta"][0].Seq)
	assert.Equal(t, int64(2), byTenant["beta"][1].Seq,
		"a tenant's positions must not be consumed by another tenant's events")
	assert.Equal(t, byTenant["beta"][0].EntryHash, byTenant["beta"][1].PrevHash)
}

// TestChain_FlushRollsBackOnInsertFailure: a partially applied batch would
// leave a hole in the chain that looks like tampering.
func TestChain_FlushRollsBackOnInsertFailure(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	mock.ExpectBegin()
	mock.ExpectExec("pg_advisory_xact_lock").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("ORDER  BY chain_seq DESC").
		WillReturnRows(sqlmock.NewRows([]string{"chain_seq", "entry_hash"}))
	mock.ExpectExec("INSERT INTO audit_log").WillReturnError(assert.AnError)
	mock.ExpectRollback()

	w := NewWriter(db, silentLogger())
	require.Error(t, w.flush(context.Background(), threeEvents("acme")))
	require.NoError(t, mock.ExpectationsWereMet())
}
