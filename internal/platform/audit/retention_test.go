// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Tests for audit retention. Hermetic: go-sqlmock stands in for Postgres.
// retention_integration_test.go runs the same rules against a real Postgres.
package audit

import (
	"context"
	"database/sql/driver"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateRetentionMonths(t *testing.T) {
	require.NoError(t, ValidateRetentionMonths(13))
	require.NoError(t, ValidateRetentionMonths(84))
	for _, months := range []int{12, 1, 0, -5} {
		require.ErrorIs(t, ValidateRetentionMonths(months), ErrRetentionTooShort, "%d months", months)
	}
}

func TestRetentionMonthsFromEnv(t *testing.T) {
	t.Run("empty gives the default of 13 months", func(t *testing.T) {
		t.Setenv(RetentionMonthsEnv, "")
		months, err := RetentionMonthsFromEnv()
		require.NoError(t, err)
		assert.Equal(t, 13, months)
	})
	t.Run("a longer period is accepted", func(t *testing.T) {
		t.Setenv(RetentionMonthsEnv, " 36 ")
		months, err := RetentionMonthsFromEnv()
		require.NoError(t, err)
		assert.Equal(t, 36, months)
	})
	t.Run("a shorter period is refused", func(t *testing.T) {
		t.Setenv(RetentionMonthsEnv, "6")
		_, err := RetentionMonthsFromEnv()
		require.ErrorIs(t, err, ErrRetentionTooShort)
	})
	t.Run("a value that is not a number is refused", func(t *testing.T) {
		t.Setenv(RetentionMonthsEnv, "one year")
		_, err := RetentionMonthsFromEnv()
		require.Error(t, err)
	})
}

func TestNewRetention_RefusesBadInput(t *testing.T) {
	db, _, err := sqlmock.New()
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	_, err = NewRetention(nil, 13, silentLogger())
	require.Error(t, err)
	_, err = NewRetention(db, 13, nil)
	require.Error(t, err)
	_, err = NewRetention(db, 12, silentLogger())
	require.ErrorIs(t, err, ErrRetentionTooShort)
}

// newTestRetention returns a Retention on sqlmock with a fixed clock.
func newTestRetention(t *testing.T, defaultMonths int, now time.Time) (*Retention, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	r, err := NewRetention(db, defaultMonths, silentLogger())
	require.NoError(t, err)
	r.now = func() time.Time { return now }
	return r, mock
}

// TestRetention_PruneTenant_MovesTheAnchorAndRemovesOnlyOlderRows pins the
// statements of one run: the cutoff is 13 months before now, the anchor
// names the row after the last removed row, and the delete stops at the
// last removed row.
func TestRetention_PruneTenant_MovesTheAnchorAndRemovesOnlyOlderRows(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	cutoff := time.Date(2025, 9, 5, 12, 0, 0, 0, time.UTC)
	r, mock := newTestRetention(t, 13, now)
	lastHash := make([]byte, chainHashLen)
	lastHash[0] = 0xAB

	mock.ExpectBegin()
	mock.ExpectExec("pg_advisory_xact_lock").
		WithArgs(tenantAdvisoryKey("acme")).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("ORDER  BY chain_seq DESC").
		WithArgs("acme", cutoff).
		WillReturnRows(sqlmock.NewRows([]string{"chain_seq", "entry_hash"}).AddRow(int64(40), lastHash))
	mock.ExpectExec("INSERT INTO audit_chain_anchor").
		WithArgs("acme", int64(41), lastHash, now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("DELETE FROM audit_log WHERE tenant_id = \\$1 AND chain_seq IS NOT NULL AND chain_seq <= \\$2").
		WithArgs("acme", int64(40)).
		WillReturnResult(sqlmock.NewResult(0, 40))
	mock.ExpectCommit()

	removed, err := r.PruneTenant(context.Background(), "acme")
	require.NoError(t, err)
	assert.Equal(t, int64(40), removed)
	require.NoError(t, mock.ExpectationsWereMet())
}

// TestRetention_PruneTenant_NothingOld: with no row before the period, the
// run writes no anchor and removes no chained row.
func TestRetention_PruneTenant_NothingOld(t *testing.T) {
	r, mock := newTestRetention(t, 13, time.Now())

	mock.ExpectBegin()
	mock.ExpectExec("pg_advisory_xact_lock").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("ORDER  BY chain_seq DESC").
		WillReturnRows(sqlmock.NewRows([]string{"chain_seq", "entry_hash"}))
	mock.ExpectCommit()

	removed, err := r.PruneTenant(context.Background(), "acme")
	require.NoError(t, err)
	assert.Zero(t, removed)
	require.NoError(t, mock.ExpectationsWereMet())
}

// TestRetention_PruneTenant_UsesTheLongerPeriodOfTheInstall: an install with
// 24 months keeps rows that the default would remove.
func TestRetention_PruneTenant_UsesTheLongerPeriodOfTheInstall(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	cutoff := time.Date(2024, 10, 5, 12, 0, 0, 0, time.UTC)
	r, mock := newTestRetention(t, 24, now)

	mock.ExpectBegin()
	mock.ExpectExec("pg_advisory_xact_lock").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("ORDER  BY chain_seq DESC").
		WithArgs("acme", cutoff).
		WillReturnRows(sqlmock.NewRows([]string{"chain_seq", "entry_hash"}))
	mock.ExpectCommit()

	_, err := r.PruneTenant(context.Background(), "acme")
	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
}

// TestRetention_PruneTenant_RollsBackOnEachFailure: a run that fails part
// way changes nothing. A removed row with no anchor would look like
// tampering.
func TestRetention_PruneTenant_RollsBackOnEachFailure(t *testing.T) {
	goodHash := make([]byte, chainHashLen)
	lock := func(m sqlmock.Sqlmock) {
		m.ExpectExec("pg_advisory_xact_lock").WillReturnResult(sqlmock.NewResult(0, 0))
	}
	lastOld := func(m sqlmock.Sqlmock) {
		m.ExpectQuery("ORDER  BY chain_seq DESC").
			WillReturnRows(sqlmock.NewRows([]string{"chain_seq", "entry_hash"}).AddRow(int64(3), goodHash))
	}
	anchor := func(m sqlmock.Sqlmock) {
		m.ExpectExec("INSERT INTO audit_chain_anchor").WillReturnResult(sqlmock.NewResult(0, 1))
	}

	cases := map[string]func(m sqlmock.Sqlmock){
		"lock": func(m sqlmock.Sqlmock) {
			m.ExpectExec("pg_advisory_xact_lock").WillReturnError(assert.AnError)
		},
		"find rows": func(m sqlmock.Sqlmock) {
			lock(m)
			m.ExpectQuery("ORDER  BY chain_seq DESC").WillReturnError(assert.AnError)
		},
		"corrupt hash": func(m sqlmock.Sqlmock) {
			lock(m)
			m.ExpectQuery("ORDER  BY chain_seq DESC").
				WillReturnRows(sqlmock.NewRows([]string{"chain_seq", "entry_hash"}).AddRow(int64(3), []byte("short")))
		},
		"anchor": func(m sqlmock.Sqlmock) {
			lock(m)
			lastOld(m)
			m.ExpectExec("INSERT INTO audit_chain_anchor").WillReturnError(assert.AnError)
		},
		"delete chained": func(m sqlmock.Sqlmock) {
			lock(m)
			lastOld(m)
			anchor(m)
			m.ExpectExec("chain_seq IS NOT NULL AND chain_seq <=").WillReturnError(assert.AnError)
		},
	}
	for name, expect := range cases {
		t.Run(name, func(t *testing.T) {
			r, mock := newTestRetention(t, 13, time.Now())
			mock.ExpectBegin()
			expect(mock)
			mock.ExpectRollback()

			_, err := r.PruneTenant(context.Background(), "acme")
			require.Error(t, err)
			require.NoError(t, mock.ExpectationsWereMet())
		})
	}

	t.Run("begin", func(t *testing.T) {
		r, mock := newTestRetention(t, 13, time.Now())
		mock.ExpectBegin().WillReturnError(assert.AnError)
		_, err := r.PruneTenant(context.Background(), "acme")
		require.Error(t, err)
	})
	t.Run("empty tenant", func(t *testing.T) {
		r, _ := newTestRetention(t, 13, time.Now())
		_, err := r.PruneTenant(context.Background(), "")
		require.Error(t, err)
	})
}

// expectPruneNothing sets the statements of a run that finds no old row.
func expectPruneNothing(mock sqlmock.Sqlmock) {
	mock.ExpectBegin()
	mock.ExpectExec("pg_advisory_xact_lock").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("ORDER  BY chain_seq DESC").
		WillReturnRows(sqlmock.NewRows([]string{"chain_seq", "entry_hash"}))
	mock.ExpectCommit()
}

// TestRetention_Prune_GoesOnAfterOneTenantFails: one tenant that fails does
// not stop retention for the other tenants. The failure is counted.
func TestRetention_Prune_GoesOnAfterOneTenantFails(t *testing.T) {
	r, mock := newTestRetention(t, 13, time.Now())

	mock.ExpectQuery("SELECT DISTINCT tenant_id FROM audit_log").
		WillReturnRows(sqlmock.NewRows([]string{"tenant_id"}).AddRow("acme").AddRow("beta"))
	mock.ExpectBegin().WillReturnError(assert.AnError) // acme fails
	// beta runs and removes two rows.
	mock.ExpectBegin()
	mock.ExpectExec("pg_advisory_xact_lock").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("ORDER  BY chain_seq DESC").
		WillReturnRows(sqlmock.NewRows([]string{"chain_seq", "entry_hash"}).AddRow(int64(2), make([]byte, chainHashLen)))
	mock.ExpectExec("INSERT INTO audit_chain_anchor").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("chain_seq IS NOT NULL AND chain_seq <=").WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectCommit()

	before := testutil.ToFloat64(auditRetentionErrorsTotal)
	removed, err := r.Prune(context.Background())
	require.Error(t, err)
	assert.Equal(t, int64(2), removed, "the rows of the tenant that passed are counted")
	assert.InDelta(t, 1, testutil.ToFloat64(auditRetentionErrorsTotal)-before, 0.001)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestRetention_Prune_ListFailure(t *testing.T) {
	r, mock := newTestRetention(t, 13, time.Now())
	mock.ExpectQuery("SELECT DISTINCT tenant_id FROM audit_log").WillReturnError(assert.AnError)
	_, err := r.Prune(context.Background())
	require.Error(t, err)
}

func TestRetention_Prune_ScanFailure(t *testing.T) {
	r, mock := newTestRetention(t, 13, time.Now())
	mock.ExpectQuery("SELECT DISTINCT tenant_id FROM audit_log").
		WillReturnRows(sqlmock.NewRows([]string{"tenant_id"}).AddRow(nil))
	before := testutil.ToFloat64(auditRetentionErrorsTotal)
	_, err := r.Prune(context.Background())
	require.ErrorContains(t, err, "scan tenant")
	assert.InDelta(t, 1, testutil.ToFloat64(auditRetentionErrorsTotal)-before, 0.001)
}

func TestRetention_Prune_RowErrorFailsTheList(t *testing.T) {
	r, mock := newTestRetention(t, 13, time.Now())
	mock.ExpectQuery("SELECT DISTINCT tenant_id FROM audit_log").
		WillReturnRows(sqlmock.NewRows([]string{"tenant_id"}).AddRow("acme").RowError(0, assert.AnError))
	_, err := r.Prune(context.Background())
	require.ErrorIs(t, err, assert.AnError)
}

// TestRetention_Run_PrunesAtStartAndStopsWithTheContext: Run makes one run
// at once, and it returns when its context ends.
func TestRetention_Run_PrunesAtStartAndStopsWithTheContext(t *testing.T) {
	r, mock := newTestRetention(t, 13, time.Now())
	mock.ExpectQuery("SELECT DISTINCT tenant_id FROM audit_log").
		WillReturnRows(sqlmock.NewRows([]string{"tenant_id"}).AddRow("acme"))
	expectPruneNothing(mock)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		r.Run(ctx, 0)
		close(done)
	}()

	require.Eventually(t, func() bool { return mock.ExpectationsWereMet() == nil },
		5*time.Second, 10*time.Millisecond, "Run must prune one time at start")
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop with its context")
	}
}

// TestRetention_Run_GoesOnAfterAFailedRun: a run that fails is logged, and
// the next tick tries again.
func TestRetention_Run_GoesOnAfterAFailedRun(t *testing.T) {
	r, mock := newTestRetention(t, 13, time.Now())
	mock.ExpectQuery("SELECT DISTINCT tenant_id FROM audit_log").WillReturnError(assert.AnError)
	mock.ExpectQuery("SELECT DISTINCT tenant_id FROM audit_log").
		WillReturnRows(sqlmock.NewRows([]string{"tenant_id"}))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.Run(ctx, 10*time.Millisecond)

	require.Eventually(t, func() bool { return mock.ExpectationsWereMet() == nil },
		5*time.Second, 10*time.Millisecond, "Run must try again after a failed run")
}

// ---------------------------------------------------------------------------
// The chain after retention
// ---------------------------------------------------------------------------

// TestChain_VerifiesFromTheRetentionAnchor: retention removed the first two
// rows. With the anchor on the third row, the rest of the chain verifies.
func TestChain_VerifiesFromTheRetentionAnchor(t *testing.T) {
	rows := flushEvents(t, "acme", nil, threeEvents("acme"))
	anchor := &chainRow{Seq: rows[2].Seq, PrevHash: rows[2].PrevHash}

	report := verifyFrom(t, "acme", 0, anchor, rows[2:])
	assert.True(t, report.Intact(), "the chain must verify after retention: %+v", report)
	assert.Equal(t, int64(3), report.FirstSeq)
	assert.Equal(t, 1, report.Chained)
}

// TestChain_RemovalWithNoAnchorIsStillDetected: the same rows are gone, and
// nothing recorded it. That is a deletion, and the verifier reports it.
func TestChain_RemovalWithNoAnchorIsStillDetected(t *testing.T) {
	rows := flushEvents(t, "acme", nil, threeEvents("acme"))

	report := verify(t, "acme", 0, rows[2:])
	require.False(t, report.Intact(), "rows that are gone with no anchor must not verify")
	assert.Equal(t, ChainBreakMissing, report.Break)
}

// TestChain_RemovalPastTheAnchorIsDetected: the anchor permits the removal of
// row 1 only. Row 2 is also gone, and the verifier reports it.
func TestChain_RemovalPastTheAnchorIsDetected(t *testing.T) {
	rows := flushEvents(t, "acme", nil, threeEvents("acme"))
	anchor := &chainRow{Seq: rows[1].Seq, PrevHash: rows[1].PrevHash}

	report := verifyFrom(t, "acme", 0, anchor, rows[2:])
	require.False(t, report.Intact())
	assert.Equal(t, ChainBreakMissing, report.Break)
	assert.Equal(t, int64(2), report.BreakSeq)
}

// TestChain_WrongAnchorHashIsDetected: an anchor with the correct position
// and a different hash does not link to the oldest row.
func TestChain_WrongAnchorHashIsDetected(t *testing.T) {
	rows := flushEvents(t, "acme", nil, threeEvents("acme"))
	wrong := make([]byte, chainHashLen)
	wrong[5] = 0x01
	anchor := &chainRow{Seq: rows[2].Seq, PrevHash: wrong}

	report := verifyFrom(t, "acme", 0, anchor, rows[2:])
	require.False(t, report.Intact())
	assert.Equal(t, ChainBreakUnlinked, report.Break)
}

// TestChain_WriterContinuesFromTheAnchorWhenEachRowIsGone: retention removed
// each row of a tenant. The next row lands on the anchor position and points
// at the anchor hash. It does not start a second chain at position 1.
func TestChain_WriterContinuesFromTheAnchorWhenEachRowIsGone(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	anchorHash := make([]byte, chainHashLen)
	anchorHash[0] = 0x7F
	var seen []driver.Value

	mock.ExpectBegin()
	mock.ExpectExec("pg_advisory_xact_lock").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("ORDER  BY chain_seq DESC").
		WillReturnRows(sqlmock.NewRows([]string{"chain_seq", "entry_hash"}))
	mock.ExpectQuery("audit_chain_anchor").
		WithArgs("acme").
		WillReturnRows(sqlmock.NewRows([]string{"first_seq", "prev_hash"}).AddRow(int64(41), anchorHash))
	mock.ExpectExec("INSERT INTO audit_log").
		WithArgs(captureArgs(12, &seen)...).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	w := NewWriter(db, silentLogger())
	require.NoError(t, w.flush(context.Background(), threeEvents("acme")[:1]))
	require.NoError(t, mock.ExpectationsWereMet())

	rows := capturedRows(t, seen)
	require.Len(t, rows, 1)
	assert.Equal(t, int64(41), rows[0].Seq)
	assert.Equal(t, anchorHash, rows[0].PrevHash)

	// The verifier accepts that row from the same anchor.
	report := verifyFrom(t, "acme", 0, &chainRow{Seq: 41, PrevHash: anchorHash}, rows)
	assert.True(t, report.Intact(), "%+v", report)
}

// TestChain_CorruptAnchorIsAnError: the writer and the verifier refuse an
// anchor that cannot be correct.
func TestChain_CorruptAnchorIsAnError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	mock.ExpectQuery("audit_chain_anchor").
		WillReturnRows(sqlmock.NewRows([]string{"first_seq", "prev_hash"}).AddRow(int64(5), []byte("short")))
	_, _, err = chainAnchor(context.Background(), db, "acme")
	require.Error(t, err)

	mock.ExpectQuery("audit_chain_anchor").WillReturnError(assert.AnError)
	_, _, err = chainAnchor(context.Background(), db, "acme")
	require.Error(t, err)

	// The verifier returns the error. It does not report an intact chain.
	mock.ExpectQuery("COUNT").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery("audit_chain_anchor").WillReturnError(assert.AnError)
	_, err = NewQuery(db).VerifyChain(context.Background(), "acme")
	require.Error(t, err)
}
