// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Tests for `audit.WriteSync` (R3.5). Hermetic — uses go-sqlmock as the
// backend so no real Postgres / testcontainers required.
package audit

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// silentLogger returns an slog.Logger that discards output. Local helper —
// the writer_test.go variant is gated on the `integration` build tag so we
// cannot share it.
func silentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// expectChainPreamble sets up the statements every flush issues before the
// INSERT: open a transaction, take the tenant's chain advisory lock, and read
// the current chain head (empty here, so the chain starts at genesis).
func expectChainPreamble(mock sqlmock.Sqlmock) {
	mock.ExpectBegin()
	mock.ExpectExec("pg_advisory_xact_lock").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("ORDER  BY chain_seq DESC").
		WillReturnRows(sqlmock.NewRows([]string{"chain_seq", "entry_hash"}))
}

// testEvent returns a minimal valid Event. Mirrors the helper of the same
// name in writer_test.go (which is integration-tagged).
func testEvent(tenant, action string) Event {
	return Event{
		TenantID:   tenant,
		ActorID:    "test-actor",
		ActorType:  "user",
		Action:     action,
		TargetType: "test",
		TargetID:   "t-1",
		Decision:   "allow",
		Metadata:   json.RawMessage(`{}`),
	}
}

// TestWriteSync_Blocks_UntilBackendAcks proves WriteSync does not return
// until the underlying ExecContext has acknowledged the write. The mock
// holds the ack for `ackDelay`; we assert WriteSync's return time exceeds
// that floor.
func TestWriteSync_Blocks_UntilBackendAcks(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	const ackDelay = 100 * time.Millisecond

	expectChainPreamble(mock)
	mock.ExpectExec("INSERT INTO audit_log").
		WillDelayFor(ackDelay).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	w := NewWriter(db, silentLogger())
	// Do NOT call Start(); WriteSync does not depend on the background goroutine.

	ev := testEvent("acme", "policy_decision")

	start := time.Now()
	err = w.WriteSync(context.Background(), ev)
	elapsed := time.Since(start)

	require.NoError(t, err)
	assert.GreaterOrEqual(t, elapsed, ackDelay,
		"WriteSync returned before backend ack delay (%v < %v)", elapsed, ackDelay)
	require.NoError(t, mock.ExpectationsWereMet())
}

// TestWriteSync_SurfacesBackendError verifies WriteSync returns the
// backend's error to the caller (does NOT silently swallow it).
func TestWriteSync_SurfacesBackendError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	backendErr := errors.New("simulated postgres failure")
	expectChainPreamble(mock)
	mock.ExpectExec("INSERT INTO audit_log").WillReturnError(backendErr)
	mock.ExpectRollback()

	w := NewWriter(db, silentLogger())

	err = w.WriteSync(context.Background(), testEvent("acme", "policy_decision"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), backendErr.Error(),
		"WriteSync did not surface the backend error verbatim")
	require.NoError(t, mock.ExpectationsWereMet())
}

// TestWriteSync_ContextCancellation verifies WriteSync respects context
// cancellation and returns the cancellation error.
func TestWriteSync_ContextCancellation(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.MonitorPingsOption(false))
	require.NoError(t, err)
	defer db.Close()

	// The mock will hold the exec long enough for ctx.Cancel() to fire.
	expectChainPreamble(mock)
	mock.ExpectExec("INSERT INTO audit_log").
		WillDelayFor(200 * time.Millisecond).
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := NewWriter(db, silentLogger())

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	err = w.WriteSync(ctx, testEvent("acme", "policy_decision"))
	require.Error(t, err, "WriteSync must surface ctx cancellation as an error")
}

// TestWriteSync_NilWriter_ReturnsError makes sure a nil-receiver call does
// not panic and is surfaced as a clean error.
func TestWriteSync_NilWriter_ReturnsError(t *testing.T) {
	var w *Writer
	err := w.WriteSync(context.Background(), testEvent("acme", "x"))
	require.Error(t, err)
}
