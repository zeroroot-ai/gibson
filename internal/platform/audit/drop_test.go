// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Tests for the audit drop path: a lost audit record must be impossible to
// miss. Hermetic — no Postgres, no Redis.
package audit

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// capturingLogger returns a logger writing into buf, at ERROR and above.
func capturingLogger(buf *bytes.Buffer) (*slog.Logger, *sync.Mutex) {
	var mu sync.Mutex
	return slog.New(slog.NewTextHandler(
		&lockedWriter{mu: &mu, buf: buf},
		&slog.HandlerOptions{Level: slog.LevelError},
	)), &mu
}

type lockedWriter struct {
	mu  *sync.Mutex
	buf *bytes.Buffer
}

func (w *lockedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n, err := w.buf.Write(p)
	if err != nil {
		return n, fmt.Errorf("lockedWriter: write: %w", err)
	}
	return n, nil
}

// fullWriter returns a Writer whose buffer is already at capacity, so the
// next Log must take the backpressure-then-drop path.
func fullWriter(t *testing.T, logger *slog.Logger) *Writer {
	t.Helper()
	db, _, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	w := NewWriter(db, logger)
	for range writerBufferSize {
		w.buffer <- Event{TenantID: "acme", Action: "filler"}
	}
	return w
}

// TestLog_DropIsCountedAndLoggedAtError is the mutation target for
// "restore the silent drop": counter, ERROR log and identity must all be
// present.
func TestLog_DropIsCountedAndLoggedAtError(t *testing.T) {
	var buf bytes.Buffer
	logger, mu := capturingLogger(&buf)
	w := fullWriter(t, logger)

	w.Log(Event{
		TenantID: "acme", ActorID: "attacker", Action: "grant_created",
		TargetType: "component", TargetID: "c1", Decision: "allow",
	})

	assert.Equal(t, int64(1), w.Dropped(), "a lost audit record must be counted")

	mu.Lock()
	out := buf.String()
	mu.Unlock()

	require.NotEmpty(t, out, "a dropped audit record must not be silent")
	assert.Contains(t, out, "level=ERROR", "a lost audit record is not a warning")
	assert.Contains(t, out, "EVENT LOST")
	// Identity must survive into the log, or the loss is unreconstructable.
	for _, want := range []string{"acme", "attacker", "grant_created", "c1"} {
		assert.Contains(t, out, want, "dropped event identity missing %q", want)
	}
}

// TestLog_DropNotifiesObserver proves the escalation hook actually fires —
// the log line alone is not the whole contract.
func TestLog_DropNotifiesObserver(t *testing.T) {
	var got []Event
	w := fullWriter(t, silentLogger()).WithDropObserver(func(ev Event) {
		got = append(got, ev)
	})

	w.Log(Event{TenantID: "acme", ActorID: "u1", Action: "grant_created"})

	require.Len(t, got, 1, "DropObserver was not called for a dropped event")
	assert.Equal(t, "grant_created", got[0].Action)
}

// TestLog_AppliesBackpressureBeforeDropping: the old code dropped the
// instant the buffer was full. Now a burst that clears within the deadline
// is absorbed instead of lost.
func TestLog_AppliesBackpressureBeforeDropping(t *testing.T) {
	w := fullWriter(t, silentLogger())

	// Free one slot shortly after Log starts waiting.
	go func() {
		time.Sleep(20 * time.Millisecond)
		<-w.buffer
	}()

	start := time.Now()
	w.Log(Event{TenantID: "acme", Action: "late.arrival"})
	elapsed := time.Since(start)

	assert.Zero(t, w.Dropped(), "event was dropped despite space freeing up in time")
	assert.GreaterOrEqual(t, elapsed, 15*time.Millisecond, "Log did not wait for space")
	assert.Less(t, elapsed, enqueueTimeout, "Log waited past the deadline")
}

// TestLog_BlocksNoLongerThanTheDeadline: bounded backpressure must stay
// bounded, or an audit-backend outage becomes a request-path outage.
func TestLog_BlocksNoLongerThanTheDeadline(t *testing.T) {
	w := fullWriter(t, silentLogger())

	start := time.Now()
	w.Log(Event{TenantID: "acme", Action: "overflow"})
	elapsed := time.Since(start)

	assert.Equal(t, int64(1), w.Dropped())
	assert.GreaterOrEqual(t, elapsed, enqueueTimeout)
	assert.Less(t, elapsed, 5*time.Second, "Log blocked far past the deadline")
}

// TestFlush_FailureIsCountedAsLoss: a failed flush discards the whole batch.
// That is data loss and must register as such, not as one stray log line.
func TestFlush_FailureIsCountedAsLoss(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	mock.ExpectBegin().WillReturnError(assert.AnError)

	var buf bytes.Buffer
	logger, mu := capturingLogger(&buf)

	var observed int
	w := NewWriter(db, logger).WithDropObserver(func(Event) { observed++ })
	w.Start(context.Background())

	for _, ev := range threeEvents("acme") {
		w.Log(ev)
	}

	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	w.Stop(stopCtx)

	assert.Equal(t, int64(3), w.Dropped(), "a failed flush lost 3 records but counted %d", w.Dropped())
	assert.Equal(t, 3, observed, "DropObserver must see every lost record")

	mu.Lock()
	out := buf.String()
	mu.Unlock()
	assert.Contains(t, out, "BATCH LOST")
	assert.Contains(t, out, "level=ERROR")
	assert.Equal(t, 1, strings.Count(out, "BATCH LOST"),
		"a lost batch should log once, not once per event")
}

// TestLog_AfterStopDoesNotPanic: Stop used to close the event buffer, so a
// Log racing shutdown panicked on send-to-closed-channel — at exactly the
// moment callers emit shutdown audit events.
func TestLog_AfterStopDoesNotPanic(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer func() { _ = db.Close() }()
	mock.ExpectBegin().WillReturnError(assert.AnError)

	w := NewWriter(db, silentLogger())
	w.Start(context.Background())

	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	w.Stop(stopCtx)

	require.NotPanics(t, func() {
		w.Log(Event{TenantID: "acme", Action: "post.stop"})
	})
	assert.Equal(t, int64(1), w.Dropped(), "a post-Stop event is still a lost record")
}

// TestStop_IsIdempotent — a double Stop must not panic on a double close.
func TestStop_IsIdempotent(t *testing.T) {
	db, _, err := sqlmock.New()
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	w := NewWriter(db, silentLogger())
	w.Start(context.Background())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	require.NotPanics(t, func() {
		w.Stop(ctx)
		w.Stop(ctx)
	})
}
