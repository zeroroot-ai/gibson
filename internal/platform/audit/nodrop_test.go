// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Tests for the rule "an audit write never drops". Hermetic: go-sqlmock
// stands in for Postgres.
package audit

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/prometheus/client_golang/prometheus/testutil"
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

// expectOneFlush sets the statements of one successful flush of one tenant
// with an empty chain.
func expectOneFlush(mock sqlmock.Sqlmock) {
	expectChainPreamble(mock)
	mock.ExpectExec("INSERT INTO audit_log").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
}

// fullWriter returns a Writer that is not started and whose queue is full.
func fullWriter(t *testing.T) *Writer {
	t.Helper()
	db, _, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	w := NewWriter(db, silentLogger())
	for range writerBufferSize {
		w.buffer <- Event{TenantID: "acme", Action: "filler"}
	}
	return w
}

// TestLog_FullQueueBlocksAndDropsNothing: with a full queue, Log waits. It
// returns when there is room, and the event is in the queue.
func TestLog_FullQueueBlocksAndDropsNothing(t *testing.T) {
	w := fullWriter(t)

	returned := make(chan struct{})
	go func() {
		w.Log(Event{TenantID: "acme", Action: "late.arrival"})
		close(returned)
	}()

	select {
	case <-returned:
		t.Fatal("Log returned while the queue was full: the event was dropped or the queue grew")
	case <-time.After(150 * time.Millisecond):
	}

	// Make room for one event. Log must now return.
	<-w.buffer
	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("Log did not return after the queue had room")
	}

	require.Len(t, w.buffer, writerBufferSize, "the queue must hold each event")
	var last Event
	for range writerBufferSize {
		last = <-w.buffer
	}
	assert.Equal(t, "late.arrival", last.Action, "the event that waited must be in the queue")
}

// TestWriter_FailedFlushIsRetriedNotDropped: Postgres refuses the first
// write. The writer keeps the batch, counts the error, and writes the same
// batch on the next try.
func TestWriter_FailedFlushIsRetriedNotDropped(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	mock.ExpectBegin().WillReturnError(assert.AnError)
	expectChainPreamble(mock)
	mock.ExpectExec("INSERT INTO audit_log").
		WillReturnResult(sqlmock.NewResult(0, 3))
	mock.ExpectCommit()

	var buf bytes.Buffer
	logger, mu := capturingLogger(&buf)
	w := NewWriter(db, logger)
	w.minBackoff, w.maxBackoff = 5*time.Millisecond, 10*time.Millisecond

	before := testutil.ToFloat64(auditWriteErrorsTotal)
	w.Start(context.Background())
	for _, ev := range threeEvents("acme") {
		w.Log(ev)
	}

	require.Eventually(t, func() bool {
		return mock.ExpectationsWereMet() == nil
	}, 5*time.Second, 10*time.Millisecond, "the writer must write the batch again after a failed flush")

	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	w.Stop(stopCtx)

	assert.InDelta(t, 1, testutil.ToFloat64(auditWriteErrorsTotal)-before, 0.001,
		"gibson_audit_write_errors_total must count the failed write")
	mu.Lock()
	out := buf.String()
	mu.Unlock()
	assert.Contains(t, out, "level=ERROR")
	assert.Contains(t, out, "write to audit_log failed")
	assert.Contains(t, out, "tries again")
}

// TestWriter_QueueBacksUpWhilePostgresIsDown: while each flush fails, the
// writer holds its batch and does not read the queue. No event leaves the
// writer by any path other than a successful write.
func TestWriter_QueueBacksUpWhilePostgresIsDown(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer func() { _ = db.Close() }()
	mock.MatchExpectationsInOrder(false)
	for range 200 {
		mock.ExpectBegin().WillReturnError(assert.AnError)
	}

	w := NewWriter(db, silentLogger())
	w.minBackoff, w.maxBackoff = 20*time.Millisecond, 20*time.Millisecond
	w.Start(context.Background())

	// One full batch starts a flush at once. That flush fails and is retried.
	for i := range batchSize {
		w.Log(Event{TenantID: "acme", Action: fmt.Sprintf("a%d", i)})
	}
	// Events that arrive during the retry stay in the queue.
	for i := range 10 {
		w.Log(Event{TenantID: "acme", Action: fmt.Sprintf("b%d", i)})
	}
	time.Sleep(100 * time.Millisecond)
	assert.Len(t, w.buffer, 10, "events must wait in the queue while Postgres is down")

	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	w.Stop(stopCtx)
}

// TestWriter_StopWritesTheQueue: Stop writes what is in the queue, also when
// the lifecycle context is already cancelled.
func TestWriter_StopWritesTheQueue(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer func() { _ = db.Close() }()
	expectChainPreamble(mock)
	mock.ExpectExec("INSERT INTO audit_log").WillReturnResult(sqlmock.NewResult(0, 3))
	mock.ExpectCommit()

	w := NewWriter(db, silentLogger())
	for _, ev := range threeEvents("acme") {
		w.Log(ev)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	w.Start(ctx)

	stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopCancel()
	w.Stop(stopCtx)

	require.NoError(t, mock.ExpectationsWereMet(),
		"the writer must write the queue with a context of its own after the lifecycle context ends")
}

// TestLog_AfterStopWritesTheEventItself: after Stop no goroutine reads the
// queue. Log then writes the event to Postgres before it returns.
func TestLog_AfterStopWritesTheEventItself(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer func() { _ = db.Close() }()
	expectOneFlush(mock)

	w := NewWriter(db, silentLogger())
	w.Start(context.Background())
	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	w.Stop(stopCtx)

	require.NotPanics(t, func() {
		w.Log(Event{TenantID: "acme", Action: "post.stop"})
	})
	require.NoError(t, mock.ExpectationsWereMet(), "a Log call after Stop must reach Postgres")
	assert.Empty(t, w.buffer, "no event may stay in a queue that nobody reads")
}

// TestLog_AfterStopReportsALostRecord: the one loss that remains. After
// Stop, with Postgres down, the event cannot be kept. The writer counts the
// error and logs the loss at ERROR.
func TestLog_AfterStopReportsALostRecord(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer func() { _ = db.Close() }()
	mock.ExpectBegin().WillReturnError(assert.AnError)

	var buf bytes.Buffer
	logger, mu := capturingLogger(&buf)
	w := NewWriter(db, logger)
	w.Start(context.Background())
	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	w.Stop(stopCtx)

	before := testutil.ToFloat64(auditWriteErrorsTotal)
	w.Log(Event{TenantID: "acme", ActorID: "u1", Action: "post.stop"})

	assert.InDelta(t, 1, testutil.ToFloat64(auditWriteErrorsTotal)-before, 0.001)
	mu.Lock()
	out := buf.String()
	mu.Unlock()
	assert.Contains(t, out, "level=ERROR")
	assert.Contains(t, out, "LOST")
	assert.Contains(t, out, "post.stop")
}

// TestWriteSync_CountsTheWriteError: the alert reads one counter for each
// kind of failed write.
func TestWriteSync_CountsTheWriteError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer func() { _ = db.Close() }()
	mock.ExpectBegin().WillReturnError(assert.AnError)

	w := NewWriter(db, silentLogger())
	before := testutil.ToFloat64(auditWriteErrorsTotal)
	require.Error(t, w.WriteSync(context.Background(), testEvent("acme", "grant_created")))
	assert.InDelta(t, 1, testutil.ToFloat64(auditWriteErrorsTotal)-before, 0.001)
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
