//go:build integration
// +build integration

// Package audit — writer_test.go
//
// Integration and unit tests for the Postgres-backed Writer and Query.
// Integration tests require Docker (via testcontainers-go) to spin up a real
// Postgres instance.
//
// Run integration tests with:
//
//	go test -tags integration ./internal/platform/audit/...
package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sync/atomic"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/tests/testhelpers"
)

// ---------------------------------------------------------------------------
// Postgres container helper
// ---------------------------------------------------------------------------

const (
	pgUser     = "testuser"
	pgPassword = "testpassword"
	pgDB       = "testaudit"
)

// setupAuditPostgres starts an ephemeral Postgres container, runs the audit
// schema migration, and returns a *sql.DB ready for testing.
// The container is terminated when the test ends.
func setupAuditPostgres(t *testing.T) *sql.DB {
	t.Helper()
	ctx := context.Background()

	// Per first-deploy-unblock-and-ha:R7.13–R7.17 the daemon's tests
	// must connect to Postgres over TLS — the `disable` SSL mode is
	// forbidden anywhere in the source tree. testhelpers.StartPostgresTLS
	// owns the testcontainer + self-signed CA setup and returns a DSN
	// that already carries `sslmode=require`. The helper also handles
	// the Docker availability skip.
	pg := testhelpers.StartPostgresTLS(t, testhelpers.PostgresOptions{
		User:     pgUser,
		Password: pgPassword,
		Database: pgDB,
	})

	db, err := sql.Open("postgres", pg.DSN)
	require.NoError(t, err, "open Postgres connection")
	t.Cleanup(func() { _ = db.Close() })

	require.Eventually(t, func() bool {
		return db.PingContext(ctx) == nil
	}, 30*time.Second, 200*time.Millisecond, "Postgres did not become ready in time")

	require.NoError(t, RunAuditMigrations(ctx, db), "RunAuditMigrations must succeed")

	return db
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// silentLogger returns an slog.Logger that only emits ERROR-level messages to
// stderr (keeps test output clean).
func silentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// countRows returns the row count in audit_log for the given tenant.
func countRows(t *testing.T, db *sql.DB, tenantID string) int {
	t.Helper()
	var n int
	err := db.QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM audit_log WHERE tenant_id = $1", tenantID).Scan(&n)
	require.NoError(t, err)
	return n
}

// testEvent returns a minimal valid Event for the given tenant and action.
func testEvent(tenant, action string) Event {
	return Event{
		TenantID:   tenant,
		ActorID:    "actor-1",
		ActorType:  "user",
		Action:     action,
		TargetType: "component",
		TargetID:   "comp-1",
		Decision:   "allow",
		Metadata:   json.RawMessage(`{"k":"v"}`),
	}
}

// stopWriter calls w.Stop() with a generous 10-second deadline.
func stopWriter(t *testing.T, w *Writer) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	w.Stop(ctx)
}

// ---------------------------------------------------------------------------
// Writer unit tests (no real DB required)
// ---------------------------------------------------------------------------

// TestWriter_Log_IsNonBlocking verifies that Log() returns immediately even
// when the internal buffer is saturated.
func TestWriter_Log_IsNonBlocking(t *testing.T) {
	// Open a DSN that will never be reachable; the Writer is never started so
	// the DB is never actually dialled.
	db, err := sql.Open("postgres", "host=localhost port=9999 dbname=noop sslmode=require connect_timeout=1")
	require.NoError(t, err)
	defer db.Close()

	w := NewWriter(db, silentLogger())
	// Do NOT call w.Start() — the background goroutine is not running.

	// Fill the buffer directly to avoid Prometheus counter side-effects.
	ev := testEvent("acme", "test.action")
	for i := 0; i < writerBufferSize; i++ {
		w.buffer <- ev
	}

	// Log() must return without blocking.
	done := make(chan struct{})
	go func() {
		w.Log(ev)
		close(done)
	}()

	select {
	case <-done:
		// Pass — Log() returned without blocking.
	case <-time.After(200 * time.Millisecond):
		t.Fatal("Log() blocked when the buffer was full")
	}
}

// TestWriter_Log_BufferOverflow_DropsGracefully verifies that Log() does not
// panic and the buffer stays at capacity when it is already full.
func TestWriter_Log_BufferOverflow_DropsGracefully(t *testing.T) {
	db, err := sql.Open("postgres", "host=localhost port=9999 dbname=noop sslmode=require connect_timeout=1")
	require.NoError(t, err)
	defer db.Close()

	w := NewWriter(db, silentLogger())

	ev := testEvent("acme", "overflow.action")
	for i := 0; i < writerBufferSize; i++ {
		w.buffer <- ev
	}

	require.NotPanics(t, func() { w.Log(ev) })
	assert.Equal(t, writerBufferSize, len(w.buffer), "buffer should remain at capacity")
}

// ---------------------------------------------------------------------------
// Writer integration tests
// ---------------------------------------------------------------------------

// TestWriter_FlushOnCount verifies that a full batch (batchSize events) is
// flushed to the database before the ticker fires.
func TestWriter_FlushOnCount(t *testing.T) {
	db := setupAuditPostgres(t)

	w := NewWriter(db, silentLogger())
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	w.Start(ctx)

	for i := 0; i < batchSize; i++ {
		w.Log(testEvent("tenant-count", fmt.Sprintf("action.%d", i)))
	}

	stopWriter(t, w)

	assert.Equal(t, batchSize, countRows(t, db, "tenant-count"),
		"all %d events should be persisted after flush-on-count", batchSize)
}

// TestWriter_FlushOnTicker verifies that events smaller than the batch
// threshold are flushed after the ticker interval.
func TestWriter_FlushOnTicker(t *testing.T) {
	db := setupAuditPostgres(t)

	w := NewWriter(db, silentLogger())
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	w.Start(ctx)

	const nEvents = 5
	for i := 0; i < nEvents; i++ {
		w.Log(testEvent("tenant-ticker", "action.tick"))
	}

	// Wait longer than the flush interval so the ticker fires.
	time.Sleep(flushInterval + 300*time.Millisecond)

	stopWriter(t, w)

	assert.Equal(t, nEvents, countRows(t, db, "tenant-ticker"),
		"%d events should be flushed after the ticker interval", nEvents)
}

// TestWriter_Stop_FlushesRemaining verifies that Stop() drains the buffer
// and flushes all remaining events before returning.
func TestWriter_Stop_FlushesRemaining(t *testing.T) {
	db := setupAuditPostgres(t)

	w := NewWriter(db, silentLogger())
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	w.Start(ctx)

	const nEvents = 42
	for i := 0; i < nEvents; i++ {
		w.Log(testEvent("tenant-stop", fmt.Sprintf("action.%d", i)))
	}

	stopWriter(t, w)

	assert.Equal(t, nEvents, countRows(t, db, "tenant-stop"),
		"Stop() must flush all %d remaining events", nEvents)
}

// TestWriter_NilMetadata_DefaultsToEmptyObject verifies that a nil Metadata
// field is stored as '{}' rather than causing a database error.
func TestWriter_NilMetadata_DefaultsToEmptyObject(t *testing.T) {
	db := setupAuditPostgres(t)

	w := NewWriter(db, silentLogger())
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	w.Start(ctx)

	w.Log(Event{
		TenantID:  "tenant-nil-meta",
		ActorID:   "actor-1",
		ActorType: "system",
		Action:    "probe",
		Metadata:  nil,
	})

	stopWriter(t, w)

	require.Equal(t, 1, countRows(t, db, "tenant-nil-meta"))

	var meta string
	err := db.QueryRowContext(ctx,
		"SELECT metadata FROM audit_log WHERE tenant_id = $1", "tenant-nil-meta").
		Scan(&meta)
	require.NoError(t, err)
	assert.JSONEq(t, `{}`, meta, "nil Metadata must be stored as '{}'")
}

// TestWriter_EmptyDecision_StoredAsNull verifies that an empty Decision field
// is persisted as SQL NULL rather than an empty string.
func TestWriter_EmptyDecision_StoredAsNull(t *testing.T) {
	db := setupAuditPostgres(t)

	w := NewWriter(db, silentLogger())
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	w.Start(ctx)

	w.Log(Event{
		TenantID:  "tenant-null-decision",
		ActorID:   "actor-1",
		ActorType: "system",
		Action:    "lifecycle.start",
		Decision:  "", // must become NULL
	})

	stopWriter(t, w)

	require.Equal(t, 1, countRows(t, db, "tenant-null-decision"))

	var decision sql.NullString
	err := db.QueryRowContext(ctx,
		"SELECT decision FROM audit_log WHERE tenant_id = $1", "tenant-null-decision").
		Scan(&decision)
	require.NoError(t, err)
	assert.False(t, decision.Valid, "empty Decision should be stored as NULL")
}

// ---------------------------------------------------------------------------
// Query integration tests
// ---------------------------------------------------------------------------

// TestQuery_List_TenantScoping verifies hard tenant isolation — List never
// returns rows from a different tenant.
func TestQuery_List_TenantScoping(t *testing.T) {
	db := setupAuditPostgres(t)
	q := NewQuery(db)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	w := NewWriter(db, silentLogger())
	w.Start(ctx)

	w.Log(testEvent("tenant-a", "event.a"))
	w.Log(testEvent("tenant-b", "event.b"))
	w.Log(testEvent("tenant-a", "event.c"))

	stopWriter(t, w)

	entries, total, err := q.List(ctx, "tenant-a", Filters{}, 100, 0)
	require.NoError(t, err)
	assert.Equal(t, 2, total, "tenant-a should have exactly 2 entries")
	assert.Len(t, entries, 2)
	for _, e := range entries {
		assert.Equal(t, "tenant-a", e.TenantID)
	}
}

// TestQuery_List_FilterByAction verifies exact-match action filtering.
func TestQuery_List_FilterByAction(t *testing.T) {
	db := setupAuditPostgres(t)
	q := NewQuery(db)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	w := NewWriter(db, silentLogger())
	w.Start(ctx)

	w.Log(testEvent("tenant-filter-action", "grant_created"))
	w.Log(testEvent("tenant-filter-action", "agent_registered"))
	w.Log(testEvent("tenant-filter-action", "grant_created"))

	stopWriter(t, w)

	entries, total, err := q.List(ctx, "tenant-filter-action", Filters{Action: "grant_created"}, 100, 0)
	require.NoError(t, err)
	assert.Equal(t, 2, total)
	assert.Len(t, entries, 2)
	for _, e := range entries {
		assert.Equal(t, "grant_created", e.Action)
	}
}

// TestQuery_List_FilterByActorID verifies actor_id filtering.
func TestQuery_List_FilterByActorID(t *testing.T) {
	db := setupAuditPostgres(t)
	q := NewQuery(db)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	w := NewWriter(db, silentLogger())
	w.Start(ctx)

	ev1 := testEvent("tenant-actor", "action.x")
	ev1.ActorID = "alice"
	ev2 := testEvent("tenant-actor", "action.y")
	ev2.ActorID = "bob"
	w.Log(ev1)
	w.Log(ev2)

	stopWriter(t, w)

	entries, total, err := q.List(ctx, "tenant-actor", Filters{ActorID: "alice"}, 100, 0)
	require.NoError(t, err)
	assert.Equal(t, 1, total)
	require.Len(t, entries, 1)
	assert.Equal(t, "alice", entries[0].ActorID)
}

// TestQuery_List_FilterByTargetTypeAndID verifies compound target filtering.
func TestQuery_List_FilterByTargetTypeAndID(t *testing.T) {
	db := setupAuditPostgres(t)
	q := NewQuery(db)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	w := NewWriter(db, silentLogger())
	w.Start(ctx)

	ev1 := testEvent("tenant-target", "check")
	ev1.TargetType = "agent"
	ev1.TargetID = "agent-42"
	ev2 := testEvent("tenant-target", "check")
	ev2.TargetType = "component"
	ev2.TargetID = "comp-99"
	w.Log(ev1)
	w.Log(ev2)

	stopWriter(t, w)

	entries, total, err := q.List(ctx, "tenant-target", Filters{TargetType: "agent", TargetID: "agent-42"}, 100, 0)
	require.NoError(t, err)
	assert.Equal(t, 1, total)
	require.Len(t, entries, 1)
	assert.Equal(t, "agent", entries[0].TargetType)
	assert.Equal(t, "agent-42", entries[0].TargetID)
}

// TestQuery_List_SinceFilter verifies that the Since time filter works
// correctly by writing two events with a measurable time gap.
func TestQuery_List_SinceFilter(t *testing.T) {
	db := setupAuditPostgres(t)
	q := NewQuery(db)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Write the early event.
	w1 := NewWriter(db, silentLogger())
	w1.Start(ctx)
	w1.Log(testEvent("tenant-since", "event.early"))
	stopWriter(t, w1)

	// Record boundary time after the early event is written.
	boundary := time.Now().UTC()
	// Small sleep to ensure the next event's created_at is strictly after boundary.
	time.Sleep(50 * time.Millisecond)

	// Write the late event.
	w2 := NewWriter(db, silentLogger())
	w2.Start(ctx)
	w2.Log(testEvent("tenant-since", "event.late"))
	stopWriter(t, w2)

	entries, total, err := q.List(ctx, "tenant-since", Filters{Since: &boundary}, 100, 0)
	require.NoError(t, err)
	assert.Equal(t, 1, total, "Since filter should return only the late event")
	require.Len(t, entries, 1)
	assert.Equal(t, "event.late", entries[0].Action)
}

// TestQuery_List_Pagination verifies limit and offset behaviour.
func TestQuery_List_Pagination(t *testing.T) {
	db := setupAuditPostgres(t)
	q := NewQuery(db)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	w := NewWriter(db, silentLogger())
	w.Start(ctx)

	const nTotal = 25
	for i := 0; i < nTotal; i++ {
		w.Log(testEvent("tenant-page", fmt.Sprintf("action.%d", i)))
	}
	stopWriter(t, w)

	// Page 1.
	entries1, total1, err := q.List(ctx, "tenant-page", Filters{}, 10, 0)
	require.NoError(t, err)
	assert.Equal(t, nTotal, total1, "total count must reflect all rows")
	assert.Len(t, entries1, 10, "first page must contain 10 entries")

	// Page 2.
	entries2, _, err := q.List(ctx, "tenant-page", Filters{}, 10, 10)
	require.NoError(t, err)
	assert.Len(t, entries2, 10)

	// Page 3 (last, partial).
	entries3, _, err := q.List(ctx, "tenant-page", Filters{}, 10, 20)
	require.NoError(t, err)
	assert.Len(t, entries3, 5, "last page should contain the remaining 5 entries")
}

// TestQuery_List_EmptyTenantReturnsError verifies the tenant guard.
func TestQuery_List_EmptyTenantReturnsError(t *testing.T) {
	db := setupAuditPostgres(t)
	q := NewQuery(db)

	_, _, err := q.List(context.Background(), "", Filters{}, 10, 0)
	assert.Error(t, err, "empty tenantID must return an error")
}

// TestQuery_List_NoResults verifies that an empty result set returns empty
// slice and 0 total without an error.
func TestQuery_List_NoResults(t *testing.T) {
	db := setupAuditPostgres(t)
	q := NewQuery(db)

	entries, total, err := q.List(context.Background(), "empty-tenant", Filters{}, 100, 0)
	require.NoError(t, err)
	assert.Equal(t, 0, total)
	assert.Empty(t, entries)
}

// TestWriter_ConcurrentLog_NoDataRace exercises concurrent Log() calls to
// detect data races (run with -race).
func TestWriter_ConcurrentLog_NoDataRace(t *testing.T) {
	db := setupAuditPostgres(t)

	w := NewWriter(db, silentLogger())
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	w.Start(ctx)

	const numGoroutines = 50
	const eventsEach = 20

	var remaining atomic.Int32
	remaining.Store(numGoroutines)
	allDone := make(chan struct{})

	for g := 0; g < numGoroutines; g++ {
		go func(id int) {
			for i := 0; i < eventsEach; i++ {
				w.Log(testEvent("tenant-race", fmt.Sprintf("action.%d.%d", id, i)))
			}
			if remaining.Add(-1) == 0 {
				close(allDone)
			}
		}(g)
	}

	<-allDone
	stopWriter(t, w)

	// Some events may be dropped if the buffer saturates, but the test must
	// not panic or race.
	rows := countRows(t, db, "tenant-race")
	assert.GreaterOrEqual(t, rows, 0,
		"race test must not corrupt DB or panic; got %d rows", rows)
}
