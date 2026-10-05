// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package audit

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/state"
	"github.com/zeroroot-ai/sdk/auth"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// newTestLogger creates an AuditLogger backed by an in-process miniredis
// instance. The state client is closed automatically when the test ends.
// The logger's drain goroutine runs until the test context is cancelled.
func newTestLogger(t *testing.T) (*AuditLogger, context.CancelFunc) {
	t.Helper()

	mr := miniredis.RunT(t)

	cfg := state.DefaultConfig()
	cfg.URL = "redis://" + mr.Addr()

	stateClient, err := state.NewStateClient(cfg)
	require.NoError(t, err, "create state client against miniredis")
	t.Cleanup(func() { _ = stateClient.Close() })

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	return NewAuditLogger(ctx, stateClient, &recordingEmitter{}, logger), cancel
}

// ctxWithTenant returns a context with the given tenant ID injected.
func ctxWithTenant(tenant string) context.Context {
	return auth.ContextWithTenantString(context.Background(), tenant)
}

// ctxWithTenantAndIdentity returns a context carrying both a tenant ID and a
// verified identity. In the new model the identity is set via
// auth.WithIdentity; Subject doubles as the email/actor identifier.
func ctxWithTenantAndIdentity(tenant, subject, _ string) context.Context {
	ctx := auth.ContextWithTenantString(context.Background(), tenant)
	tid, _ := auth.NewTenantID(tenant)
	id := auth.Identity{
		Subject:        subject,
		Issuer:         "zitadel",
		CredentialType: "oidc",
		Tenant:         tid,
	}
	return auth.WithIdentity(ctx, id)
}

// recordingEmitter stands in for the durable Postgres writer. It keeps each
// event that the logger hands to it.
type recordingEmitter struct {
	mu     sync.Mutex
	events []Event
}

func (r *recordingEmitter) Log(event Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, event)
}

func (r *recordingEmitter) recorded() []Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Event(nil), r.events...)
}

// durableOf returns the recording emitter of a logger from newTestLogger.
func durableOf(t *testing.T, al *AuditLogger) *recordingEmitter {
	t.Helper()
	rec, ok := al.durable.(*recordingEmitter)
	require.True(t, ok, "the test logger has no recording emitter")
	return rec
}

// tailErrorCounter reads the current value of the auditTailErrorsTotal counter.
func tailErrorCounter() float64 {
	m := &dto.Metric{}
	if err := auditTailErrorsTotal.Write(m); err != nil {
		return 0
	}
	if m.Counter == nil {
		return 0
	}
	return m.Counter.GetValue()
}

// waitForQueue blocks until the logger's write queue is empty or the timeout
// is reached. Returns true if the queue drained in time.
func waitForQueue(al *AuditLogger, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if len(al.writeQueue) == 0 {
			return true
		}
		time.Sleep(2 * time.Millisecond)
	}
	return len(al.writeQueue) == 0
}

// ---------------------------------------------------------------------------
// Log — basic write
// ---------------------------------------------------------------------------

func TestAuditLogger_Log_WritesEntryToStream(t *testing.T) {
	al, _ := newTestLogger(t)
	ctx := ctxWithTenantAndIdentity("acme", "user-123", "alice@example.com")

	al.Log(ctx, "apikey.create", "apikey", "key-abc", map[string]any{
		"name": "ci-runner",
	})

	// Allow the drain goroutine to process.
	require.True(t, waitForQueue(al, 200*time.Millisecond), "write queue did not drain")
	// Give the XADD a moment to complete.
	time.Sleep(10 * time.Millisecond)

	entries, err := al.Query(ctx, "acme", AuditQueryOptions{Limit: 10})
	require.NoError(t, err)
	require.Len(t, entries, 1)

	e := entries[0]
	assert.NotEmpty(t, e.ID, "entry ID must be set")
	assert.Equal(t, "acme", e.TenantID)
	assert.Equal(t, "user-123", e.ActorID)
	// In the new identity model, ActorEmail mirrors Subject (no separate email field).
	assert.Equal(t, "user-123", e.ActorEmail)
	assert.Equal(t, "apikey.create", e.Action)
	assert.Equal(t, "apikey", e.Resource)
	assert.Equal(t, "key-abc", e.ResourceID)
	assert.Equal(t, resultSuccess, e.Result)
	assert.Equal(t, "ci-runner", e.Details["name"])
	assert.False(t, e.Timestamp.IsZero(), "timestamp must be set")
}

// ---------------------------------------------------------------------------
// LogWithResult — success / failure
// ---------------------------------------------------------------------------

func TestAuditLogger_LogWithResult_RecordsSuccess(t *testing.T) {
	al, _ := newTestLogger(t)
	ctx := ctxWithTenantAndIdentity("acme", "user-1", "")

	al.LogWithResult(ctx, "mission.start", "mission", "m-1", resultSuccess, nil)
	require.True(t, waitForQueue(al, 200*time.Millisecond), "write queue did not drain")
	time.Sleep(10 * time.Millisecond)

	entries, err := al.Query(ctx, "acme", AuditQueryOptions{})
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, resultSuccess, entries[0].Result)
}

func TestAuditLogger_LogWithResult_RecordsFailure(t *testing.T) {
	al, _ := newTestLogger(t)
	ctx := ctxWithTenantAndIdentity("acme", "user-1", "")

	al.LogWithResult(ctx, "mission.start", "mission", "m-1", resultFailure, map[string]any{
		"reason": "quota exceeded",
	})
	require.True(t, waitForQueue(al, 200*time.Millisecond), "write queue did not drain")
	time.Sleep(10 * time.Millisecond)

	entries, err := al.Query(ctx, "acme", AuditQueryOptions{})
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, resultFailure, entries[0].Result)
	assert.Equal(t, "quota exceeded", entries[0].Details["reason"])
}

// ---------------------------------------------------------------------------
// Log — an entry with no actor is refused, not recorded as "unknown"
// ---------------------------------------------------------------------------

func TestAuditLogger_Log_MissingIdentity_IsRefused(t *testing.T) {
	al, _ := newTestLogger(t)
	// Context has a tenant but no identity.
	ctx := ctxWithTenant("acme")
	before := testutil.ToFloat64(auditActorlessTotal)

	al.Log(ctx, "tenant.list", "tenant", "", nil)
	require.True(t, waitForQueue(al, 200*time.Millisecond), "write queue did not drain")
	time.Sleep(10 * time.Millisecond)

	entries, err := al.Query(ctx, "acme", AuditQueryOptions{})
	require.NoError(t, err)
	assert.Empty(t, entries, "an actorless entry must not reach the stream")
	assert.InDelta(t, before+1, testutil.ToFloat64(auditActorlessTotal), 0, "the refusal is counted")
}

// ---------------------------------------------------------------------------
// Query — time filtering
// ---------------------------------------------------------------------------

func TestAuditLogger_Query_TimeFiltering(t *testing.T) {
	al, _ := newTestLogger(t)
	ctx := ctxWithTenantAndIdentity("acme", "user-1", "")

	// Write first entry.
	al.Log(ctx, "event.a", "res", "r1", nil)
	require.True(t, waitForQueue(al, 200*time.Millisecond), "write queue did not drain")
	time.Sleep(10 * time.Millisecond)

	// Sleep so the first entry's Redis stream ID is strictly before t0.
	time.Sleep(5 * time.Millisecond)

	// Record the boundary after the first entry has been written.
	t0 := time.Now().UTC()

	// Sleep again so the second entry's Redis stream ID is strictly after t0.
	time.Sleep(5 * time.Millisecond)

	// Write second entry after t0.
	al.Log(ctx, "event.b", "res", "r2", nil)
	require.True(t, waitForQueue(al, 200*time.Millisecond), "write queue did not drain")
	time.Sleep(10 * time.Millisecond)

	// Query using t0 as start — should return only the second entry.
	entries, err := al.Query(ctx, "acme", AuditQueryOptions{
		StartTime: t0,
		Limit:     10,
	})
	require.NoError(t, err)
	require.Len(t, entries, 1, "only entries at or after t0 should be returned")
	assert.Equal(t, "event.b", entries[0].Action)
}

func TestAuditLogger_Query_EndTimeFiltering(t *testing.T) {
	al, _ := newTestLogger(t)
	ctx := ctxWithTenantAndIdentity("acme", "user-1", "")

	// Write first entry.
	al.Log(ctx, "event.early", "res", "r1", nil)
	require.True(t, waitForQueue(al, 200*time.Millisecond), "write queue did not drain")
	time.Sleep(10 * time.Millisecond)

	// Sleep so the first entry's Redis stream ID is strictly before tMid.
	time.Sleep(5 * time.Millisecond)

	// Record the mid-point.
	tMid := time.Now().UTC()

	// Sleep again so the second entry's Redis stream ID is strictly after tMid.
	time.Sleep(5 * time.Millisecond)

	// Write second entry well after the mid-point.
	al.Log(ctx, "event.late", "res", "r2", nil)
	require.True(t, waitForQueue(al, 200*time.Millisecond), "write queue did not drain")
	time.Sleep(10 * time.Millisecond)

	// Query with EndTime = tMid — should only get the first entry.
	entries, err := al.Query(ctx, "acme", AuditQueryOptions{
		EndTime: tMid,
		Limit:   10,
	})
	require.NoError(t, err)
	require.Len(t, entries, 1, "only entries before or at tMid should be returned")
	assert.Equal(t, "event.early", entries[0].Action)
}

// ---------------------------------------------------------------------------
// Query — action prefix filtering
// ---------------------------------------------------------------------------

func TestAuditLogger_Query_FiltersByActionPrefix(t *testing.T) {
	al, _ := newTestLogger(t)
	ctx := ctxWithTenantAndIdentity("acme", "user-1", "")

	al.Log(ctx, "apikey.create", "apikey", "k1", nil)
	al.Log(ctx, "apikey.revoke", "apikey", "k2", nil)
	al.Log(ctx, "mission.start", "mission", "m1", nil)
	require.True(t, waitForQueue(al, 200*time.Millisecond), "write queue did not drain")
	time.Sleep(10 * time.Millisecond)

	entries, err := al.Query(ctx, "acme", AuditQueryOptions{
		Action: "apikey",
		Limit:  10,
	})
	require.NoError(t, err)
	require.Len(t, entries, 2, "only apikey.* actions should be returned")

	for _, e := range entries {
		assert.True(t, len(e.Action) >= len("apikey") && e.Action[:len("apikey")] == "apikey",
			"expected action prefix 'apikey', got %q", e.Action)
	}
}

func TestAuditLogger_Query_ExactActionMatch(t *testing.T) {
	al, _ := newTestLogger(t)
	ctx := ctxWithTenantAndIdentity("acme", "user-1", "")

	al.Log(ctx, "apikey.create", "apikey", "k1", nil)
	al.Log(ctx, "apikey.revoke", "apikey", "k2", nil)
	require.True(t, waitForQueue(al, 200*time.Millisecond), "write queue did not drain")
	time.Sleep(10 * time.Millisecond)

	entries, err := al.Query(ctx, "acme", AuditQueryOptions{
		Action: "apikey.create",
		Limit:  10,
	})
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "apikey.create", entries[0].Action)
}

// ---------------------------------------------------------------------------
// Query — actor filtering
// ---------------------------------------------------------------------------

func TestAuditLogger_Query_FiltersByActor(t *testing.T) {
	al, _ := newTestLogger(t)

	ctxAlice := ctxWithTenantAndIdentity("acme", "alice", "alice@example.com")
	ctxBob := ctxWithTenantAndIdentity("acme", "bob", "bob@example.com")

	al.Log(ctxAlice, "apikey.create", "apikey", "k1", nil)
	al.Log(ctxBob, "mission.start", "mission", "m1", nil)
	al.Log(ctxAlice, "mission.stop", "mission", "m1", nil)
	require.True(t, waitForQueue(al, 200*time.Millisecond), "write queue did not drain")
	time.Sleep(10 * time.Millisecond)

	queryCtx := ctxWithTenantAndIdentity("acme", "user-1", "")
	entries, err := al.Query(queryCtx, "acme", AuditQueryOptions{
		ActorID: "alice",
		Limit:   10,
	})
	require.NoError(t, err)
	require.Len(t, entries, 2, "should return only alice's entries")

	for _, e := range entries {
		assert.Equal(t, "alice", e.ActorID)
	}
}

// ---------------------------------------------------------------------------
// Tenant isolation
// ---------------------------------------------------------------------------

func TestAuditLogger_TenantIsolation(t *testing.T) {
	// Both tenants share the same AuditLogger (same Redis instance).
	al, _ := newTestLogger(t)

	ctxA := ctxWithTenantAndIdentity("tenant-a", "user-a", "a@example.com")
	ctxB := ctxWithTenantAndIdentity("tenant-b", "user-b", "b@example.com")

	al.Log(ctxA, "mission.start", "mission", "m-a", nil)
	al.Log(ctxB, "mission.start", "mission", "m-b", nil)
	require.True(t, waitForQueue(al, 200*time.Millisecond), "write queue did not drain")
	time.Sleep(10 * time.Millisecond)

	// Query tenant-a — must not see tenant-b's entry.
	entriesA, err := al.Query(ctxA, "tenant-a", AuditQueryOptions{Limit: 10})
	require.NoError(t, err)
	require.Len(t, entriesA, 1, "tenant-a must see exactly its own entry")
	assert.Equal(t, "tenant-a", entriesA[0].TenantID)
	assert.Equal(t, "m-a", entriesA[0].ResourceID)

	// Query tenant-b — must not see tenant-a's entry.
	entriesB, err := al.Query(ctxB, "tenant-b", AuditQueryOptions{Limit: 10})
	require.NoError(t, err)
	require.Len(t, entriesB, 1, "tenant-b must see exactly its own entry")
	assert.Equal(t, "tenant-b", entriesB[0].TenantID)
	assert.Equal(t, "m-b", entriesB[0].ResourceID)
}

// ---------------------------------------------------------------------------
// Query — limit enforcement
// ---------------------------------------------------------------------------

func TestAuditLogger_Query_LimitIsRespected(t *testing.T) {
	al, _ := newTestLogger(t)
	ctx := ctxWithTenantAndIdentity("acme", "user-1", "")

	// Write 20 entries.
	for i := 0; i < 20; i++ {
		al.Log(ctx, "event.tick", "res", "r", nil)
	}
	require.True(t, waitForQueue(al, 500*time.Millisecond), "write queue did not drain")
	time.Sleep(10 * time.Millisecond)

	entries, err := al.Query(ctx, "acme", AuditQueryOptions{Limit: 5})
	require.NoError(t, err)
	assert.Len(t, entries, 5, "query must honour the Limit option")
}

func TestAuditLogger_Query_DefaultLimitApplied(t *testing.T) {
	al, _ := newTestLogger(t)
	ctx := ctxWithTenantAndIdentity("acme", "user-1", "")

	// Limit = 0 should use defaultQueryLimit (100).
	// We can only meaningfully test that Limit 0 doesn't panic and returns entries.
	al.Log(ctx, "event.tick", "res", "r", nil)
	require.True(t, waitForQueue(al, 200*time.Millisecond), "write queue did not drain")
	time.Sleep(10 * time.Millisecond)

	entries, err := al.Query(ctx, "acme", AuditQueryOptions{})
	require.NoError(t, err)
	assert.NotEmpty(t, entries)
}

// ---------------------------------------------------------------------------
// Stream key format
// ---------------------------------------------------------------------------

func TestAuditLogger_StreamKey_Format(t *testing.T) {
	al, _ := newTestLogger(t)
	key := al.streamKey("my-tenant")
	assert.Equal(t, "tenant:my-tenant:audit:log", key)
}

// ---------------------------------------------------------------------------
// Query on empty stream returns empty slice (not an error)
// ---------------------------------------------------------------------------

func TestAuditLogger_Query_EmptyStream_ReturnsEmpty(t *testing.T) {
	al, _ := newTestLogger(t)
	ctx := ctxWithTenantAndIdentity("acme", "user-1", "")

	entries, err := al.Query(ctx, "acme", AuditQueryOptions{})
	require.NoError(t, err)
	assert.Empty(t, entries, "querying an empty stream must return empty slice, not an error")
}

// ---------------------------------------------------------------------------
// Query — empty tenant returns error
// ---------------------------------------------------------------------------

func TestAuditLogger_Query_EmptyTenant_ReturnsError(t *testing.T) {
	al, _ := newTestLogger(t)
	ctx := context.Background()

	_, err := al.Query(ctx, "", AuditQueryOptions{})
	assert.Error(t, err, "Query with empty tenant must return an error")
}

// ---------------------------------------------------------------------------
// The durable copy and the live tail
// ---------------------------------------------------------------------------

// newBrokenLogger creates an AuditLogger backed by a miniredis instance that
// is immediately stopped, causing all XADD commands to fail. MaxRetries is
// set to 0 so the XADD fails on the first attempt without sleeping.
func newBrokenLogger(t *testing.T) *AuditLogger {
	t.Helper()

	mr := miniredis.RunT(t)

	cfg := state.DefaultConfig()
	cfg.URL = "redis://" + mr.Addr()
	cfg.MaxRetries = -1 // disable retries
	// DialTimeout stays at the default. NewStateClient pings with a context
	// bounded by it, so a short value here fails the SETUP on a loaded runner
	// before the broken path is ever exercised (go-ci run 36430697103,
	// 2026-09-28). The broken path does not need it: a closed port refuses
	// the dial at once, and the read and write timeouts below keep XADD fast.
	cfg.ReadTimeout = 50 * time.Millisecond
	cfg.WriteTimeout = 50 * time.Millisecond

	stateClient, err := state.NewStateClient(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = stateClient.Close() })

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	al := NewAuditLogger(ctx, stateClient, &recordingEmitter{}, logger)

	// Stop miniredis so all subsequent XADD commands fail immediately.
	mr.Close()

	return al
}

// TestAuditLogger_EachRecordGoesToTheDurableWriter: the logger hands each
// record to the durable writer, with each field that the live tail has.
func TestAuditLogger_EachRecordGoesToTheDurableWriter(t *testing.T) {
	al, _ := newTestLogger(t)
	ctx := ctxWithTenantAndIdentity("acme", "user-1", "")

	al.LogWithResult(ctx, "plugin.enable", "plugin", "github", resultFailure, map[string]any{"why": "test"})

	got := durableOf(t, al).recorded()
	require.Len(t, got, 1, "the durable writer must get the record")
	ev := got[0]
	assert.Equal(t, "acme", ev.TenantID)
	assert.Equal(t, "user-1", ev.ActorID)
	assert.Equal(t, "user", ev.ActorType)
	assert.Equal(t, "plugin.enable", ev.Action)
	assert.Equal(t, "plugin", ev.TargetType)
	assert.Equal(t, "github", ev.TargetID)

	var meta struct {
		EntryID string         `json:"entry_id"`
		Result  string         `json:"result"`
		Details map[string]any `json:"details"`
	}
	require.NoError(t, json.Unmarshal(ev.Metadata, &meta))
	assert.NotEmpty(t, meta.EntryID)
	assert.Equal(t, resultFailure, meta.Result)
	assert.Equal(t, "test", meta.Details["why"])

	// The live tail holds the same record.
	require.True(t, waitForQueue(al, time.Second))
	require.Eventually(t, func() bool {
		entries, err := al.Query(context.Background(), "acme", AuditQueryOptions{})
		return err == nil && len(entries) == 1 && entries[0].ID == meta.EntryID
	}, time.Second, 5*time.Millisecond, "the live tail must hold the record")
}

// TestAuditLogger_ActorlessEntryDoesNotReachTheDurableWriter: a refused
// entry is written nowhere.
func TestAuditLogger_ActorlessEntryDoesNotReachTheDurableWriter(t *testing.T) {
	al, _ := newTestLogger(t)
	al.Log(ctxWithTenant("acme"), "test.action", "resource", "r1", nil)
	assert.Empty(t, durableOf(t, al).recorded())
}

// TestAuditLogger_TailFailureKeepsTheDurableRecord: when Redis refuses the
// copy for the live tail, the durable writer still has the record. The miss
// is counted as a tail error.
func TestAuditLogger_TailFailureKeepsTheDurableRecord(t *testing.T) {
	al := newBrokenLogger(t)

	before := tailErrorCounter()

	ctx := ctxWithTenantAndIdentity("acme", "user-1", "")
	require.NotPanics(t, func() {
		al.Log(ctx, "test.action", "resource", "r1", nil)
	})

	require.Len(t, durableOf(t, al).recorded(), 1, "Postgres must hold the record when Redis is down")
	require.Eventually(t, func() bool {
		return tailErrorCounter()-before >= 1
	}, 2*time.Second, 5*time.Millisecond, "gibson_audit_tail_errors_total must count the miss")
}

// TestAuditLogger_FullTailQueueDoesNotHoldTheCaller: the live tail is not
// the record. A full tail queue does not block Log and does not lose the
// durable record.
func TestAuditLogger_FullTailQueueDoesNotHoldTheCaller(t *testing.T) {
	mr := miniredis.RunT(t)
	cfg := state.DefaultConfig()
	cfg.URL = "redis://" + mr.Addr()

	stateClient, err := state.NewStateClient(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = stateClient.Close() })

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	// Cancel at once, so the drain goroutine exits and the queue stays full.
	drainCtx, drainCancel := context.WithCancel(context.Background())
	drainCancel()

	al := NewAuditLogger(drainCtx, stateClient, &recordingEmitter{}, logger)
	select {
	case <-al.done:
	case <-time.After(time.Second):
		t.Fatal("drain goroutine did not exit after context cancel")
	}

	dummy := auditWrite{
		streamKey: "tenant:acme:audit:log",
		values:    map[string]any{"id": "dummy"},
	}
	for i := 0; i < writeQueueCap; i++ {
		al.writeQueue <- dummy
	}

	before := tailErrorCounter()

	done := make(chan struct{})
	go func() {
		al.Log(ctxWithTenantAndIdentity("acme", "user-1", ""), "overflow.action", "resource", "r1", nil)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Log blocked on a full live tail queue")
	}

	assert.Len(t, durableOf(t, al).recorded(), 1, "the durable writer must hold the record")
	assert.Equal(t, float64(1), tailErrorCounter()-before,
		"gibson_audit_tail_errors_total must count the record that is not in the tail")
}

// TestNewAuditLogger_RequiresTheDurableWriter: a logger with no durable
// writer would keep the record only in a stream that Redis trims.
func TestNewAuditLogger_RequiresTheDurableWriter(t *testing.T) {
	mr := miniredis.RunT(t)
	cfg := state.DefaultConfig()
	cfg.URL = "redis://" + mr.Addr()
	stateClient, err := state.NewStateClient(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = stateClient.Close() })

	require.Panics(t, func() {
		NewAuditLogger(context.Background(), stateClient, nil, slog.Default())
	})
}

// TestActorTypeFor maps each credential class onto the actor_type column.
func TestActorTypeFor(t *testing.T) {
	assert.Equal(t, "user", actorTypeFor(auth.CredentialOIDCUser))
	assert.Equal(t, "system", actorTypeFor(auth.CredentialClientCredentials))
	assert.Equal(t, "agent", actorTypeFor(auth.CredentialCapabilityGrant))
	assert.Equal(t, "user", actorTypeFor(""))
}
