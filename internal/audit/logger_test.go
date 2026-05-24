package audit

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zero-day-ai/gibson/internal/state"
	"github.com/zero-day-ai/sdk/auth"
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

	return NewAuditLogger(ctx, stateClient, logger), cancel
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

// drainCounter reads the current value of the auditWriteDropsTotal counter.
func drainCounter() float64 {
	m := &dto.Metric{}
	if err := auditWriteDropsTotal.Write(m); err != nil {
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
	ctx := ctxWithTenant("acme")

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
	ctx := ctxWithTenant("acme")

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
// Log — missing identity falls back to "unknown"
// ---------------------------------------------------------------------------

func TestAuditLogger_Log_MissingIdentity_UsesUnknown(t *testing.T) {
	al, _ := newTestLogger(t)
	// Context has a tenant but no identity.
	ctx := ctxWithTenant("acme")

	al.Log(ctx, "tenant.list", "tenant", "", nil)
	require.True(t, waitForQueue(al, 200*time.Millisecond), "write queue did not drain")
	time.Sleep(10 * time.Millisecond)

	entries, err := al.Query(ctx, "acme", AuditQueryOptions{})
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "unknown", entries[0].ActorID)
	assert.Equal(t, "unknown", entries[0].ActorEmail)
}

// ---------------------------------------------------------------------------
// Query — time filtering
// ---------------------------------------------------------------------------

func TestAuditLogger_Query_TimeFiltering(t *testing.T) {
	al, _ := newTestLogger(t)
	ctx := ctxWithTenant("acme")

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
	ctx := ctxWithTenant("acme")

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
	ctx := ctxWithTenant("acme")

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
	ctx := ctxWithTenant("acme")

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

	queryCtx := ctxWithTenant("acme")
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
	ctx := ctxWithTenant("acme")

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
	ctx := ctxWithTenant("acme")

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
	ctx := ctxWithTenant("acme")

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
// New tests: fire-and-forget resilience
// ---------------------------------------------------------------------------

// newBrokenLogger creates an AuditLogger backed by a miniredis instance that
// is immediately stopped, causing all XADD commands to fail. MaxRetries is
// set to 0 so the XADD fails on the first attempt without sleeping.
func newBrokenLogger(t *testing.T) (*AuditLogger, context.CancelFunc) {
	t.Helper()

	mr := miniredis.RunT(t)

	cfg := state.DefaultConfig()
	cfg.URL = "redis://" + mr.Addr()
	cfg.MaxRetries = -1              // disable retries
	cfg.DialTimeout = 50 * time.Millisecond  // fail fast on connection
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

	al := NewAuditLogger(ctx, stateClient, logger)

	// Stop miniredis so all subsequent XADD commands fail immediately.
	mr.Close()

	return al, cancel
}

// TestAuditLogger_DropOnXADDError verifies that when the drain goroutine
// encounters an XADD error, it increments gibson_audit_write_drops_total.
func TestAuditLogger_DropOnXADDError(t *testing.T) {
	al, _ := newBrokenLogger(t)

	before := drainCounter()

	ctx := ctxWithTenant("acme")
	al.Log(ctx, "test.action", "resource", "r1", nil)

	// Wait for the drain goroutine to process the item and increment the counter.
	// MaxRetries=0 means no retry delay; 500ms is ample headroom.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if drainCounter()-before >= 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	after := drainCounter()
	assert.Equal(t, float64(1), after-before,
		"gibson_audit_write_drops_total must increment by 1 on XADD error")
}

// TestAuditLogger_DropOnQueueFull verifies that when the write queue is
// already at capacity, Log() drops the entry and increments the counter.
func TestAuditLogger_DropOnQueueFull(t *testing.T) {
	// Use a stopped drain context so nothing drains from the queue.
	mr := miniredis.RunT(t)
	cfg := state.DefaultConfig()
	cfg.URL = "redis://" + mr.Addr()

	stateClient, err := state.NewStateClient(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = stateClient.Close() })

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	// Create a context that we cancel immediately so the drain goroutine exits
	// and the queue stays full.
	drainCtx, drainCancel := context.WithCancel(context.Background())
	drainCancel() // cancel immediately so drainLoop exits quickly

	al := NewAuditLogger(drainCtx, stateClient, logger)

	// Wait for drain goroutine to exit (done channel will close).
	select {
	case <-al.done:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("drain goroutine did not exit after context cancel")
	}

	// Fill the queue to capacity with dummy items.
	ctx := ctxWithTenant("acme")
	dummy := auditWrite{
		streamKey: "tenant:acme:audit:log",
		values:    map[string]any{"id": "dummy"},
		loggerCtx: ctx,
	}
	for i := 0; i < writeQueueCap; i++ {
		al.writeQueue <- dummy
	}

	before := drainCounter()

	// This Log() call must hit the queue-full path.
	al.Log(ctx, "overflow.action", "resource", "r1", nil)

	after := drainCounter()
	assert.Equal(t, float64(1), after-before,
		"gibson_audit_write_drops_total must increment by 1 when queue is full")
}

// TestAuditLogger_NoErrorPropagated verifies that Log() does not panic and
// does not propagate an error to the caller even when the underlying Redis is
// unreachable.
func TestAuditLogger_NoErrorPropagated(t *testing.T) {
	al, _ := newBrokenLogger(t)

	ctx := ctxWithTenant("acme")

	// Must not panic.
	require.NotPanics(t, func() {
		al.Log(ctx, "test.action", "resource", "r1", nil)
	})

	// Log() returns nothing — no error to check. The test passing without panic
	// is the verification.
	_ = errors.New("placeholder to confirm no error return")
}
