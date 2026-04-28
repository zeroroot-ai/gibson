package audit

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
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
func newTestLogger(t *testing.T) *AuditLogger {
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

	return NewAuditLogger(stateClient, logger)
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

// ---------------------------------------------------------------------------
// Log — basic write
// ---------------------------------------------------------------------------

func TestAuditLogger_Log_WritesEntryToStream(t *testing.T) {
	al := newTestLogger(t)
	ctx := ctxWithTenantAndIdentity("acme", "user-123", "alice@example.com")

	err := al.Log(ctx, "apikey.create", "apikey", "key-abc", map[string]any{
		"name": "ci-runner",
	})
	require.NoError(t, err)

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
	al := newTestLogger(t)
	ctx := ctxWithTenant("acme")

	require.NoError(t, al.LogWithResult(ctx, "mission.start", "mission", "m-1", resultSuccess, nil))

	entries, err := al.Query(ctx, "acme", AuditQueryOptions{})
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, resultSuccess, entries[0].Result)
}

func TestAuditLogger_LogWithResult_RecordsFailure(t *testing.T) {
	al := newTestLogger(t)
	ctx := ctxWithTenant("acme")

	require.NoError(t, al.LogWithResult(ctx, "mission.start", "mission", "m-1", resultFailure, map[string]any{
		"reason": "quota exceeded",
	}))

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
	al := newTestLogger(t)
	// Context has a tenant but no identity.
	ctx := ctxWithTenant("acme")

	require.NoError(t, al.Log(ctx, "tenant.list", "tenant", "", nil))

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
	al := newTestLogger(t)
	ctx := ctxWithTenant("acme")

	// Write first entry.
	require.NoError(t, al.Log(ctx, "event.a", "res", "r1", nil))

	// Sleep so the first entry's Redis stream ID is strictly before t0.
	time.Sleep(5 * time.Millisecond)

	// Record the boundary after the first entry has been written.
	t0 := time.Now().UTC()

	// Sleep again so the second entry's Redis stream ID is strictly after t0.
	time.Sleep(5 * time.Millisecond)

	// Write second entry after t0.
	require.NoError(t, al.Log(ctx, "event.b", "res", "r2", nil))

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
	al := newTestLogger(t)
	ctx := ctxWithTenant("acme")

	// Write first entry.
	require.NoError(t, al.Log(ctx, "event.early", "res", "r1", nil))

	// Sleep so the first entry's Redis stream ID is strictly before tMid.
	time.Sleep(5 * time.Millisecond)

	// Record the mid-point.
	tMid := time.Now().UTC()

	// Sleep again so the second entry's Redis stream ID is strictly after tMid.
	time.Sleep(5 * time.Millisecond)

	// Write second entry well after the mid-point.
	require.NoError(t, al.Log(ctx, "event.late", "res", "r2", nil))

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
	al := newTestLogger(t)
	ctx := ctxWithTenant("acme")

	require.NoError(t, al.Log(ctx, "apikey.create", "apikey", "k1", nil))
	require.NoError(t, al.Log(ctx, "apikey.revoke", "apikey", "k2", nil))
	require.NoError(t, al.Log(ctx, "mission.start", "mission", "m1", nil))

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
	al := newTestLogger(t)
	ctx := ctxWithTenant("acme")

	require.NoError(t, al.Log(ctx, "apikey.create", "apikey", "k1", nil))
	require.NoError(t, al.Log(ctx, "apikey.revoke", "apikey", "k2", nil))

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
	al := newTestLogger(t)

	ctxAlice := ctxWithTenantAndIdentity("acme", "alice", "alice@example.com")
	ctxBob := ctxWithTenantAndIdentity("acme", "bob", "bob@example.com")

	require.NoError(t, al.Log(ctxAlice, "apikey.create", "apikey", "k1", nil))
	require.NoError(t, al.Log(ctxBob, "mission.start", "mission", "m1", nil))
	require.NoError(t, al.Log(ctxAlice, "mission.stop", "mission", "m1", nil))

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
	al := newTestLogger(t)

	ctxA := ctxWithTenantAndIdentity("tenant-a", "user-a", "a@example.com")
	ctxB := ctxWithTenantAndIdentity("tenant-b", "user-b", "b@example.com")

	require.NoError(t, al.Log(ctxA, "mission.start", "mission", "m-a", nil))
	require.NoError(t, al.Log(ctxB, "mission.start", "mission", "m-b", nil))

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
	al := newTestLogger(t)
	ctx := ctxWithTenant("acme")

	// Write 20 entries.
	for i := 0; i < 20; i++ {
		require.NoError(t, al.Log(ctx, "event.tick", "res", "r", nil))
	}

	entries, err := al.Query(ctx, "acme", AuditQueryOptions{Limit: 5})
	require.NoError(t, err)
	assert.Len(t, entries, 5, "query must honour the Limit option")
}

func TestAuditLogger_Query_DefaultLimitApplied(t *testing.T) {
	al := newTestLogger(t)
	ctx := ctxWithTenant("acme")

	// Limit = 0 should use defaultQueryLimit (100).
	// We can only meaningfully test that Limit 0 doesn't panic and returns entries.
	require.NoError(t, al.Log(ctx, "event.tick", "res", "r", nil))

	entries, err := al.Query(ctx, "acme", AuditQueryOptions{})
	require.NoError(t, err)
	assert.NotEmpty(t, entries)
}

// ---------------------------------------------------------------------------
// Stream key format
// ---------------------------------------------------------------------------

func TestAuditLogger_StreamKey_Format(t *testing.T) {
	al := newTestLogger(t)
	key := al.streamKey("my-tenant")
	assert.Equal(t, "tenant:my-tenant:audit:log", key)
}

// ---------------------------------------------------------------------------
// Query on empty stream returns empty slice (not an error)
// ---------------------------------------------------------------------------

func TestAuditLogger_Query_EmptyStream_ReturnsEmpty(t *testing.T) {
	al := newTestLogger(t)
	ctx := ctxWithTenant("acme")

	entries, err := al.Query(ctx, "acme", AuditQueryOptions{})
	require.NoError(t, err)
	assert.Empty(t, entries, "querying an empty stream must return empty slice, not an error")
}

// ---------------------------------------------------------------------------
// Query — empty tenant returns error
// ---------------------------------------------------------------------------

func TestAuditLogger_Query_EmptyTenant_ReturnsError(t *testing.T) {
	al := newTestLogger(t)
	ctx := context.Background()

	_, err := al.Query(ctx, "", AuditQueryOptions{})
	assert.Error(t, err, "Query with empty tenant must return an error")
}
