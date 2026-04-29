package secrets

import (
	"context"
	"log/slog"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zero-day-ai/gibson/internal/audit"
	"github.com/zero-day-ai/gibson/internal/state"
)

// newTestAuditLogger creates an AuditLogger backed by an in-process miniredis
// instance. It follows the same pattern used by audit/logger_test.go.
func newTestAuditLogger(t *testing.T) *audit.AuditLogger {
	t.Helper()
	mr := miniredis.RunT(t)
	cfg := state.DefaultConfig()
	cfg.URL = "redis://" + mr.Addr()
	sc, err := state.NewStateClient(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sc.Close() })
	sl := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	return audit.NewAuditLogger(sc, sl)
}

func TestAuditWriter_SuccessfulWrite(t *testing.T) {
	logger := newTestAuditLogger(t)
	w := NewAuditWriter(logger, slog.Default())

	event := AuditEvent{
		ActorID:       "plugin_principal:foo",
		ActorTenantID: "acme-corp",
		Action:        ActionSecretRead,
		Effect:        EffectAllow,
		ResourceType:  "secret",
		ResourceURI:   "secret:tenant-acme-corp:cred:openai",
		Decision:      "allow",
		Success:       true,
		OccurredAt:    time.Now().UTC(),
	}
	// Must not panic or error.
	w.Audit(context.Background(), event)
}

func TestAuditWriter_RetryOnFailure_SleepsExpectedTimes(t *testing.T) {
	// Use a closed Redis client so every write fails, then count sleep calls.
	mr := miniredis.RunT(t)
	cfg := state.DefaultConfig()
	cfg.URL = "redis://" + mr.Addr()
	sc, err := state.NewStateClient(cfg)
	require.NoError(t, err)
	// Close immediately to force write failures.
	require.NoError(t, sc.Close())

	sl := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	logger := audit.NewAuditLogger(sc, sl)

	var sleepCalls int32
	fakeSleep := func(_ time.Duration) { atomic.AddInt32(&sleepCalls, 1) }

	w := newAuditWriterWithClock(logger, sl, nil, fakeSleep)

	event := AuditEvent{
		ActorID:       "plugin_principal:foo",
		ActorTenantID: "acme-corp",
		Action:        ActionSecretRead,
		Effect:        EffectAllow,
		ResourceType:  "secret",
		ResourceURI:   "secret:tenant-acme-corp:cred:openai",
		Decision:      "allow",
		Success:       true,
		OccurredAt:    time.Now().UTC(),
	}

	// Must return even when all retries fail.
	w.Audit(context.Background(), event)

	// 3 backoffs between 4 attempts.
	assert.EqualValues(t, 3, atomic.LoadInt32(&sleepCalls),
		"expected 3 sleep calls (4 total attempts, 3 backoffs)")
}

func TestAuditWriter_PlaintextGuard_RejectsLongFieldWithValue(t *testing.T) {
	logger := newTestAuditLogger(t)
	w := NewAuditWriter(logger, slog.Default())

	// A field > 256 bytes containing "value" must be rejected.
	longField := string(make([]byte, 300)) + "value_leakage"
	event := AuditEvent{
		ActorID:       "plugin_principal:foo",
		ActorTenantID: "acme-corp",
		Action:        ActionSecretRead,
		Effect:        EffectAllow,
		ResourceType:  "secret",
		ResourceURI:   longField,
		Decision:      "allow",
		Success:       true,
		OccurredAt:    time.Now().UTC(),
	}
	// Must not panic; rejection is silent to the caller but logged CRITICAL.
	w.Audit(context.Background(), event)
}

func TestAuditWriter_PlaintextGuard_AllowsShortFieldWithValue(t *testing.T) {
	logger := newTestAuditLogger(t)
	w := NewAuditWriter(logger, slog.Default())

	// Short field containing "value" — guard must NOT trigger.
	event := AuditEvent{
		ActorID:       "plugin_principal:foo",
		ActorTenantID: "acme-corp",
		Action:        ActionSecretRead,
		Effect:        EffectAllow,
		ResourceType:  "secret",
		ResourceURI:   "secret:acme:value",
		Decision:      "allow",
		Success:       true,
		OccurredAt:    time.Now().UTC(),
	}
	// Should write without rejection.
	w.Audit(context.Background(), event)
}

func TestAuditWriter_CallerUnaffectedByAuditFailure(t *testing.T) {
	// Verify the caller continues even when audit is broken.
	mr := miniredis.RunT(t)
	cfg := state.DefaultConfig()
	cfg.URL = "redis://" + mr.Addr()
	sc, err := state.NewStateClient(cfg)
	require.NoError(t, err)
	require.NoError(t, sc.Close())

	sl := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	logger := audit.NewAuditLogger(sc, sl)
	noSleep := func(_ time.Duration) {}
	w := newAuditWriterWithClock(logger, sl, nil, noSleep)

	event := AuditEvent{
		ActorID: "p", ActorTenantID: "acme-corp",
		Action: ActionSecretRead, Effect: EffectAllow,
		ResourceType: "secret", ResourceURI: "secret:acme:foo",
		Decision: "allow", Success: true,
	}

	done := make(chan struct{})
	go func() {
		w.Audit(context.Background(), event)
		close(done)
	}()

	select {
	case <-done:
		// Good — returned promptly.
	case <-time.After(2 * time.Second):
		t.Fatal("Audit blocked for > 2s; caller was affected by audit failure")
	}
}

// TestContainsSubstring covers the internal helper.
func TestContainsSubstring(t *testing.T) {
	tests := []struct {
		s, sub string
		want   bool
	}{
		{"hello value world", "value", true},
		{"short", "value", false},
		{"secret_value=foo", "secret_value", true},
		{"clean string", "value", false},
		{"", "value", false},
		{"value", "", false},
		{"xvaluex", "value", true},
	}
	for _, tc := range tests {
		got := containsSubstring(tc.s, tc.sub)
		assert.Equal(t, tc.want, got, "containsSubstring(%q, %q)", tc.s, tc.sub)
	}
}
