// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package secrets

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/state"
	"github.com/zeroroot-ai/gibson/internal/platform/audit"
	"github.com/zeroroot-ai/gibson/internal/platform/audit/audittest"
	"github.com/zeroroot-ai/sdk/auth"
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
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return audit.NewAuditLogger(ctx, sc, &audittest.Recorder{}, sl)
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
	// Verify the caller continues even when audit is broken. Since
	// AuditLogger.LogWithResult is now fire-and-forget, Audit() must return
	// promptly even when the underlying Redis is unreachable.
	mr := miniredis.RunT(t)
	cfg := state.DefaultConfig()
	cfg.URL = "redis://" + mr.Addr()
	cfg.MaxRetries = -1 // disable retries
	cfg.DialTimeout = 50 * time.Millisecond
	cfg.ReadTimeout = 50 * time.Millisecond
	cfg.WriteTimeout = 50 * time.Millisecond
	sc, err := state.NewStateClient(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sc.Close() })
	// Stop Redis to simulate failure.
	mr.Close()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	sl := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	logger := audit.NewAuditLogger(ctx, sc, &audittest.Recorder{}, sl)
	w := NewAuditWriter(logger, sl)

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

// newRecordingAuditLogger is newTestAuditLogger with the durable Recorder
// returned, so a test can read what reached the durable writer.
func newRecordingAuditLogger(t *testing.T) (*audit.AuditLogger, *audittest.Recorder) {
	t.Helper()
	mr := miniredis.RunT(t)
	cfg := state.DefaultConfig()
	cfg.URL = "redis://" + mr.Addr()
	sc, err := state.NewStateClient(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sc.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	rec := &audittest.Recorder{}
	return audit.NewAuditLogger(ctx, sc, rec, slog.Default()), rec
}

func operatorContext() context.Context {
	ctx := auth.ContextWithTenantString(context.Background(), "acme-corp")
	tid, _ := auth.NewTenantID("acme-corp")
	return auth.WithIdentity(ctx, auth.Identity{Subject: "operator-1", Issuer: "zitadel", CredentialType: "oidc", Tenant: tid})
}

// TestAuditWriter_Record_WritesDurablyBeforeItReturns: Record returns
// after the durable writer has the event.
func TestAuditWriter_Record_WritesDurablyBeforeItReturns(t *testing.T) {
	logger, rec := newRecordingAuditLogger(t)
	w := NewAuditWriter(logger, slog.Default())

	require.NoError(t, w.Record(operatorContext(), AuditEvent{
		ActorID: "operator-1", ActorTenantID: "acme-corp",
		Action: ActionSecretConfigSet, Effect: EffectAllow,
		ResourceType: "secret_broker_config", ResourceURI: "secret_broker_config:tenant-acme-corp",
		Decision: "allow", Success: true,
	}))
	events := rec.Events()
	require.Len(t, events, 1)
	assert.Equal(t, ActionSecretConfigSet, events[0].Action)
}

// TestAuditWriter_Record_RefusesAPlaintextEvent: the guard refuses the
// event, and the caller gets an error, so it makes no change.
func TestAuditWriter_Record_RefusesAPlaintextEvent(t *testing.T) {
	logger, rec := newRecordingAuditLogger(t)
	w := NewAuditWriter(logger, slog.Default())

	err := w.Record(operatorContext(), AuditEvent{
		ActorTenantID: "acme-corp", Action: ActionSecretConfigSet,
		ResourceURI: string(make([]byte, 300)) + "secret_value",
	})
	require.ErrorIs(t, err, ErrAuditRejected)
	assert.Empty(t, rec.Events())
}

// TestAuditWriter_Record_FailsWithNoActor: a context with no identity gets
// an error, not a record with no actor.
func TestAuditWriter_Record_FailsWithNoActor(t *testing.T) {
	logger, rec := newRecordingAuditLogger(t)
	w := NewAuditWriter(logger, slog.Default())

	err := w.Record(context.Background(), AuditEvent{ActorTenantID: "acme-corp", Action: ActionSecretConfigSet})
	require.ErrorIs(t, err, audit.ErrNoActor)
	assert.Empty(t, rec.Events())
}
