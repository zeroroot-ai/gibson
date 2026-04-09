package authz_test

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/authz"
)

// newTestLogger returns an slog.Logger that writes to a buffer for assertion.
func newTestLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func TestNoopAuthorizer_Check(t *testing.T) {
	noop := authz.NewNoopAuthorizer(slog.Default())

	tests := []struct {
		name     string
		user     string
		relation string
		object   string
	}{
		{"empty strings", "", "", ""},
		{"normal check", "user:alice", "admin", "tenant:acme"},
		{"platform operator", "user:root", "platform_operator", "system_tenant:_system"},
		{"component execute", "user:bob", "can_execute", "component:nmap"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed, err := noop.Check(context.Background(), tt.user, tt.relation, tt.object)
			require.NoError(t, err)
			assert.True(t, allowed, "noopAuthorizer.Check must always return true")
		})
	}
}

func TestNoopAuthorizer_BatchCheck(t *testing.T) {
	noop := authz.NewNoopAuthorizer(slog.Default())

	checks := []authz.CheckRequest{
		{User: "user:alice", Relation: "admin", Object: "tenant:acme"},
		{User: "user:bob", Relation: "member", Object: "tenant:acme"},
		{User: "user:carol", Relation: "platform_operator", Object: "system_tenant:_system"},
	}

	results, err := noop.BatchCheck(context.Background(), checks)
	require.NoError(t, err)
	require.Len(t, results, len(checks), "BatchCheck must return one result per input")
	for i, allowed := range results {
		assert.True(t, allowed, "BatchCheck[%d] must be true in noop mode", i)
	}
}

func TestNoopAuthorizer_BatchCheck_Empty(t *testing.T) {
	noop := authz.NewNoopAuthorizer(slog.Default())

	results, err := noop.BatchCheck(context.Background(), nil)
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestNoopAuthorizer_Write_LogsWarn(t *testing.T) {
	var buf bytes.Buffer
	logger := newTestLogger(&buf)
	noop := authz.NewNoopAuthorizer(logger)

	tuples := []authz.Tuple{
		{User: "user:alice", Relation: "admin", Object: "tenant:acme"},
	}

	err := noop.Write(context.Background(), tuples)
	require.NoError(t, err)

	logOutput := buf.String()
	assert.True(t, strings.Contains(logOutput, "WARN") || strings.Contains(logOutput, "warn"),
		"Write must emit a WARN log, got: %s", logOutput)
	assert.Contains(t, logOutput, "noop", "WARN log must mention noop mode")
}

func TestNoopAuthorizer_Delete_LogsWarn(t *testing.T) {
	var buf bytes.Buffer
	logger := newTestLogger(&buf)
	noop := authz.NewNoopAuthorizer(logger)

	tuples := []authz.Tuple{
		{User: "user:alice", Relation: "admin", Object: "tenant:acme"},
	}

	err := noop.Delete(context.Background(), tuples)
	require.NoError(t, err)

	logOutput := buf.String()
	assert.True(t, strings.Contains(logOutput, "WARN") || strings.Contains(logOutput, "warn"),
		"Delete must emit a WARN log, got: %s", logOutput)
	assert.Contains(t, logOutput, "noop", "WARN log must mention noop mode")
}

func TestNoopAuthorizer_ListObjects(t *testing.T) {
	noop := authz.NewNoopAuthorizer(slog.Default())

	objects, err := noop.ListObjects(context.Background(), "user:alice", "admin", "tenant")
	require.NoError(t, err)
	assert.Empty(t, objects, "ListObjects must return empty slice in noop mode")
}

func TestNoopAuthorizer_ListUsers(t *testing.T) {
	noop := authz.NewNoopAuthorizer(slog.Default())

	users, err := noop.ListUsers(context.Background(), "tenant", "tenant:acme", "admin")
	require.NoError(t, err)
	assert.Empty(t, users, "ListUsers must return empty slice in noop mode")
}

func TestNoopAuthorizer_StoreID(t *testing.T) {
	noop := authz.NewNoopAuthorizer(slog.Default())
	assert.Empty(t, noop.StoreID(), "StoreID must return empty string in noop mode")
}

func TestNoopAuthorizer_ModelID(t *testing.T) {
	noop := authz.NewNoopAuthorizer(slog.Default())
	assert.Empty(t, noop.ModelID(), "ModelID must return empty string in noop mode")
}

func TestNoopAuthorizer_Close(t *testing.T) {
	noop := authz.NewNoopAuthorizer(slog.Default())
	err := noop.Close()
	require.NoError(t, err)
}

func TestNoopAuthorizer_NilLogger(t *testing.T) {
	// Must not panic when logger is nil — defaults to slog.Default()
	noop := authz.NewNoopAuthorizer(nil)
	assert.NotNil(t, noop)

	allowed, err := noop.Check(context.Background(), "user:alice", "admin", "tenant:acme")
	require.NoError(t, err)
	assert.True(t, allowed)
}

// TestNoopAuthorizer_Concurrent verifies concurrent safety.
func TestNoopAuthorizer_Concurrent(t *testing.T) {
	noop := authz.NewNoopAuthorizer(slog.Default())

	const goroutines = 100
	done := make(chan struct{}, goroutines)

	ctx := context.Background()
	for i := 0; i < goroutines; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			_, _ = noop.Check(ctx, "user:alice", "admin", "tenant:acme")
			_, _ = noop.BatchCheck(ctx, []authz.CheckRequest{{User: "user:alice", Relation: "admin", Object: "tenant:acme"}})
			_ = noop.Write(ctx, []authz.Tuple{{User: "user:alice", Relation: "admin", Object: "tenant:acme"}})
			_ = noop.Delete(ctx, []authz.Tuple{{User: "user:alice", Relation: "admin", Object: "tenant:acme"}})
			_, _ = noop.ListObjects(ctx, "user:alice", "admin", "tenant")
			_, _ = noop.ListUsers(ctx, "tenant", "tenant:acme", "admin")
			_ = noop.StoreID()
			_ = noop.ModelID()
		}()
	}

	for i := 0; i < goroutines; i++ {
		<-done
	}
}

// TestNoopAuthorizer_ImplementsInterface ensures the compile-time check passes.
func TestNoopAuthorizer_ImplementsInterface(t *testing.T) {
	var _ authz.Authorizer = authz.NewNoopAuthorizer(nil)
}
