// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/engine/state"
	"github.com/zeroroot-ai/gibson/internal/platform/audit"
	"github.com/zeroroot-ai/gibson/internal/platform/audit/audittest"
	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
	"github.com/zeroroot-ai/sdk/auth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// refusingWriter is a durable writer whose synchronous write fails.
type refusingWriter struct{ audittest.Recorder }

func (*refusingWriter) WriteSync(context.Context, audit.Event) error {
	return errors.New("audit database down")
}

func newPluginAuditLogger(t *testing.T, durable audit.DurableWriter) *audit.AuditLogger {
	t.Helper()
	mr := miniredis.RunT(t)
	cfg := state.DefaultConfig()
	cfg.URL = "redis://" + mr.Addr()
	sc, err := state.NewStateClient(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sc.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return audit.NewAuditLogger(ctx, sc, durable, slog.New(slog.DiscardHandler))
}

func adminCtx(t *testing.T) context.Context {
	t.Helper()
	tid, err := auth.NewTenantID("tenant-a")
	require.NoError(t, err)
	return auth.WithIdentity(auth.ContextWithTenantString(context.Background(), "tenant-a"),
		auth.Identity{Subject: "admin-1", Issuer: auth.IssuerOIDC, Tenant: tid})
}

// A plugin change whose audit record is not durable does not happen
// (gibson#676).
func TestPluginChange_AuditFailureChangesNothing(t *testing.T) {
	store, _ := newTestComponentAccessStore(t)
	srv := accessServer(store)
	srv.auditLog = newPluginAuditLogger(t, &refusingWriter{})
	ctx := adminCtx(t)

	_, err := srv.EnablePlugin(ctx, &componentpb.EnablePluginRequest{PluginName: "gitlab"})
	require.Error(t, err)
	assert.Equal(t, codes.Unavailable, status.Code(err))

	_, err = store.GetAccess(ctx, "tenant-a", "gitlab")
	assert.ErrorIs(t, err, ErrComponentNotEnabled, "the plugin must not be enabled")
}

// Each plugin change writes its record before the change, and a failed
// change writes a second record with the result "failure".
func TestPluginChange_RecordsFirstAndRecordsAFailure(t *testing.T) {
	store, _ := newTestComponentAccessStore(t)
	srv := accessServer(store)
	rec := &audittest.Recorder{}
	srv.auditLog = newPluginAuditLogger(t, rec)
	ctx := adminCtx(t)

	_, err := srv.EnablePlugin(ctx, &componentpb.EnablePluginRequest{PluginName: "gitlab"})
	require.NoError(t, err)
	_, err = srv.UpdatePluginConfig(ctx, &componentpb.UpdatePluginConfigRequest{PluginName: "jira", ConfigJson: `{"a":1}`})
	require.Error(t, err, "jira is not enabled")
	_, err = srv.DisablePlugin(ctx, &componentpb.DisablePluginRequest{PluginName: "gitlab"})
	require.NoError(t, err)

	events := rec.Events()
	actions := make([]string, 0, len(events))
	for _, ev := range events {
		actions = append(actions, ev.Action)
	}
	assert.Equal(t, []string{"plugin.enable", "plugin.config.update", "plugin.config.update", "plugin.disable"}, actions)
	assert.Contains(t, string(events[2].Metadata), "failure", "the second record names the failure")
}

// A server with no audit logger refuses a plugin change. It never changes
// state with no record (gibson#676).
func TestPluginChange_NoAuditLoggerRefuses(t *testing.T) {
	store, _ := newTestComponentAccessStore(t)
	srv := accessServer(store)
	ctx := adminCtx(t)

	_, err := srv.EnablePlugin(ctx, &componentpb.EnablePluginRequest{PluginName: "gitlab"})
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	_, err = store.GetAccess(ctx, "tenant-a", "gitlab")
	assert.ErrorIs(t, err, ErrComponentNotEnabled)
}
