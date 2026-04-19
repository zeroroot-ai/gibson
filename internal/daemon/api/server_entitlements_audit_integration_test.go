//go:build integration

package api

// server_entitlements_audit_integration_test.go — end-to-end test of the
// audit-emission path exercised by WriteAccessTuples.
//
// Spec: access-matrix-finish task 26, R6 AC 1-3, 9.
//
// Approach: call emitAccessTupleChange through a real AuditLogger backed by
// miniredis (same pattern used by internal/audit/logger_test.go), then read
// the tenant's audit Redis stream via AuditLogger.Query and assert the
// event's shape.
//
// Run with:
//   go test -tags integration -run TestAuditEmission ./internal/daemon/api/...

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/require"

	sdkauth "github.com/zero-day-ai/sdk/auth"

	"github.com/zero-day-ai/gibson/internal/audit"
	"github.com/zero-day-ai/gibson/internal/auth"
	"github.com/zero-day-ai/gibson/internal/state"
)

func TestAuditEmission_AccessTupleChange_EndToEnd(t *testing.T) {
	mr := miniredis.RunT(t)

	cfg := state.DefaultConfig()
	cfg.URL = "redis://" + mr.Addr()
	stateClient, err := state.NewStateClient(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = stateClient.Close() })

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))
	al := audit.NewAuditLogger(stateClient, logger)

	// Identity: tenant admin via API key → classifyActorSource → "tenant_admin".
	ident := &auth.Identity{
		Identity: sdkauth.Identity{Subject: "gsk_test", Issuer: "apikey"},
	}
	ctx := auth.ContextWithIdentity(context.Background(), ident)
	ctx = auth.ContextWithTenant(ctx, "acme")

	tuple := struct{ User, Relation, Object string }{
		User:     "team:acme-red#member",
		Relation: "team_execute_disabled",
		Object:   "component:plugin/gitlab",
	}
	emitAccessTupleChange(ctx, al, "tenant_admin", tuple, "write", "dashboard: team execute deny")

	deadline := time.Now().Add(5 * time.Second)
	for {
		entries, err := al.Query(ctx, "acme", audit.AuditQueryOptions{Limit: 10})
		require.NoError(t, err)
		for _, e := range entries {
			if e.Action == "access_tuple_change" {
				require.Equal(t, "component:plugin/gitlab", e.ResourceID)
				require.Equal(t, "component", e.Resource)
				// Details is a map[string]any persisted verbatim.
				require.Equal(t, "execute", e.Details["action_class"])
				require.Equal(t, "team", e.Details["scope_type"])
				require.Equal(t, "write", e.Details["operation"])
				require.Equal(t, "tenant_admin", e.Details["actor_source"])
				require.Equal(t,
					"team:acme-red#member#team_execute_disabled@component:plugin/gitlab",
					e.Details["tuple"],
				)
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no access_tuple_change event within 5s (have %d entries)", len(entries))
		}
		time.Sleep(100 * time.Millisecond)
	}
}
