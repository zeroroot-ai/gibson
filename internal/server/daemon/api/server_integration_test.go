//go:build integration

package api

// server_integration_test.go — integration smoke tests for the daemon-local
// tenant RPCs that are wired on DaemonServer.
//
// Purpose:
//   Each test constructs a DaemonServer with the relevant stores wired (using
//   miniredis in-process for Redis-backed stores and a lightweight mock for the
//   finding store), then calls the RPC with minimal valid input and asserts the
//   result is NOT codes.Unimplemented and NOT codes.Unavailable.
//
//   This catches the class of bug where a WithXxx option was added to
//   DaemonServer but the corresponding With* call was omitted at daemon startup.
//
// Scope note:
//   The user/member-admin RPCs that this file once covered (ResetPassword,
//   SuspendMember, GetUserProfile, UpdateUserProfile, RevokeUserSessions) are no
//   longer served by DaemonServer — ResetPassword/SuspendMember were removed, and
//   profile/session management moved to the Zitadel admin client
//   (internal/platform/idp/zitadel/admin.go). ExportFindings also dropped out of
//   this in-process smoke test: it now queries the per-tenant data-plane pool
//   (poolGetter/Neo4j) rather than a wired finding store, so it requires a real
//   data-plane pool to exercise and a no-pool call correctly returns Unavailable.
//   The mission-draft RPCs remain miniredis-testable and are exercised here.
//
// Run with:
//   go test -tags integration -run TestNewRPCsNotUnimplemented ./internal/server/daemon/api/...

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/missiondraft"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

var integTestLogger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

// newIntegServer builds a DaemonServer with the mission-draft store wired using
// miniredis.
func newIntegServer(t *testing.T) *DaemonServer {
	t.Helper()
	mr := miniredis.RunT(t)
	client := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	draftStore := missiondraft.New(client, integTestLogger)

	srv := &DaemonServer{logger: integTestLogger}
	srv.WithMissionDraftStore(draftStore)
	return srv
}

// ---------------------------------------------------------------------------
// TestNewRPCsNotUnimplemented
// ---------------------------------------------------------------------------

// TestNewRPCsNotUnimplemented verifies that the wired tenant RPCs execute at
// least past the dependency check, returning neither Unimplemented nor
// Unavailable.
func TestNewRPCsNotUnimplemented(t *testing.T) {
	ctx := context.Background()

	// SaveMissionDraft: missionDraftStore wired → should create and return
	// a new draft ID.
	t.Run("SaveMissionDraft", func(t *testing.T) {
		srv := newIntegServer(t)
		resp, err := srv.SaveMissionDraft(ctx, &tenantv1.SaveMissionDraftRequest{
			TenantId: "tenant-1", Name: "Smoke Draft", CueSource: "name: smoke",
		})
		require.NoError(t, err, "SaveMissionDraft must succeed when store is wired")
		assert.NotEmpty(t, resp.DraftId)
	})

	// ListMissionDrafts: should return empty list (no drafts saved yet in
	// the fresh miniredis instance).
	t.Run("ListMissionDrafts", func(t *testing.T) {
		srv := newIntegServer(t)
		resp, err := srv.ListMissionDrafts(ctx, &tenantv1.ListMissionDraftsRequest{TenantId: "tenant-1"})
		require.NoError(t, err, "ListMissionDrafts must succeed when store is wired")
		assert.NotNil(t, resp.Drafts)
	})
}
