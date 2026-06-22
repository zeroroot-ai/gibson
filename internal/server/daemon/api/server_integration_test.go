//go:build integration

package api

// server_integration_test.go — integration smoke tests for the eight new
// RPCs introduced by the prod-unimplemented-apis spec.
//
// Purpose:
//   Each test constructs a DaemonServer with all new stores wired (using
//   miniredis in-process for Redis-backed stores and lightweight mock
//   implementations for identity operations), then calls the RPC with minimal
//   valid input and asserts the result is NOT codes.Unimplemented and NOT
//   codes.Unavailable.
//
//   This catches the class of bug where a WithXxx option was added to
//   DaemonServer but the corresponding With* call was omitted at daemon startup.
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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/finding"
	"github.com/zeroroot-ai/gibson/internal/engine/missiondraft"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

var integTestLogger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

// newIntegServer builds a DaemonServer with all new stores wired using miniredis.
// The user/session/profile RPCs currently delegate to the dashboard layer
// (Better Auth) and return Unimplemented for the mutation paths; this helper
// exists to verify the non-user-admin RPCs (mission drafts, findings export)
// are properly wired.
func newIntegServer(t *testing.T) *DaemonServer {
	t.Helper()
	mr := miniredis.RunT(t)
	client := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	draftStore := missiondraft.New(client, integTestLogger)

	srv := &DaemonServer{logger: integTestLogger}
	srv.WithMissionDraftStore(draftStore)
	srv.WithFindingStore(&integMockFindingStore{})
	return srv
}

// grpcCodeOf extracts the gRPC status code from an error.
func grpcCodeOf(err error) codes.Code {
	if err == nil {
		return codes.OK
	}
	s, _ := status.FromError(err)
	return s.Code()
}

// notUnimplementedNotUnavailable asserts that the given error is neither
// codes.Unimplemented nor codes.Unavailable.
func notUnimplementedNotUnavailable(t *testing.T, name string, err error) {
	t.Helper()
	if err != nil {
		c := grpcCodeOf(err)
		assert.NotEqual(t, codes.Unimplemented, c,
			"%s: RPC must not return Unimplemented (store not wired)", name)
		assert.NotEqual(t, codes.Unavailable, c,
			"%s: RPC must not return Unavailable (store wired but not reachable)", name)
	}
}

// ---------------------------------------------------------------------------
// integMockFindingStore satisfies findingStoreIface with an empty result.
// ---------------------------------------------------------------------------

type integMockFindingStore struct{}

func (f *integMockFindingStore) List(_ context.Context, _ types.ID, _ *finding.FindingFilter) ([]finding.EnhancedFinding, error) {
	return []finding.EnhancedFinding{}, nil
}

// ---------------------------------------------------------------------------
// TestNewRPCsNotUnimplemented
// ---------------------------------------------------------------------------

// TestNewRPCsNotUnimplemented verifies that all eight new RPCs are wired and
// execute at least past the dependency check, returning neither Unimplemented
// nor Unavailable.
func TestNewRPCsNotUnimplemented(t *testing.T) {
	ctx := context.Background()

	// ResetPassword: handler always returns success (Better Auth in the
	// dashboard handles the actual reset); no backend dependency in the
	// daemon. Only way to get Unimplemented is if the handler is unregistered.
	t.Run("ResetPassword", func(t *testing.T) {
		srv := newIntegServer(t)
		resp, err := srv.ResetPassword(ctx, &ResetPasswordRequest{Email: "test@example.com"})
		require.NoError(t, err)
		assert.True(t, resp.Success)
	})

	// RevokeUserSessions: currently returns Unimplemented because session
	// management has moved to the dashboard layer (Better Auth). The test
	// below is retained as a marker until the dashboard-backed implementation
	// lands.
	t.Run("RevokeUserSessions", func(t *testing.T) {
		srv := newIntegServer(t)
		_, err := srv.RevokeUserSessions(ctx, &RevokeUserSessionsRequest{
			TenantId: "tenant-1", UserId: "user-1",
		})
		// Accept any code except Unimplemented; the store wiring path is reached.
		if err != nil {
			c := grpcCodeOf(err)
			assert.NotEqual(t, codes.Unimplemented, c, "RevokeUserSessions must not return Unimplemented")
		}
	})

	// SuspendMember: manages only the FGA member tuple — the user account
	// itself is disabled by Better Auth in the dashboard. Must not return
	// Unimplemented.
	t.Run("SuspendMember", func(t *testing.T) {
		srv := newIntegServer(t)
		_, err := srv.SuspendMember(ctx, &SuspendMemberRequest{
			TenantId: "tenant-1", UserId: "user-1", Suspend: true,
		})
		if err != nil {
			c := grpcCodeOf(err)
			assert.NotEqual(t, codes.Unimplemented, c, "SuspendMember must not return Unimplemented")
		}
	})

	// GetUserProfile: currently returns Unimplemented pending dashboard-backed impl.
	t.Run("GetUserProfile", func(t *testing.T) {
		srv := newIntegServer(t)
		_, err := srv.GetUserProfile(ctx, &GetUserProfileRequest{TenantId: "t1", UserId: "u1"})
		require.Error(t, err)
		assert.NotEqual(t, codes.Unimplemented, grpcCodeOf(err))
	})

	// UpdateUserProfile: same as GetUserProfile.
	t.Run("UpdateUserProfile", func(t *testing.T) {
		srv := newIntegServer(t)
		_, err := srv.UpdateUserProfile(ctx, &UpdateUserProfileRequest{TenantId: "t1", UserId: "u1"})
		require.Error(t, err)
		assert.NotEqual(t, codes.Unimplemented, grpcCodeOf(err))
	})

	// ExportFindings: findingStore is wired via integMockFindingStore —
	// should return OK (empty CSV/JSON).
	t.Run("ExportFindings", func(t *testing.T) {
		srv := newIntegServer(t)
		resp, err := srv.ExportFindings(ctx, &ExportFindingsRequest{TenantId: "tenant-1"})
		// Must not be Unimplemented or Unavailable; empty result is acceptable.
		notUnimplementedNotUnavailable(t, "ExportFindings", err)
		if err == nil {
			assert.NotNil(t, resp)
		}
	})

	// SaveMissionDraft: missionDraftStore wired → should create and return
	// a new draft ID.
	t.Run("SaveMissionDraft", func(t *testing.T) {
		srv := newIntegServer(t)
		resp, err := srv.SaveMissionDraft(ctx, &SaveMissionDraftRequest{
			TenantId: "tenant-1", Name: "Smoke Draft", Yaml: "name: smoke",
		})
		require.NoError(t, err, "SaveMissionDraft must succeed when store is wired")
		assert.NotEmpty(t, resp.DraftId)
	})

	// ListMissionDrafts: should return empty list (no drafts saved yet in
	// the fresh miniredis instance).
	t.Run("ListMissionDrafts", func(t *testing.T) {
		srv := newIntegServer(t)
		resp, err := srv.ListMissionDrafts(ctx, &ListMissionDraftsRequest{TenantId: "tenant-1"})
		require.NoError(t, err, "ListMissionDrafts must succeed when store is wired")
		assert.NotNil(t, resp.Drafts)
	})
}
