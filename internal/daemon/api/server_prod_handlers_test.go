package api

// server_prod_handlers_test.go contains unit tests for the 8 new handler
// methods added by the prod-unimplemented-apis spec.
//
// Strategy:
//   - Input validation cases verify codes.InvalidArgument for missing
//     required fields.
//   - The user/session/profile RPCs now delegate to the dashboard layer
//     (Better Auth) and return codes.Unimplemented for the mutation paths
//     they have not yet been rewired for. See the per-RPC comments below.
//   - Nil-store cases verify codes.Unavailable when a mission / findings
//     store is not wired.
//   - Success cases use lightweight mock helpers where applicable.

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zero-day-ai/gibson/internal/missiondraft"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

var testSlogLogger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

// blankServer returns a DaemonServer with no external dependencies wired.
// It is only suitable for testing input validation and nil-store branches.
func blankServer() *DaemonServer {
	return &DaemonServer{
		logger: testSlogLogger,
	}
}

func grpcCode(err error) codes.Code {
	if err == nil {
		return codes.OK
	}
	s, _ := status.FromError(err)
	return s.Code()
}

// ---------------------------------------------------------------------------
// mockMissionDraftStore satisfies the missionDraftStore field type.
// ---------------------------------------------------------------------------

type mockDraftStore struct {
	saveErr    error
	savedID    string
	listErr    error
	listDrafts []*missiondraft.MissionDraft
}

func (m *mockDraftStore) Save(ctx context.Context, tenantID, name, yaml, draftID string) (string, error) {
	if m.saveErr != nil {
		return "", m.saveErr
	}
	if m.savedID != "" {
		return m.savedID, nil
	}
	return "draft-abc", nil
}

func (m *mockDraftStore) List(ctx context.Context, tenantID string) ([]*missiondraft.MissionDraft, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	return m.listDrafts, nil
}

// ---------------------------------------------------------------------------
// mockImpersonationIssuer
// ---------------------------------------------------------------------------

type mockImpersonationIssuer struct {
	token string
	err   error
}

func (m *mockImpersonationIssuer) IssueToken(_ context.Context, _ string) (string, error) {
	return m.token, m.err
}

// ---------------------------------------------------------------------------
// ResetPassword tests
// ---------------------------------------------------------------------------

func TestResetPassword_MissingEmail_InvalidArgument(t *testing.T) {
	srv := blankServer()
	_, err := srv.ResetPassword(context.Background(), &ResetPasswordRequest{Email: ""})
	assert.Equal(t, codes.InvalidArgument, grpcCode(err))
}

func TestResetPassword_ReturnsSuccess(t *testing.T) {
	// Handler always returns Success=true to prevent email enumeration. The
	// actual reset flow is handled by Better Auth in the dashboard.
	srv := blankServer()
	resp, err := srv.ResetPassword(context.Background(), &ResetPasswordRequest{Email: "user@example.com"})
	require.NoError(t, err)
	assert.True(t, resp.Success, "must return success=true regardless of backend")
}

// ---------------------------------------------------------------------------
// RevokeUserSessions tests
// ---------------------------------------------------------------------------

func TestRevokeUserSessions_MissingTenantID_InvalidArgument(t *testing.T) {
	srv := blankServer()
	_, err := srv.RevokeUserSessions(context.Background(), &RevokeUserSessionsRequest{
		TenantId: "",
		UserId:   "user-1",
	})
	assert.Equal(t, codes.InvalidArgument, grpcCode(err))
}

func TestRevokeUserSessions_MissingUserID_InvalidArgument(t *testing.T) {
	srv := blankServer()
	_, err := srv.RevokeUserSessions(context.Background(), &RevokeUserSessionsRequest{
		TenantId: "tenant-1",
		UserId:   "",
	})
	assert.Equal(t, codes.InvalidArgument, grpcCode(err))
}

func TestRevokeUserSessions_Unimplemented(t *testing.T) {
	// Session revocation moved to the dashboard layer (Better Auth); handler
	// returns Unimplemented after validating required fields.
	srv := blankServer()
	_, err := srv.RevokeUserSessions(context.Background(), &RevokeUserSessionsRequest{
		TenantId: "tenant-1",
		UserId:   "user-1",
	})
	assert.Equal(t, codes.Unimplemented, grpcCode(err))
}

// ---------------------------------------------------------------------------
// SuspendMember tests
// ---------------------------------------------------------------------------

func TestSuspendMember_MissingTenantID_InvalidArgument(t *testing.T) {
	srv := blankServer()
	_, err := srv.SuspendMember(context.Background(), &SuspendMemberRequest{
		TenantId: "",
		UserId:   "user-1",
		Suspend:  true,
	})
	assert.Equal(t, codes.InvalidArgument, grpcCode(err))
}

func TestSuspendMember_MissingUserID_InvalidArgument(t *testing.T) {
	srv := blankServer()
	_, err := srv.SuspendMember(context.Background(), &SuspendMemberRequest{
		TenantId: "tenant-1",
		UserId:   "",
		Suspend:  true,
	})
	assert.Equal(t, codes.InvalidArgument, grpcCode(err))
}

func TestSuspendMember_NoAuthorizer_SucceedsWithoutFGATupleChange(t *testing.T) {
	// SuspendMember manages only the FGA member tuple — the user account
	// itself is disabled by Better Auth in the dashboard. With no authorizer
	// wired, the handler still succeeds and returns the new status string
	// (the authorizer block is a no-op when s.authorizer is nil).
	srv := blankServer()
	resp, err := srv.SuspendMember(context.Background(), &SuspendMemberRequest{
		TenantId: "tenant-1",
		UserId:   "user-1",
		Suspend:  true,
	})
	require.NoError(t, err)
	assert.Equal(t, "suspended", resp.NewStatus)
}

// ---------------------------------------------------------------------------
// GetUserProfile tests
// ---------------------------------------------------------------------------

func TestGetUserProfile_MissingTenantID_InvalidArgument(t *testing.T) {
	srv := blankServer()
	_, err := srv.GetUserProfile(context.Background(), &GetUserProfileRequest{TenantId: "", UserId: "u1"})
	assert.Equal(t, codes.InvalidArgument, grpcCode(err))
}

func TestGetUserProfile_MissingUserID_InvalidArgument(t *testing.T) {
	srv := blankServer()
	_, err := srv.GetUserProfile(context.Background(), &GetUserProfileRequest{TenantId: "t1", UserId: ""})
	assert.Equal(t, codes.InvalidArgument, grpcCode(err))
}

func TestGetUserProfile_Unimplemented(t *testing.T) {
	// Profile management moved to the dashboard layer (Better Auth).
	srv := blankServer()
	_, err := srv.GetUserProfile(context.Background(), &GetUserProfileRequest{TenantId: "t1", UserId: "u1"})
	assert.Equal(t, codes.Unimplemented, grpcCode(err))
}

// ---------------------------------------------------------------------------
// UpdateUserProfile tests
// ---------------------------------------------------------------------------

func TestUpdateUserProfile_MissingTenantID_InvalidArgument(t *testing.T) {
	srv := blankServer()
	_, err := srv.UpdateUserProfile(context.Background(), &UpdateUserProfileRequest{TenantId: "", UserId: "u1"})
	assert.Equal(t, codes.InvalidArgument, grpcCode(err))
}

func TestUpdateUserProfile_Unimplemented(t *testing.T) {
	// Profile management moved to the dashboard layer (Better Auth).
	srv := blankServer()
	_, err := srv.UpdateUserProfile(context.Background(), &UpdateUserProfileRequest{TenantId: "t1", UserId: "u1"})
	assert.Equal(t, codes.Unimplemented, grpcCode(err))
}

// ---------------------------------------------------------------------------
// ExportFindings tests
// ---------------------------------------------------------------------------

func TestExportFindings_MissingTenantID_InvalidArgument(t *testing.T) {
	srv := blankServer()
	_, err := srv.ExportFindings(context.Background(), &ExportFindingsRequest{TenantId: ""})
	assert.Equal(t, codes.InvalidArgument, grpcCode(err))
}

func TestExportFindings_NilFindingStore_Unavailable(t *testing.T) {
	srv := blankServer()
	_, err := srv.ExportFindings(context.Background(), &ExportFindingsRequest{TenantId: "t1"})
	assert.Equal(t, codes.Unavailable, grpcCode(err))
}

// ---------------------------------------------------------------------------
// SaveMissionDraft tests
// ---------------------------------------------------------------------------

func TestSaveMissionDraft_MissingTenantID_InvalidArgument(t *testing.T) {
	srv := blankServer()
	_, err := srv.SaveMissionDraft(context.Background(), &SaveMissionDraftRequest{
		TenantId: "", Name: "draft", Yaml: "name: x",
	})
	assert.Equal(t, codes.InvalidArgument, grpcCode(err))
}

func TestSaveMissionDraft_MissingName_InvalidArgument(t *testing.T) {
	srv := blankServer()
	_, err := srv.SaveMissionDraft(context.Background(), &SaveMissionDraftRequest{
		TenantId: "t1", Name: "", Yaml: "name: x",
	})
	assert.Equal(t, codes.InvalidArgument, grpcCode(err))
}

func TestSaveMissionDraft_YAMLTooLarge_InvalidArgument(t *testing.T) {
	srv := blankServer()
	bigYAML := strings.Repeat("x", 512*1024+1)
	_, err := srv.SaveMissionDraft(context.Background(), &SaveMissionDraftRequest{
		TenantId: "t1", Name: "big", Yaml: bigYAML,
	})
	assert.Equal(t, codes.InvalidArgument, grpcCode(err))
}

func TestSaveMissionDraft_NilStore_Unavailable(t *testing.T) {
	srv := blankServer()
	_, err := srv.SaveMissionDraft(context.Background(), &SaveMissionDraftRequest{
		TenantId: "t1", Name: "draft", Yaml: "name: x",
	})
	assert.Equal(t, codes.Unavailable, grpcCode(err))
}

func TestSaveMissionDraft_Success(t *testing.T) {
	srv := blankServer()
	srv.missionDraftStore = &mockDraftStore{savedID: "draft-123"}

	resp, err := srv.SaveMissionDraft(context.Background(), &SaveMissionDraftRequest{
		TenantId: "t1", Name: "My Draft", Yaml: "name: hello",
	})
	require.NoError(t, err)
	assert.Equal(t, "draft-123", resp.DraftId)
}

// ---------------------------------------------------------------------------
// ListMissionDrafts tests
// ---------------------------------------------------------------------------

func TestListMissionDrafts_MissingTenantID_InvalidArgument(t *testing.T) {
	srv := blankServer()
	_, err := srv.ListMissionDrafts(context.Background(), &ListMissionDraftsRequest{TenantId: ""})
	assert.Equal(t, codes.InvalidArgument, grpcCode(err))
}

func TestListMissionDrafts_NilStore_Unavailable(t *testing.T) {
	srv := blankServer()
	_, err := srv.ListMissionDrafts(context.Background(), &ListMissionDraftsRequest{TenantId: "t1"})
	assert.Equal(t, codes.Unavailable, grpcCode(err))
}

func TestListMissionDrafts_Success(t *testing.T) {
	srv := blankServer()
	srv.missionDraftStore = &mockDraftStore{
		listDrafts: []*missiondraft.MissionDraft{
			{ID: "d1", Name: "Draft One", CreatedAt: "2026-01-01T00:00:00Z", UpdatedAt: "2026-01-01T00:00:00Z"},
		},
	}

	resp, err := srv.ListMissionDrafts(context.Background(), &ListMissionDraftsRequest{TenantId: "t1"})
	require.NoError(t, err)
	require.Len(t, resp.Drafts, 1)
	assert.Equal(t, "d1", resp.Drafts[0].Id)
	assert.Equal(t, "Draft One", resp.Drafts[0].Name)
}
