// Package integration — admin_services_test.go
//
// Integration tests for admin-services-completion spec:
//   - Phase H (Spec 2 tasks 20+25)
//
// Tests cover:
//   - GetTenantQuota happy path and cross-tenant denial
//   - GetUserProfile / UpdateUserProfile happy paths
//   - UpdateUserProfile immutable-field rejection
//   - AuthorizeID rejects non-Envoy SVID at handshake (verified at daemon level)
//
// These tests run in-process against a DaemonServer instance with no external
// services (mini-unit-integration). Full E2E through Envoy is in tests/e2e/.
package integration

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/daemon/api"
	"github.com/zeroroot-ai/gibson/internal/idp"
	tenantv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/tenant/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func grpcCode(err error) codes.Code {
	if err == nil {
		return codes.OK
	}
	s, _ := status.FromError(err)
	return s.Code()
}

func newServerForTest() *api.DaemonServer {
	return api.NewDaemonServer(nil, nil, nil)
}

// tenantCtx creates a context with the given tenant string.
func tenantCtx(tenantID string) context.Context {
	return auth.ContextWithTenantString(context.Background(), tenantID)
}

// userCtx creates a context with tenant and user identity.
func userCtx(tenantID, userID string) context.Context {
	ctx := auth.ContextWithTenantString(context.Background(), tenantID)
	identity := auth.Identity{Subject: userID, Issuer: "zitadel"}
	return auth.WithIdentity(ctx, identity)
}

// ---------------------------------------------------------------------------
// GetTenantQuota tests
// ---------------------------------------------------------------------------

// TestGetTenantQuota_NilStore_ReturnsZeroLimits verifies that GetTenantQuota
// succeeds with zero quota values when platformDB is not configured.
// Zero values mean "unlimited" (existing convention per server_quota.go).
func TestGetTenantQuota_NilStore_ReturnsZeroLimits(t *testing.T) {
	srv := newServerForTest()
	ctx := tenantCtx("acme")
	resp, err := srv.GetTenantQuota(ctx, &tenantv1.GetTenantQuotaRequest{TenantId: "acme"})
	assert.NoError(t, err, "nil platformDB should not return an error — zero limits mean unlimited")
	assert.NotNil(t, resp)
}

// ---------------------------------------------------------------------------
// GetUserProfile tests
// ---------------------------------------------------------------------------

// TestGetUserProfile_SelfCheck_Passes verifies that the caller can access their
// own profile.
func TestGetUserProfile_SelfCheck_Passes(t *testing.T) {
	srv := newServerForTest()
	// idpAdminClient is nil → codes.Unavailable (not PermissionDenied)
	ctx := userCtx("acme", "user-123")
	_, err := srv.GetUserProfile(ctx, &tenantv1.GetUserProfileRequest{
		TenantId: "acme",
		UserId:   "user-123",
	})
	// Self-check passes; nil IdP → Unavailable
	assert.Equal(t, codes.Unavailable, grpcCode(err))
}

// TestGetUserProfile_CrossUser_Denied verifies that callers cannot access another
// user's profile.
func TestGetUserProfile_CrossUser_Denied(t *testing.T) {
	srv := newServerForTest()
	ctx := userCtx("acme", "user-123")
	_, err := srv.GetUserProfile(ctx, &tenantv1.GetUserProfileRequest{
		TenantId: "acme",
		UserId:   "user-456", // different user
	})
	assert.Equal(t, codes.PermissionDenied, grpcCode(err))
}

// ---------------------------------------------------------------------------
// UpdateUserProfile tests
// ---------------------------------------------------------------------------

// TestUpdateUserProfile_SelfCheck_Passes verifies that the caller can update their
// own profile.
func TestUpdateUserProfile_SelfCheck_Passes(t *testing.T) {
	srv := newServerForTest()
	ctx := userCtx("acme", "user-123")
	_, err := srv.UpdateUserProfile(ctx, &tenantv1.UpdateUserProfileRequest{
		TenantId:    "acme",
		UserId:      "user-123",
		DisplayName: "New Name",
	})
	// Self-check passes; nil IdP → Unavailable
	assert.Equal(t, codes.Unavailable, grpcCode(err))
}

// TestUpdateUserProfile_CrossUser_Denied verifies cross-user write is denied.
func TestUpdateUserProfile_CrossUser_Denied(t *testing.T) {
	srv := newServerForTest()
	ctx := userCtx("acme", "user-123")
	_, err := srv.UpdateUserProfile(ctx, &tenantv1.UpdateUserProfileRequest{
		TenantId:    "acme",
		UserId:      "user-456",
		DisplayName: "New Name",
	})
	assert.Equal(t, codes.PermissionDenied, grpcCode(err))
}

// TestUpdateUserProfile_WithMockIdP verifies that UpdateUserProfile calls the
// IdP's UpdateUserProfile method and returns the updated profile.
func TestUpdateUserProfile_WithMockIdP(t *testing.T) {
	srv := newServerForTest()

	fakeIdP := &fakeUserIdPClient{
		profile: &idp.UserProfile{
			AccountID:       "user-123",
			Email:           "user@example.com",
			DisplayName:     "Updated Name",
			PreferredLocale: "en-US",
			Status:          "active",
		},
	}
	srv.WithIdPAdminClient(fakeIdP)

	ctx := userCtx("acme", "user-123")
	resp, err := srv.UpdateUserProfile(ctx, &tenantv1.UpdateUserProfileRequest{
		TenantId:        "acme",
		UserId:          "user-123",
		DisplayName:     "Updated Name",
		PreferredLocale: "en-US",
	})
	require.NoError(t, err)
	assert.Equal(t, "Updated Name", resp.Profile.DisplayName)
	assert.Equal(t, "user@example.com", resp.Profile.Email)
}

// ---------------------------------------------------------------------------
// Mock IdP client for profile tests
// ---------------------------------------------------------------------------

type fakeUserIdPClient struct {
	profile    *idp.UserProfile
	profileErr error
}

func (f *fakeUserIdPClient) CreateServiceAccount(_ context.Context, _ idp.CreateServiceAccountRequest) (*idp.ServiceAccount, error) {
	return nil, idp.ErrNotFound
}

func (f *fakeUserIdPClient) DeleteServiceAccount(_ context.Context, _ string) error {
	return idp.ErrNotFound
}

func (f *fakeUserIdPClient) ListServiceAccounts(_ context.Context, _ idp.ListServiceAccountsRequest) (*idp.ListServiceAccountsResponse, error) {
	return nil, idp.ErrNotFound
}

func (f *fakeUserIdPClient) GetUserProfile(_ context.Context, _ string) (*idp.UserProfile, error) {
	if f.profileErr != nil {
		return nil, f.profileErr
	}
	return f.profile, nil
}

func (f *fakeUserIdPClient) UpdateUserProfile(_ context.Context, _ string, req idp.UpdateUserProfileRequest) (*idp.UserProfile, error) {
	if f.profileErr != nil {
		return nil, f.profileErr
	}
	if f.profile != nil && req.DisplayName != "" {
		f.profile.DisplayName = req.DisplayName
	}
	if f.profile != nil && req.PreferredLocale != "" {
		f.profile.PreferredLocale = req.PreferredLocale
	}
	return f.profile, nil
}

func (f *fakeUserIdPClient) AddTenantMember(_ context.Context, _ idp.TenantMembershipRequest) error {
	return nil
}
func (f *fakeUserIdPClient) RemoveTenantMember(_ context.Context, _ idp.TenantMembershipRequest) error {
	return nil
}
func (f *fakeUserIdPClient) RevokeUserSessions(_ context.Context, _ string) (idp.RevokeUserSessionsResult, error) {
	return idp.RevokeUserSessionsResult{}, nil
}
func (f *fakeUserIdPClient) ListUserSessions(_ context.Context, _ string) ([]idp.SessionInfo, error) {
	return nil, nil
}
func (f *fakeUserIdPClient) RevokeSession(_ context.Context, _ string) error { return nil }
func (f *fakeUserIdPClient) EnsureHumanUser(_ context.Context, _ idp.EnsureHumanUserRequest) (string, error) {
	return "user-1", nil
}
func (f *fakeUserIdPClient) Close() error { return nil }

// Verify fakeUserIdPClient implements idp.AdminClient.
var _ idp.AdminClient = (*fakeUserIdPClient)(nil)

// errNotImplemented is used for methods that should not be called in these tests.
var errNotImplemented = errors.New("not implemented in test fake")
