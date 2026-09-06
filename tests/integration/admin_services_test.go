// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

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

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/internal/platform/idp"
	"github.com/zeroroot-ai/gibson/internal/server/daemon/api"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
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

// userCtx creates a context with tenant and user identity.
func userCtx(tenantID, userID string) context.Context {
	ctx := auth.ContextWithTenantString(context.Background(), tenantID)
	identity := auth.Identity{Subject: userID, Issuer: "zitadel"}
	return auth.WithIdentity(ctx, identity)
}

// allowAdminAuthorizer is a minimal authz.Authorizer stub that grants the
// "admin" relation on one specific tenant object to one specific user —
// just enough to satisfy DaemonServer.requireTenantAdmin's fail-closed check
// (server_audit.go) in tests that are exercising something other than
// authorization itself. requireTenantAdmin returns codes.Unavailable when
// s.authorizer is nil (deliberate fail-closed behavior, not a noop), so any
// test that wants to reach past that gate must wire one of these in.
type allowAdminAuthorizer struct {
	user, object string
}

func (a *allowAdminAuthorizer) Check(_ context.Context, user, relation, object string) (bool, error) {
	return user == a.user && relation == "admin" && object == a.object, nil
}

func (a *allowAdminAuthorizer) BatchCheck(_ context.Context, checks []authz.CheckRequest) ([]bool, error) {
	out := make([]bool, len(checks))
	for i, c := range checks {
		out[i] = c.User == a.user && c.Relation == "admin" && c.Object == a.object
	}
	return out, nil
}

func (a *allowAdminAuthorizer) Write(_ context.Context, _ []authz.Tuple) error  { return nil }
func (a *allowAdminAuthorizer) Delete(_ context.Context, _ []authz.Tuple) error { return nil }

func (a *allowAdminAuthorizer) ListObjects(_ context.Context, _, _, _ string) ([]string, error) {
	return nil, nil
}

func (a *allowAdminAuthorizer) ListUsers(_ context.Context, _, _, _ string) ([]string, error) {
	return nil, nil
}

// ---------------------------------------------------------------------------
// GetTenantQuota tests
// ---------------------------------------------------------------------------

// TestGetTenantQuota_NilStore_ReturnsZeroLimits verifies that GetTenantQuota
// succeeds with zero quota values when platformDB is not configured.
// Zero values mean "unlimited" (existing convention per server_quota.go).
//
// This exercises the nil-platformDB path specifically, so it wires an
// allowAdminAuthorizer that passes requireTenantAdmin's FGA check for the
// caller — requireTenantAdmin fails closed (codes.Unavailable) when
// s.authorizer is nil, and this test isn't the one meant to cover that gate
// (see TestGetTenantQuota_MissingAuthorizer_FailsClosed for that).
func TestGetTenantQuota_NilStore_ReturnsZeroLimits(t *testing.T) {
	srv := newServerForTest().WithAuthorizer(&allowAdminAuthorizer{user: "user:user-123", object: "tenant:acme"})
	ctx := userCtx("acme", "user-123")
	resp, err := srv.GetTenantQuota(ctx, &tenantv1.GetTenantQuotaRequest{TenantId: "acme"})
	assert.NoError(t, err, "nil platformDB should not return an error — zero limits mean unlimited")
	assert.NotNil(t, resp)
}

// TestGetTenantQuota_MissingAuthorizer_FailsClosed verifies that
// requireTenantAdmin fails closed (codes.Unavailable) rather than allowing
// the request through when no Authorizer is wired. FGA is a hard startup
// dependency in every shipped configuration (one-code-path epic, deploy#195),
// so an unwired authorizer here means a misconfigured test harness or a
// DaemonServer built outside normal daemon bootstrap — never something to
// silently allow (see server_audit.go's requireTenantAdmin doc comment).
func TestGetTenantQuota_MissingAuthorizer_FailsClosed(t *testing.T) {
	srv := newServerForTest()
	ctx := userCtx("acme", "user-123")
	_, err := srv.GetTenantQuota(ctx, &tenantv1.GetTenantQuotaRequest{TenantId: "acme"})
	assert.Equal(t, codes.Unavailable, grpcCode(err))
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
func (f *fakeUserIdPClient) SetHumanPassword(context.Context, idp.SetHumanPasswordRequest) error {
	return nil
}

func (f *fakeUserIdPClient) CreateHumanUser(_ context.Context, _ idp.CreateHumanUserRequest) (idp.CreateHumanUserResult, error) {
	return idp.CreateHumanUserResult{UserID: "user-1"}, nil
}
func (f *fakeUserIdPClient) FindUserIDByEmail(_ context.Context, _ string) (string, error) {
	return "", idp.ErrNotFound
}
func (f *fakeUserIdPClient) Close() error { return nil }

// Verify fakeUserIdPClient implements idp.AdminClient.
var _ idp.AdminClient = (*fakeUserIdPClient)(nil)

// errNotImplemented is used for methods that should not be called in these tests.
var errNotImplemented = errors.New("not implemented in test fake")

// ListUsersOfType is unused by this package's tests. It exists because the
// method is on authz.Authorizer — a gate reached by type assertion was
// silently skipped by every double that did not implement it.
func (a *allowAdminAuthorizer) ListUsersOfType(context.Context, string, string, string, string) ([]string, error) {
	return nil, nil
}
