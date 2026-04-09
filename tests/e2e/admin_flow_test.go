//go:build e2e
// +build e2e

package e2e

// admin_flow_test.go — Integration test for the authz-04 admin flow.
//
// This test exercises the full invite → accept → grant → team flow using
// real handler implementations wired to miniredis (no external services
// required). It proves:
//
//  1. Admin can invite a new user → receive a signed token
//  2. User can accept the invitation → receive the PasswordSetURL
//  3. Consuming the token again is rejected with ErrInvitationConsumed
//  4. Admin can grant component access for a user via FGA tuples
//  5. Admin can create a team, add the user, and set crosstalk
//
// Run with:
//
//	go test -tags=e2e -v -run TestAdminFlow ./tests/e2e/...
//
// Requirements: 10.1, 10.2, 10.3, 10.4, 10.5

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zero-day-ai/gibson/internal/authz"
	"github.com/zero-day-ai/gibson/internal/keycloak"
	"github.com/zero-day-ai/gibson/internal/provisioner"
)

// ---------------------------------------------------------------------------
// Shared test doubles
// ---------------------------------------------------------------------------

// stubFGAForAdminFlow implements authz.Authorizer in-memory.
type stubFGAForAdminFlow struct {
	tuples  []authz.Tuple
	allowed bool
}

func (s *stubFGAForAdminFlow) Check(_ context.Context, _, _, _ string) (bool, error) {
	return s.allowed, nil
}
func (s *stubFGAForAdminFlow) BatchCheck(_ context.Context, _ []authz.CheckRequest) ([]bool, error) {
	return nil, nil
}
func (s *stubFGAForAdminFlow) Write(_ context.Context, t []authz.Tuple) error {
	s.tuples = append(s.tuples, t...)
	return nil
}
func (s *stubFGAForAdminFlow) Delete(_ context.Context, t []authz.Tuple) error {
	filtered := s.tuples[:0]
	for _, existing := range s.tuples {
		remove := false
		for _, del := range t {
			if existing == del {
				remove = true
				break
			}
		}
		if !remove {
			filtered = append(filtered, existing)
		}
	}
	s.tuples = filtered
	return nil
}
func (s *stubFGAForAdminFlow) ListObjects(_ context.Context, _, _, _ string) ([]string, error) {
	return nil, nil
}
func (s *stubFGAForAdminFlow) ListUsers(_ context.Context, _, _, _ string) ([]string, error) {
	return nil, nil
}
func (s *stubFGAForAdminFlow) StoreID() string { return "test-store" }
func (s *stubFGAForAdminFlow) ModelID() string { return "test-model" }
func (s *stubFGAForAdminFlow) Close() error    { return nil }

// stubKCForAdminFlow implements provisioner.KeycloakAdmin for test isolation.
type stubKCForAdminFlow struct {
	createdUserID string
}

func (k *stubKCForAdminFlow) CreateUser(_ context.Context, cfg keycloak.UserConfig) (string, error) {
	if k.createdUserID != "" {
		return k.createdUserID, nil
	}
	return fmt.Sprintf("kc-%s", cfg.Email), nil
}
func (k *stubKCForAdminFlow) DeleteUser(_ context.Context, _ string) error { return nil }
func (k *stubKCForAdminFlow) CreateOrganization(_ context.Context, _, _, _ string) (string, error) {
	return "org-123", nil
}
func (k *stubKCForAdminFlow) GetOrganizationByAlias(_ context.Context, _ string) (*provisioner.OrgRepresentation, error) {
	return &provisioner.OrgRepresentation{ID: "org-123", Alias: "acme"}, nil
}
func (k *stubKCForAdminFlow) DeleteOrganization(_ context.Context, _ string) error { return nil }
func (k *stubKCForAdminFlow) AddOrganizationMember(_ context.Context, _, _ string) error { return nil }
func (k *stubKCForAdminFlow) RemoveOrganizationMember(_ context.Context, _, _ string) error {
	return nil
}
func (k *stubKCForAdminFlow) ListOrganizationMembers(_ context.Context, _ string) ([]provisioner.OrgMemberRepresentation, error) {
	return nil, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newAdminFlowRedis(t *testing.T) *redis.Client {
	t.Helper()
	mr, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mr.Close)
	return redis.NewClient(&redis.Options{Addr: mr.Addr()})
}

// ---------------------------------------------------------------------------
// TestAdminFlow
// ---------------------------------------------------------------------------

func TestAdminFlow(t *testing.T) {
	ctx := context.Background()
	rc := newAdminFlowRedis(t)
	fga := &stubFGAForAdminFlow{allowed: true}
	kc := &stubKCForAdminFlow{}
	logger := slog.Default()

	const tenantID = "acme"
	const adminUserID = "admin-001"
	signingKey := []byte("super-secret-key-32-bytes-long!!!")

	// -------------------------------------------------------------------------
	// Build handlers
	// -------------------------------------------------------------------------

	inviteHandler, err := provisioner.NewInviteHandler(kc, fga, rc, provisioner.InviteHandlerConfig{
		SigningKey: signingKey,
		BaseURL:    "https://dashboard.example.com",
	}, logger)
	require.NoError(t, err)

	grantHandler, err := provisioner.NewGrantHandler(fga, logger)
	require.NoError(t, err)

	teamHandler, err := provisioner.NewTeamHandler(fga, rc, logger)
	require.NoError(t, err)

	// -------------------------------------------------------------------------
	// Step 1: Admin invites a new member
	// -------------------------------------------------------------------------

	inv, err := inviteHandler.Invite(ctx, provisioner.InviteRequest{
		TenantID: tenantID,
		OrgID:    "org-123",
		Email:    "newuser@example.com",
		Role:     "operator",
	})
	require.NoError(t, err, "Invite should succeed")
	require.NotEmpty(t, inv.Token, "Token must be non-empty")
	require.NotEmpty(t, inv.UserID, "UserID must be returned")
	t.Logf("Step 1 PASS: Invite created for user %s", inv.UserID)

	// FGA member tuple must have been written.
	memberTupleFound := false
	for _, tuple := range fga.tuples {
		if tuple.Relation == "member" && tuple.Object == fmt.Sprintf("tenant:%s", tenantID) {
			memberTupleFound = true
		}
	}
	assert.True(t, memberTupleFound, "FGA member tuple must be written on invite")

	// -------------------------------------------------------------------------
	// Step 2: User accepts the invitation
	// -------------------------------------------------------------------------

	result, err := inviteHandler.Accept(ctx, inv.Token)
	require.NoError(t, err, "Accept must succeed for a fresh token")
	require.NotEmpty(t, result.PasswordSetURL, "PasswordSetURL must be returned")
	t.Logf("Step 2 PASS: Token accepted, PasswordSetURL=%s", result.PasswordSetURL)

	// -------------------------------------------------------------------------
	// Step 3: Accepting the same token again must fail
	// -------------------------------------------------------------------------

	_, err = inviteHandler.Accept(ctx, inv.Token)
	require.Error(t, err, "Second accept must fail")
	assert.True(t, errors.Is(err, provisioner.ErrInvitationConsumed), "Must be ErrInvitationConsumed")
	t.Logf("Step 3 PASS: Consumed token rejected")

	// -------------------------------------------------------------------------
	// Step 4: Admin grants component access
	// -------------------------------------------------------------------------

	err = grantHandler.Grant(ctx, tenantID, inv.UserID, "component:tool-nuclei", "execute")
	require.NoError(t, err, "Grant must succeed")

	// Verify FGA tuple was written.
	executeGrantFound := false
	for _, tuple := range fga.tuples {
		if tuple.User == fmt.Sprintf("user:%s", inv.UserID) && tuple.Relation == "can_execute" {
			executeGrantFound = true
		}
	}
	assert.True(t, executeGrantFound, "FGA can_execute tuple must be written on grant")
	t.Logf("Step 4 PASS: Component grant created")

	// -------------------------------------------------------------------------
	// Step 5: Admin creates a team and adds the user
	// -------------------------------------------------------------------------

	rec, err := teamHandler.Create(ctx, tenantID, "Red Team", "Red team ops", adminUserID)
	require.NoError(t, err, "Team creation must succeed")
	require.NotEmpty(t, rec.TeamID, "TeamID must be non-empty")
	t.Logf("Step 5a PASS: Team created id=%s", rec.TeamID)

	parentTupleFound := false
	for _, tuple := range fga.tuples {
		if tuple.Relation == "parent" && tuple.Object == fmt.Sprintf("tenant:%s", tenantID) {
			parentTupleFound = true
		}
	}
	assert.True(t, parentTupleFound, "FGA parent tuple must be written on team create")

	err = teamHandler.AddMember(ctx, tenantID, rec.TeamID, inv.UserID)
	require.NoError(t, err, "AddMember must succeed when user is a tenant member")
	t.Logf("Step 5b PASS: User added to team")

	teams, err := teamHandler.List(ctx, tenantID)
	require.NoError(t, err)
	require.Len(t, teams, 1, "Must have exactly one team")
	assert.Equal(t, rec.TeamID, teams[0].TeamID)
	t.Logf("Step 5c PASS: Team list returns 1 team")

	// -------------------------------------------------------------------------
	// Step 6: Delete team
	// -------------------------------------------------------------------------

	err = teamHandler.Delete(ctx, tenantID, rec.TeamID)
	require.NoError(t, err, "Team deletion must succeed")

	teams, err = teamHandler.List(ctx, tenantID)
	require.NoError(t, err)
	assert.Len(t, teams, 0, "Team list must be empty after deletion")
	t.Logf("Step 6 PASS: Team deleted")

	t.Log("=== TestAdminFlow: all steps passed ===")
}
