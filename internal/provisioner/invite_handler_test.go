package provisioner

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zero-day-ai/gibson/internal/authz"
	"github.com/zero-day-ai/gibson/internal/keycloak"
)

// ---------------------------------------------------------------------------
// Mocks reused across invite tests
// ---------------------------------------------------------------------------

type mockKCForInvite struct {
	createUserID  string
	createUserErr error
	deletedUsers  []string

	addOrgMemberErr    error
	removedOrgMembers  []string
}

func (m *mockKCForInvite) CreateUser(_ context.Context, _ keycloak.UserConfig) (string, error) {
	return m.createUserID, m.createUserErr
}
func (m *mockKCForInvite) DeleteUser(_ context.Context, id string) error {
	m.deletedUsers = append(m.deletedUsers, id)
	return nil
}
func (m *mockKCForInvite) CreateOrganization(_ context.Context, _, _, _ string) (string, error) {
	return "org-1", nil
}
func (m *mockKCForInvite) GetOrganizationByAlias(_ context.Context, _ string) (*OrgRepresentation, error) {
	return nil, ErrNotFound
}
func (m *mockKCForInvite) DeleteOrganization(_ context.Context, _ string) error { return nil }
func (m *mockKCForInvite) AddOrganizationMember(_ context.Context, _, _ string) error {
	return m.addOrgMemberErr
}
func (m *mockKCForInvite) RemoveOrganizationMember(_ context.Context, orgID, userID string) error {
	m.removedOrgMembers = append(m.removedOrgMembers, userID)
	return nil
}
func (m *mockKCForInvite) ListOrganizationMembers(_ context.Context, _ string) ([]OrgMemberRepresentation, error) {
	return nil, nil
}

type mockAuthzForInvite struct {
	writeErr    error
	writtenTuples []authz.Tuple
	deletedTuples []authz.Tuple
}

func (m *mockAuthzForInvite) Check(_ context.Context, _, _, _ string) (bool, error) { return true, nil }
func (m *mockAuthzForInvite) BatchCheck(_ context.Context, _ []authz.CheckRequest) ([]bool, error) {
	return nil, nil
}
func (m *mockAuthzForInvite) Write(_ context.Context, tuples []authz.Tuple) error {
	m.writtenTuples = append(m.writtenTuples, tuples...)
	return m.writeErr
}
func (m *mockAuthzForInvite) Delete(_ context.Context, tuples []authz.Tuple) error {
	m.deletedTuples = append(m.deletedTuples, tuples...)
	return nil
}
func (m *mockAuthzForInvite) ListObjects(_ context.Context, _, _, _ string) ([]string, error) {
	return nil, nil
}
func (m *mockAuthzForInvite) ListUsers(_ context.Context, _, _, _ string) ([]string, error) {
	return nil, nil
}
func (m *mockAuthzForInvite) StoreID() string { return "" }
func (m *mockAuthzForInvite) ModelID() string { return "" }
func (m *mockAuthzForInvite) Close() error    { return nil }

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func newTestInviteHandler(t *testing.T, kc KeycloakAdmin, az authz.Authorizer, rc *redis.Client) *InviteHandler {
	t.Helper()
	h, err := NewInviteHandler(kc, az, rc, InviteHandlerConfig{
		SigningKey: []byte("test-signing-key-32-bytes-long!!"),
		BaseURL:   "https://app.example.com",
		TokenTTL:  24 * time.Hour,
	}, nil)
	require.NoError(t, err)
	return h
}

func newMiniRedis(t *testing.T) *redis.Client {
	t.Helper()
	mr, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mr.Close)
	return redis.NewClient(&redis.Options{Addr: mr.Addr()})
}

// ---------------------------------------------------------------------------
// Tests: Invite (success and failure paths)
// ---------------------------------------------------------------------------

func TestInviteHandler_Invite_Success(t *testing.T) {
	kc := &mockKCForInvite{createUserID: "user-123"}
	az := &mockAuthzForInvite{}
	rc := newMiniRedis(t)
	h := newTestInviteHandler(t, kc, az, rc)

	inv, err := h.Invite(context.Background(), InviteRequest{
		TenantID: "acme",
		OrgID:    "org-1",
		Email:    "alice@example.com",
		Role:     "admin",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, inv.Token)
	assert.NotEmpty(t, inv.InvitationURL)
	assert.Equal(t, "user-123", inv.UserID)
	assert.Equal(t, "acme", inv.TenantID)
	assert.Contains(t, inv.InvitationURL, "/invite/accept?token=")

	// Verify FGA tuple was written with admin relation.
	require.Len(t, az.writtenTuples, 1)
	assert.Equal(t, "user:user-123", az.writtenTuples[0].User)
	assert.Equal(t, "admin", az.writtenTuples[0].Relation)
	assert.Equal(t, "tenant:acme", az.writtenTuples[0].Object)
}

func TestInviteHandler_Invite_OperatorRole_UsesMemberRelation(t *testing.T) {
	kc := &mockKCForInvite{createUserID: "user-456"}
	az := &mockAuthzForInvite{}
	rc := newMiniRedis(t)
	h := newTestInviteHandler(t, kc, az, rc)

	_, err := h.Invite(context.Background(), InviteRequest{
		TenantID: "acme",
		OrgID:    "org-1",
		Email:    "bob@example.com",
		Role:     "operator",
	})
	require.NoError(t, err)
	require.Len(t, az.writtenTuples, 1)
	assert.Equal(t, "member", az.writtenTuples[0].Relation)
}

func TestInviteHandler_Invite_CreateUserFails_NoRollbackNeeded(t *testing.T) {
	kc := &mockKCForInvite{createUserErr: errors.New("kc internal error")}
	az := &mockAuthzForInvite{}
	rc := newMiniRedis(t)
	h := newTestInviteHandler(t, kc, az, rc)

	_, err := h.Invite(context.Background(), InviteRequest{
		TenantID: "acme",
		OrgID:    "org-1",
		Email:    "carol@example.com",
		Role:     "viewer",
	})
	require.Error(t, err)
	// No FGA writes should have happened.
	assert.Len(t, az.writtenTuples, 0)
}

func TestInviteHandler_Invite_AddOrgMemberFails_RollsBackUser(t *testing.T) {
	kc := &mockKCForInvite{
		createUserID:    "user-789",
		addOrgMemberErr: errors.New("org membership failed"),
	}
	az := &mockAuthzForInvite{}
	rc := newMiniRedis(t)
	h := newTestInviteHandler(t, kc, az, rc)

	_, err := h.Invite(context.Background(), InviteRequest{
		TenantID: "acme",
		OrgID:    "org-1",
		Email:    "dave@example.com",
		Role:     "viewer",
	})
	require.Error(t, err)
	// User should be rolled back.
	assert.Contains(t, kc.deletedUsers, "user-789")
	// FGA tuple should NOT have been written.
	assert.Len(t, az.writtenTuples, 0)
}

func TestInviteHandler_Invite_FGAWriteFails_RollsBackUserAndOrg(t *testing.T) {
	kc := &mockKCForInvite{createUserID: "user-aaa"}
	az := &mockAuthzForInvite{writeErr: errors.New("fga write failed")}
	rc := newMiniRedis(t)
	h := newTestInviteHandler(t, kc, az, rc)

	_, err := h.Invite(context.Background(), InviteRequest{
		TenantID: "acme",
		OrgID:    "org-1",
		Email:    "eve@example.com",
		Role:     "operator",
	})
	require.Error(t, err)
	assert.Contains(t, kc.deletedUsers, "user-aaa")
	assert.Contains(t, kc.removedOrgMembers, "user-aaa")
}

func TestInviteHandler_Invite_InvalidRole_ReturnsError(t *testing.T) {
	kc := &mockKCForInvite{createUserID: "user-bbb"}
	az := &mockAuthzForInvite{}
	rc := newMiniRedis(t)
	h := newTestInviteHandler(t, kc, az, rc)

	_, err := h.Invite(context.Background(), InviteRequest{
		TenantID: "acme",
		OrgID:    "org-1",
		Email:    "frank@example.com",
		Role:     "superuser", // invalid
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidSignupInput)
}

func TestInviteHandler_Invite_ConflictEmail_ReturnsUserAlreadyMember(t *testing.T) {
	kc := &mockKCForInvite{createUserErr: ErrConflict}
	az := &mockAuthzForInvite{}
	rc := newMiniRedis(t)
	h := newTestInviteHandler(t, kc, az, rc)

	_, err := h.Invite(context.Background(), InviteRequest{
		TenantID: "acme",
		OrgID:    "org-1",
		Email:    "existing@example.com",
		Role:     "viewer",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUserAlreadyMember)
}

// ---------------------------------------------------------------------------
// Tests: Accept
// ---------------------------------------------------------------------------

func TestInviteHandler_Accept_ValidToken(t *testing.T) {
	kc := &mockKCForInvite{createUserID: "user-999"}
	az := &mockAuthzForInvite{}
	rc := newMiniRedis(t)
	h := newTestInviteHandler(t, kc, az, rc)

	// Create a real invitation first.
	inv, err := h.Invite(context.Background(), InviteRequest{
		TenantID: "acme",
		OrgID:    "org-1",
		Email:    "grace@example.com",
		Role:     "operator",
	})
	require.NoError(t, err)

	// Accept it.
	result, err := h.Accept(context.Background(), inv.Token)
	require.NoError(t, err)
	assert.Equal(t, "acme", result.TenantID)
	assert.Equal(t, "user-999", result.UserID)
	assert.Equal(t, "operator", result.Role)
	assert.NotEmpty(t, result.PasswordSetURL)
}

func TestInviteHandler_Accept_AlreadyConsumed(t *testing.T) {
	kc := &mockKCForInvite{createUserID: "user-111"}
	az := &mockAuthzForInvite{}
	rc := newMiniRedis(t)
	h := newTestInviteHandler(t, kc, az, rc)

	inv, err := h.Invite(context.Background(), InviteRequest{
		TenantID: "acme",
		OrgID:    "org-1",
		Email:    "henry@example.com",
		Role:     "viewer",
	})
	require.NoError(t, err)

	// Accept once.
	_, err = h.Accept(context.Background(), inv.Token)
	require.NoError(t, err)

	// Accept again should return ErrInvitationConsumed.
	_, err = h.Accept(context.Background(), inv.Token)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvitationConsumed)
}

func TestInviteHandler_Accept_ExpiredToken(t *testing.T) {
	kc := &mockKCForInvite{createUserID: "user-222"}
	az := &mockAuthzForInvite{}
	rc := newMiniRedis(t)

	// Use a very short TTL to simulate expiry.
	h, err := NewInviteHandler(kc, az, rc, InviteHandlerConfig{
		SigningKey: []byte("test-signing-key-32-bytes-long!!"),
		BaseURL:   "https://app.example.com",
		TokenTTL:  1 * time.Millisecond,
	}, nil)
	require.NoError(t, err)

	inv, err := h.Invite(context.Background(), InviteRequest{
		TenantID: "acme",
		OrgID:    "org-1",
		Email:    "iris@example.com",
		Role:     "viewer",
	})
	require.NoError(t, err)

	// Wait for TTL to elapse.
	time.Sleep(50 * time.Millisecond)

	// Even though the JWT may still parse (short TTL issues), the Redis key is gone.
	// A realistic expired JWT (exp in the past) will also fail parseToken.
	// For this test we just verify the Accept path returns an error.
	_, err = h.Accept(context.Background(), inv.Token)
	require.Error(t, err)
}

func TestInviteHandler_Accept_InvalidToken(t *testing.T) {
	kc := &mockKCForInvite{}
	az := &mockAuthzForInvite{}
	rc := newMiniRedis(t)
	h := newTestInviteHandler(t, kc, az, rc)

	_, err := h.Accept(context.Background(), "not.a.valid.jwt")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvitationInvalid)
}

// ---------------------------------------------------------------------------
// Tests: Resend
// ---------------------------------------------------------------------------

func TestInviteHandler_Resend_Success(t *testing.T) {
	kc := &mockKCForInvite{}
	az := &mockAuthzForInvite{}
	rc := newMiniRedis(t)
	h := newTestInviteHandler(t, kc, az, rc)

	inv, err := h.Resend(context.Background(), "acme", "user-333", "org-1", "jack@example.com", "viewer")
	require.NoError(t, err)
	assert.NotEmpty(t, inv.Token)
	assert.Equal(t, "user-333", inv.UserID)
	assert.Equal(t, "acme", inv.TenantID)
}

// ---------------------------------------------------------------------------
// Tests: constructor validation
// ---------------------------------------------------------------------------

func TestNewInviteHandler_NilKeyRejected(t *testing.T) {
	rc := newMiniRedis(t)
	_, err := NewInviteHandler(
		&mockKCForInvite{},
		&mockAuthzForInvite{},
		rc,
		InviteHandlerConfig{SigningKey: []byte("short")}, // too short
		nil,
	)
	require.Error(t, err)
}
