package provisioner

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zero-day-ai/gibson/internal/authz"
	"github.com/zero-day-ai/gibson/internal/keycloak"
)

// ---------------------------------------------------------------------------
// Shared test doubles
// ---------------------------------------------------------------------------

// mockKCForRollback is a lightweight in-test mock for KeycloakAdmin that
// records which calls were made and returns pre-configured errors.
type mockKCForRollback struct {
	deleteUserErr              error
	deleteOrgErr               error
	removeOrgMemberErr         error
	deleteUserCalled           bool
	deleteOrgCalled            bool
	removeOrgMemberCalled      bool
	deleteUserCalledWith       string
	deleteOrgCalledWith        string
	removeOrgMemberCalledWith  [2]string // [orgID, userID]
}

func (m *mockKCForRollback) CreateUser(_ context.Context, _ keycloak.UserConfig) (string, error) {
	return "", errors.New("not implemented")
}
func (m *mockKCForRollback) DeleteUser(_ context.Context, userID string) error {
	m.deleteUserCalled = true
	m.deleteUserCalledWith = userID
	return m.deleteUserErr
}
func (m *mockKCForRollback) CreateOrganization(_ context.Context, _, _, _ string) (string, error) {
	return "", errors.New("not implemented")
}
func (m *mockKCForRollback) GetOrganizationByAlias(_ context.Context, _ string) (*OrgRepresentation, error) {
	return nil, errors.New("not implemented")
}
func (m *mockKCForRollback) DeleteOrganization(_ context.Context, orgID string) error {
	m.deleteOrgCalled = true
	m.deleteOrgCalledWith = orgID
	return m.deleteOrgErr
}
func (m *mockKCForRollback) AddOrganizationMember(_ context.Context, _, _ string) error {
	return errors.New("not implemented")
}
func (m *mockKCForRollback) RemoveOrganizationMember(_ context.Context, orgID, userID string) error {
	m.removeOrgMemberCalled = true
	m.removeOrgMemberCalledWith = [2]string{orgID, userID}
	return m.removeOrgMemberErr
}
func (m *mockKCForRollback) ListOrganizationMembers(_ context.Context, _ string) ([]OrgMemberRepresentation, error) {
	return nil, errors.New("not implemented")
}

// mockAuthzForRollback captures Delete calls.
type mockAuthzForRollback struct {
	deleteErr     error
	deleteCalled  bool
	deleteTuples  []authz.Tuple
}

func (m *mockAuthzForRollback) Check(_ context.Context, _, _, _ string) (bool, error) {
	return false, errors.New("not implemented")
}
func (m *mockAuthzForRollback) BatchCheck(_ context.Context, _ []authz.CheckRequest) ([]bool, error) {
	return nil, errors.New("not implemented")
}
func (m *mockAuthzForRollback) Write(_ context.Context, _ []authz.Tuple) error {
	return errors.New("not implemented")
}
func (m *mockAuthzForRollback) Delete(_ context.Context, tuples []authz.Tuple) error {
	m.deleteCalled = true
	m.deleteTuples = tuples
	return m.deleteErr
}
func (m *mockAuthzForRollback) ListObjects(_ context.Context, _, _, _ string) ([]string, error) {
	return nil, errors.New("not implemented")
}
func (m *mockAuthzForRollback) ListUsers(_ context.Context, _, _, _ string) ([]string, error) {
	return nil, errors.New("not implemented")
}
func (m *mockAuthzForRollback) StoreID() string { return "" }
func (m *mockAuthzForRollback) ModelID() string { return "" }
func (m *mockAuthzForRollback) Close() error    { return nil }

// ---------------------------------------------------------------------------
// Helper to build a Rollback with fresh mocks
// ---------------------------------------------------------------------------

func newRollbackWithMocks(t *testing.T) (*Rollback, *mockKCForRollback, *mockAuthzForRollback) {
	t.Helper()
	kc := &mockKCForRollback{}
	az := &mockAuthzForRollback{}
	rb := NewRollback(kc, az, slog.Default())
	return rb, kc, az
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestRollback_HappyPath_AllIDsPresent(t *testing.T) {
	rb, kc, az := newRollbackWithMocks(t)

	err := rb.UndoSignup(context.Background(), "user-123", "org-456", "acme-corp")

	require.NoError(t, err)
	assert.True(t, az.deleteCalled, "authz Delete should have been called")
	require.Len(t, az.deleteTuples, 1)
	assert.Equal(t, "user:user-123", az.deleteTuples[0].User)
	assert.Equal(t, "admin", az.deleteTuples[0].Relation)
	assert.Equal(t, "tenant:acme-corp", az.deleteTuples[0].Object)

	assert.True(t, kc.removeOrgMemberCalled)
	assert.Equal(t, [2]string{"org-456", "user-123"}, kc.removeOrgMemberCalledWith)

	assert.True(t, kc.deleteOrgCalled)
	assert.Equal(t, "org-456", kc.deleteOrgCalledWith)

	assert.True(t, kc.deleteUserCalled)
	assert.Equal(t, "user-123", kc.deleteUserCalledWith)
}

func TestRollback_PartialState_OnlyUserID(t *testing.T) {
	rb, kc, az := newRollbackWithMocks(t)

	err := rb.UndoSignup(context.Background(), "user-123", "", "")

	require.NoError(t, err)
	// FGA delete skipped (no tenant ID)
	assert.False(t, az.deleteCalled)
	// Remove org member skipped (no org ID)
	assert.False(t, kc.removeOrgMemberCalled)
	// Delete org skipped (no org ID)
	assert.False(t, kc.deleteOrgCalled)
	// User deleted
	assert.True(t, kc.deleteUserCalled)
	assert.Equal(t, "user-123", kc.deleteUserCalledWith)
}

func TestRollback_PartialState_UserAndOrgID(t *testing.T) {
	rb, kc, az := newRollbackWithMocks(t)

	err := rb.UndoSignup(context.Background(), "user-123", "org-456", "")

	require.NoError(t, err)
	// FGA tuple skipped — tenantID is empty
	assert.False(t, az.deleteCalled)
	// Membership removed
	assert.True(t, kc.removeOrgMemberCalled)
	// Org deleted
	assert.True(t, kc.deleteOrgCalled)
	// User deleted
	assert.True(t, kc.deleteUserCalled)
}

func TestRollback_PartialState_NoIDs(t *testing.T) {
	rb, kc, az := newRollbackWithMocks(t)

	err := rb.UndoSignup(context.Background(), "", "", "")

	require.NoError(t, err)
	assert.False(t, az.deleteCalled)
	assert.False(t, kc.removeOrgMemberCalled)
	assert.False(t, kc.deleteOrgCalled)
	assert.False(t, kc.deleteUserCalled)
}

func TestRollback_NotFoundTolerance(t *testing.T) {
	// All steps return ErrNotFound — should produce no error.
	kc := &mockKCForRollback{
		deleteUserErr:      ErrNotFound,
		deleteOrgErr:       ErrNotFound,
		removeOrgMemberErr: ErrNotFound,
	}
	az := &mockAuthzForRollback{deleteErr: ErrNotFound}
	rb := NewRollback(kc, az, slog.Default())

	err := rb.UndoSignup(context.Background(), "user-123", "org-456", "acme-corp")

	require.NoError(t, err, "ErrNotFound at every step should produce no combined error")
	// All steps were still attempted.
	assert.True(t, az.deleteCalled)
	assert.True(t, kc.removeOrgMemberCalled)
	assert.True(t, kc.deleteOrgCalled)
	assert.True(t, kc.deleteUserCalled)
}

func TestRollback_OneStepFails_OtherStepsContinue(t *testing.T) {
	boom := errors.New("network timeout")
	kc := &mockKCForRollback{
		deleteOrgErr: boom,
	}
	az := &mockAuthzForRollback{}
	rb := NewRollback(kc, az, slog.Default())

	err := rb.UndoSignup(context.Background(), "user-123", "org-456", "acme-corp")

	// Error is returned but all steps were attempted.
	require.Error(t, err)
	assert.True(t, errors.Is(err, boom))

	assert.True(t, az.deleteCalled, "FGA delete should have run before the failing step")
	assert.True(t, kc.removeOrgMemberCalled, "remove member should have run before the failing step")
	assert.True(t, kc.deleteOrgCalled, "delete org was the failing step but was still called")
	assert.True(t, kc.deleteUserCalled, "delete user should have run after the failing step")
}

func TestRollback_MultipleStepsFail_ErrorsJoined(t *testing.T) {
	e1 := errors.New("FGA error")
	e2 := errors.New("KC delete user error")
	kc := &mockKCForRollback{deleteUserErr: e2}
	az := &mockAuthzForRollback{deleteErr: e1}
	rb := NewRollback(kc, az, slog.Default())

	err := rb.UndoSignup(context.Background(), "user-123", "org-456", "acme-corp")

	require.Error(t, err)
	assert.True(t, errors.Is(err, e1), "e1 should be in the combined error")
	assert.True(t, errors.Is(err, e2), "e2 should be in the combined error")
	// All steps were still attempted.
	assert.True(t, kc.removeOrgMemberCalled)
	assert.True(t, kc.deleteOrgCalled)
	assert.True(t, kc.deleteUserCalled)
}

func TestRollback_Idempotency(t *testing.T) {
	// Second call returns ErrNotFound on everything — should be a no-op.
	kc := &mockKCForRollback{
		deleteUserErr:      ErrNotFound,
		deleteOrgErr:       ErrNotFound,
		removeOrgMemberErr: ErrNotFound,
	}
	az := &mockAuthzForRollback{deleteErr: ErrNotFound}
	rb := NewRollback(kc, az, slog.Default())

	// First call (simulate partial success).
	err1 := rb.UndoSignup(context.Background(), "user-123", "org-456", "acme-corp")
	require.NoError(t, err1)

	// Second call (idempotent — everything already gone).
	err2 := rb.UndoSignup(context.Background(), "user-123", "org-456", "acme-corp")
	require.NoError(t, err2)
}

func TestRollback_NilLogger_UsesDefault(t *testing.T) {
	kc := &mockKCForRollback{}
	az := &mockAuthzForRollback{}
	// Passing nil logger must not panic.
	rb := NewRollback(kc, az, nil)
	require.NotNil(t, rb)
	err := rb.UndoSignup(context.Background(), "user-x", "org-y", "tenant-z")
	require.NoError(t, err)
}
