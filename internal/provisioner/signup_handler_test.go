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
// KeycloakAdmin mock
// ---------------------------------------------------------------------------

type mockKCForSignup struct {
	createUserID string
	createUserErr error

	createOrgID  string
	createOrgErr error

	getOrgByAliasOrg *OrgRepresentation
	getOrgByAliasErr error

	addMemberErr error
}

func (m *mockKCForSignup) CreateUser(_ context.Context, _ keycloak.UserConfig) (string, error) {
	return m.createUserID, m.createUserErr
}
func (m *mockKCForSignup) DeleteUser(_ context.Context, _ string) error { return nil }
func (m *mockKCForSignup) CreateOrganization(_ context.Context, _, _, _ string) (string, error) {
	return m.createOrgID, m.createOrgErr
}
func (m *mockKCForSignup) GetOrganizationByAlias(_ context.Context, _ string) (*OrgRepresentation, error) {
	return m.getOrgByAliasOrg, m.getOrgByAliasErr
}
func (m *mockKCForSignup) DeleteOrganization(_ context.Context, _ string) error { return nil }
func (m *mockKCForSignup) AddOrganizationMember(_ context.Context, _, _ string) error {
	return m.addMemberErr
}
func (m *mockKCForSignup) RemoveOrganizationMember(_ context.Context, _, _ string) error { return nil }
func (m *mockKCForSignup) ListOrganizationMembers(_ context.Context, _ string) ([]OrgMemberRepresentation, error) {
	return nil, nil
}

// ---------------------------------------------------------------------------
// Authorizer mock
// ---------------------------------------------------------------------------

type mockAuthzForSignup struct {
	writeErr    error
	writeCalled bool
}

func (m *mockAuthzForSignup) Check(_ context.Context, _, _, _ string) (bool, error) { return true, nil }
func (m *mockAuthzForSignup) BatchCheck(_ context.Context, _ []authz.CheckRequest) ([]bool, error) {
	return nil, nil
}
func (m *mockAuthzForSignup) Write(_ context.Context, _ []authz.Tuple) error {
	m.writeCalled = true
	return m.writeErr
}
func (m *mockAuthzForSignup) Delete(_ context.Context, _ []authz.Tuple) error { return nil }
func (m *mockAuthzForSignup) ListObjects(_ context.Context, _, _, _ string) ([]string, error) {
	return nil, nil
}
func (m *mockAuthzForSignup) ListUsers(_ context.Context, _, _, _ string) ([]string, error) {
	return nil, nil
}
func (m *mockAuthzForSignup) StoreID() string { return "" }
func (m *mockAuthzForSignup) ModelID() string { return "" }
func (m *mockAuthzForSignup) Close() error    { return nil }

// ---------------------------------------------------------------------------
// Rollback mock (satisfies rollbackerIface)
// ---------------------------------------------------------------------------

type mockRollbackForSignup struct {
	calledWith []rollbackCall
	returnErr  error
}

type rollbackCall struct {
	userID   string
	orgID    string
	tenantID string
}

func (m *mockRollbackForSignup) UndoSignup(_ context.Context, userID, orgID, tenantID string) error {
	m.calledWith = append(m.calledWith, rollbackCall{userID: userID, orgID: orgID, tenantID: tenantID})
	return m.returnErr
}

// ---------------------------------------------------------------------------
// Provisioner stub (satisfies tenantProvisionerIface)
// ---------------------------------------------------------------------------

type provisionerStubForSignup struct {
	err error
}

func (p *provisionerStubForSignup) ProvisionTenant(_ context.Context, _ ProvisionRequest) (*ProvisionResult, error) {
	if p.err != nil {
		return nil, p.err
	}
	return &ProvisionResult{Status: "completed"}, nil
}

// ---------------------------------------------------------------------------
// Builder helpers
// ---------------------------------------------------------------------------

// newTestSignupHandler wires a SignupHandler with all mocks pre-injected.
func newTestSignupHandler(
	kc *mockKCForSignup,
	az *mockAuthzForSignup,
	rbk *mockRollbackForSignup,
	provErr error,
) *SignupHandler {
	return &SignupHandler{
		kc:          kc,
		authz:       az,
		provisioner: &provisionerStubForSignup{err: provErr},
		rollback:    rbk,
		logger:      slog.Default(),
	}
}

func validSignupRequest() SignupRequest {
	return SignupRequest{
		Email:       "alice@example.com",
		Password:    "securepassword123",
		CompanyName: "Acme Corp",
		Plan:        "free",
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestSignupHandler_SuccessPath(t *testing.T) {
	kc := &mockKCForSignup{
		createUserID: "user-uuid-123",
		createOrgID:  "org-uuid-456",
	}
	az := &mockAuthzForSignup{}
	rbk := &mockRollbackForSignup{}

	h := newTestSignupHandler(kc, az, rbk, nil)
	resp, err := h.Signup(context.Background(), validSignupRequest())

	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, "user-uuid-123", resp.UserID)
	assert.Equal(t, "acme-corp", resp.TenantID)
	assert.Equal(t, "acme-corp", resp.OrganizationAlias)
	assert.Equal(t, "/login", resp.RedirectURL)
	assert.True(t, az.writeCalled, "FGA write should have been called")
	assert.Empty(t, rbk.calledWith, "rollback must NOT be called on success")
}

func TestSignupHandler_InvalidInput(t *testing.T) {
	tests := []struct {
		name string
		req  SignupRequest
	}{
		{
			name: "empty_email",
			req:  SignupRequest{Email: "", Password: "securepassword123", CompanyName: "Acme", Plan: "free"},
		},
		{
			name: "invalid_email_format",
			req:  SignupRequest{Email: "not-an-email", Password: "securepassword123", CompanyName: "Acme", Plan: "free"},
		},
		{
			name: "short_password",
			req:  SignupRequest{Email: "alice@example.com", Password: "short", CompanyName: "Acme", Plan: "free"},
		},
		{
			name: "empty_company",
			req:  SignupRequest{Email: "alice@example.com", Password: "securepassword123", CompanyName: "", Plan: "free"},
		},
		{
			name: "invalid_plan",
			req:  SignupRequest{Email: "alice@example.com", Password: "securepassword123", CompanyName: "Acme", Plan: "diamond"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			kc := &mockKCForSignup{}
			az := &mockAuthzForSignup{}
			rbk := &mockRollbackForSignup{}
			h := newTestSignupHandler(kc, az, rbk, nil)

			_, err := h.Signup(context.Background(), tc.req)

			require.Error(t, err)
			assert.True(t, errors.Is(err, ErrInvalidSignupInput), "expected ErrInvalidSignupInput, got: %v", err)
			assert.Empty(t, rbk.calledWith, "rollback must NOT be called on validation failure")
		})
	}
}

func TestSignupHandler_CreateUser_Fails(t *testing.T) {
	boom := errors.New("KC network error")
	kc := &mockKCForSignup{createUserErr: boom}
	az := &mockAuthzForSignup{}
	rbk := &mockRollbackForSignup{}

	h := newTestSignupHandler(kc, az, rbk, nil)
	_, err := h.Signup(context.Background(), validSignupRequest())

	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrSignupFailed))
	require.Len(t, rbk.calledWith, 1)
	// userID and orgID should be empty since user creation failed before any state was created.
	assert.Equal(t, "", rbk.calledWith[0].userID)
	assert.Equal(t, "", rbk.calledWith[0].orgID)
	assert.Equal(t, "acme-corp", rbk.calledWith[0].tenantID)
}

func TestSignupHandler_CreateUser_Conflict_ReturnsEmailAlreadyExists(t *testing.T) {
	kc := &mockKCForSignup{createUserErr: ErrConflict}
	az := &mockAuthzForSignup{}
	rbk := &mockRollbackForSignup{}

	h := newTestSignupHandler(kc, az, rbk, nil)
	_, err := h.Signup(context.Background(), validSignupRequest())

	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrEmailAlreadyExists))
	// Rollback must NOT be called on conflict — no state was written.
	assert.Empty(t, rbk.calledWith)
}

func TestSignupHandler_CreateOrganization_Fails(t *testing.T) {
	boom := errors.New("org create error")
	kc := &mockKCForSignup{
		createUserID: "user-123",
		createOrgErr: boom,
	}
	az := &mockAuthzForSignup{}
	rbk := &mockRollbackForSignup{}

	h := newTestSignupHandler(kc, az, rbk, nil)
	_, err := h.Signup(context.Background(), validSignupRequest())

	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrSignupFailed))
	require.Len(t, rbk.calledWith, 1)
	assert.Equal(t, "user-123", rbk.calledWith[0].userID, "rollback must receive the created userID")
	assert.Equal(t, "", rbk.calledWith[0].orgID, "orgID must be empty: org creation failed")
}

func TestSignupHandler_CreateOrganization_Conflict_FetchesExisting(t *testing.T) {
	kc := &mockKCForSignup{
		createUserID: "user-123",
		createOrgErr: ErrConflict,
		getOrgByAliasOrg: &OrgRepresentation{
			ID:    "existing-org-id",
			Alias: "acme-corp",
		},
	}
	az := &mockAuthzForSignup{}
	rbk := &mockRollbackForSignup{}

	h := newTestSignupHandler(kc, az, rbk, nil)
	resp, err := h.Signup(context.Background(), validSignupRequest())

	require.NoError(t, err, "existing org conflict should be handled gracefully")
	require.NotNil(t, resp)
	assert.Equal(t, "acme-corp", resp.TenantID)
	assert.Empty(t, rbk.calledWith, "rollback must NOT be called on graceful 409 handling")
}

func TestSignupHandler_AddOrgMember_Fails(t *testing.T) {
	boom := errors.New("member add error")
	kc := &mockKCForSignup{
		createUserID: "user-123",
		createOrgID:  "org-456",
		addMemberErr: boom,
	}
	az := &mockAuthzForSignup{}
	rbk := &mockRollbackForSignup{}

	h := newTestSignupHandler(kc, az, rbk, nil)
	_, err := h.Signup(context.Background(), validSignupRequest())

	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrSignupFailed))
	require.Len(t, rbk.calledWith, 1)
	assert.Equal(t, "user-123", rbk.calledWith[0].userID)
	assert.Equal(t, "org-456", rbk.calledWith[0].orgID)
}

func TestSignupHandler_FGAWrite_Fails(t *testing.T) {
	boom := errors.New("FGA write error")
	kc := &mockKCForSignup{
		createUserID: "user-123",
		createOrgID:  "org-456",
	}
	az := &mockAuthzForSignup{writeErr: boom}
	rbk := &mockRollbackForSignup{}

	h := newTestSignupHandler(kc, az, rbk, nil)
	_, err := h.Signup(context.Background(), validSignupRequest())

	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrSignupFailed))
	require.Len(t, rbk.calledWith, 1)
	assert.Equal(t, "user-123", rbk.calledWith[0].userID)
	assert.Equal(t, "org-456", rbk.calledWith[0].orgID)
}

func TestSignupHandler_ProvisionTenant_Fails(t *testing.T) {
	boom := errors.New("provision error")
	kc := &mockKCForSignup{
		createUserID: "user-123",
		createOrgID:  "org-456",
	}
	az := &mockAuthzForSignup{}
	rbk := &mockRollbackForSignup{}

	h := newTestSignupHandler(kc, az, rbk, boom)
	_, err := h.Signup(context.Background(), validSignupRequest())

	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrSignupFailed))
	require.Len(t, rbk.calledWith, 1)
	assert.Equal(t, "user-123", rbk.calledWith[0].userID)
	assert.Equal(t, "org-456", rbk.calledWith[0].orgID)
}

// ---------------------------------------------------------------------------
// Slug helper tests
// ---------------------------------------------------------------------------

func TestSlugify(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"Zero Day AI", "zero-day-ai"},
		{"Acme Corp.", "acme-corp"},
		{"  foo--bar  ", "foo-bar"},
		{"My Company!", "my-company"},
		{"ABC", "abc"},
		{"123 Company", "123-company"},
		{"UPPER CASE", "upper-case"},
		{"hyphen-already", "hyphen-already"},
		{"multiple   spaces", "multiple-spaces"},
		{"trailing-", "trailing"},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := slugify(tc.input)
			assert.Equal(t, tc.expected, got)
		})
	}
}

func TestEmailDomain(t *testing.T) {
	assert.Equal(t, "example.com", emailDomain("alice@example.com"))
	assert.Equal(t, "zero-day.ai", emailDomain("bob@zero-day.ai"))
	assert.Equal(t, "", emailDomain("notanemail"))
}

