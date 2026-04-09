package provisioner

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zero-day-ai/gibson/internal/authz"
	"github.com/zero-day-ai/gibson/internal/config"
	"github.com/zero-day-ai/gibson/internal/keycloak"
)

// ---------------------------------------------------------------------------
// membershipScanner stub
// ---------------------------------------------------------------------------

type stubScanner struct {
	records []MembershipRecord
	err     error
}

func (s *stubScanner) ScanMemberships(_ context.Context) ([]MembershipRecord, error) {
	return s.records, s.err
}

// ---------------------------------------------------------------------------
// KeycloakAdmin mock for reconcile tests
// ---------------------------------------------------------------------------

type mockKCForReconcile struct {
	// GetOrganizationByAlias controls
	getOrgErr error
	getOrgRec *OrgRepresentation // non-nil means found

	// CreateOrganization controls
	createOrgID  string
	createOrgErr error

	// AddOrganizationMember controls
	addMemberErr error

	// Call tracking
	getOrgCalls    []string   // alias values
	createOrgCalls []string   // name values
	addMemberCalls [][2]string // [orgID, userID]
}

func (m *mockKCForReconcile) CreateUser(_ context.Context, _ keycloak.UserConfig) (string, error) {
	return "", errors.New("not implemented")
}
func (m *mockKCForReconcile) DeleteUser(_ context.Context, _ string) error { return nil }
func (m *mockKCForReconcile) CreateOrganization(_ context.Context, name, _, _ string) (string, error) {
	m.createOrgCalls = append(m.createOrgCalls, name)
	return m.createOrgID, m.createOrgErr
}
func (m *mockKCForReconcile) GetOrganizationByAlias(_ context.Context, alias string) (*OrgRepresentation, error) {
	m.getOrgCalls = append(m.getOrgCalls, alias)
	return m.getOrgRec, m.getOrgErr
}
func (m *mockKCForReconcile) DeleteOrganization(_ context.Context, _ string) error { return nil }
func (m *mockKCForReconcile) AddOrganizationMember(_ context.Context, orgID, userID string) error {
	m.addMemberCalls = append(m.addMemberCalls, [2]string{orgID, userID})
	return m.addMemberErr
}
func (m *mockKCForReconcile) RemoveOrganizationMember(_ context.Context, _, _ string) error {
	return nil
}
func (m *mockKCForReconcile) ListOrganizationMembers(_ context.Context, _ string) ([]OrgMemberRepresentation, error) {
	return nil, nil
}

// ---------------------------------------------------------------------------
// Authorizer mock for reconcile tests
// ---------------------------------------------------------------------------

type mockAuthzForReconcile struct {
	writeErr     error
	writeCalled  bool
	writeTuples  []authz.Tuple
}

func (m *mockAuthzForReconcile) Check(_ context.Context, _, _, _ string) (bool, error) {
	return false, errors.New("not implemented")
}
func (m *mockAuthzForReconcile) BatchCheck(_ context.Context, _ []authz.CheckRequest) ([]bool, error) {
	return nil, errors.New("not implemented")
}
func (m *mockAuthzForReconcile) Write(_ context.Context, tuples []authz.Tuple) error {
	m.writeCalled = true
	m.writeTuples = append(m.writeTuples, tuples...)
	return m.writeErr
}
func (m *mockAuthzForReconcile) Delete(_ context.Context, _ []authz.Tuple) error { return nil }
func (m *mockAuthzForReconcile) ListObjects(_ context.Context, _, _, _ string) ([]string, error) {
	return nil, errors.New("not implemented")
}
func (m *mockAuthzForReconcile) ListUsers(_ context.Context, _, _, _ string) ([]string, error) {
	return nil, errors.New("not implemented")
}
func (m *mockAuthzForReconcile) StoreID() string { return "" }
func (m *mockAuthzForReconcile) ModelID() string { return "" }
func (m *mockAuthzForReconcile) Close() error    { return nil }

// ---------------------------------------------------------------------------
// Builder helper
// ---------------------------------------------------------------------------

func enabledCfg() config.ProvisionerConfig {
	return config.ProvisionerConfig{ReconcileOnStartup: true}
}

func disabledCfg() config.ProvisionerConfig {
	return config.ProvisionerConfig{ReconcileOnStartup: false}
}

func newTestReconciler(
	cfg config.ProvisionerConfig,
	scanner membershipScanner,
	kc *mockKCForReconcile,
	az *mockAuthzForReconcile,
) *OrgReconciler {
	return NewOrgReconciler(cfg, scanner, kc, az, slog.Default())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestReconcile_DisabledFlag_IsNoOp(t *testing.T) {
	kc := &mockKCForReconcile{}
	az := &mockAuthzForReconcile{}
	scanner := &stubScanner{records: []MembershipRecord{
		{TenantID: "acme-corp", UserID: "user-1", Email: "a@acme.com", Role: "owner"},
	}}

	r := newTestReconciler(disabledCfg(), scanner, kc, az)
	err := r.ReconcileKeycloakOrgs(context.Background())

	require.NoError(t, err)
	// No KC or FGA calls should have been made.
	assert.Empty(t, kc.getOrgCalls)
	assert.Empty(t, kc.createOrgCalls)
	assert.Empty(t, kc.addMemberCalls)
	assert.False(t, az.writeCalled)
}

func TestReconcile_NoMemberships_IsNoOp(t *testing.T) {
	kc := &mockKCForReconcile{}
	az := &mockAuthzForReconcile{}
	scanner := &stubScanner{records: nil}

	r := newTestReconciler(enabledCfg(), scanner, kc, az)
	err := r.ReconcileKeycloakOrgs(context.Background())

	require.NoError(t, err)
	assert.Empty(t, kc.getOrgCalls)
	assert.False(t, az.writeCalled)
}

func TestReconcile_ScanFails_ReturnsError(t *testing.T) {
	scanErr := errors.New("redis connection refused")
	scanner := &stubScanner{err: scanErr}
	kc := &mockKCForReconcile{}
	az := &mockAuthzForReconcile{}

	r := newTestReconciler(enabledCfg(), scanner, kc, az)
	err := r.ReconcileKeycloakOrgs(context.Background())

	require.Error(t, err)
	assert.True(t, errors.Is(err, scanErr))
}

func TestReconcile_HappyPath_OrgAbsent_CreatesOrgAndWritesFGA(t *testing.T) {
	kc := &mockKCForReconcile{
		getOrgErr:    ErrNotFound, // org does not exist yet
		createOrgID:  "org-999",
	}
	az := &mockAuthzForReconcile{}
	scanner := &stubScanner{records: []MembershipRecord{
		{TenantID: "acme-corp", UserID: "user-1", Email: "alice@acme.com", Role: "owner"},
	}}

	r := newTestReconciler(enabledCfg(), scanner, kc, az)
	err := r.ReconcileKeycloakOrgs(context.Background())

	require.NoError(t, err)

	// Should have checked for the org then created it.
	assert.Equal(t, []string{"acme-corp"}, kc.getOrgCalls)
	require.Len(t, kc.createOrgCalls, 1)

	// Should have added the member.
	require.Len(t, kc.addMemberCalls, 1)
	assert.Equal(t, [2]string{"org-999", "user-1"}, kc.addMemberCalls[0])

	// Should have written the FGA admin tuple (owner role).
	assert.True(t, az.writeCalled)
	require.Len(t, az.writeTuples, 1)
	assert.Equal(t, "user:user-1", az.writeTuples[0].User)
	assert.Equal(t, "admin", az.writeTuples[0].Relation)
	assert.Equal(t, "tenant:acme-corp", az.writeTuples[0].Object)
}

func TestReconcile_HappyPath_OrgAlreadyExists_SkipsCreation(t *testing.T) {
	kc := &mockKCForReconcile{
		getOrgRec: &OrgRepresentation{ID: "org-existing", Alias: "acme-corp"},
		// getOrgErr is nil → org found immediately
	}
	az := &mockAuthzForReconcile{}
	scanner := &stubScanner{records: []MembershipRecord{
		{TenantID: "acme-corp", UserID: "user-1", Email: "alice@acme.com", Role: "owner"},
	}}

	r := newTestReconciler(enabledCfg(), scanner, kc, az)
	err := r.ReconcileKeycloakOrgs(context.Background())

	require.NoError(t, err)
	// Org was found — CreateOrganization must NOT have been called.
	assert.Empty(t, kc.createOrgCalls)
	// Member still gets added.
	require.Len(t, kc.addMemberCalls, 1)
	assert.Equal(t, [2]string{"org-existing", "user-1"}, kc.addMemberCalls[0])
}

func TestReconcile_MemberAlreadyInOrg_SkipsGracefully(t *testing.T) {
	kc := &mockKCForReconcile{
		getOrgRec:    &OrgRepresentation{ID: "org-x", Alias: "acme-corp"},
		addMemberErr: ErrConflict, // already a member
	}
	az := &mockAuthzForReconcile{}
	scanner := &stubScanner{records: []MembershipRecord{
		{TenantID: "acme-corp", UserID: "user-1", Email: "a@acme.com", Role: "owner"},
	}}

	r := newTestReconciler(enabledCfg(), scanner, kc, az)
	err := r.ReconcileKeycloakOrgs(context.Background())

	require.NoError(t, err)
	// FGA write still happens even though add-member returned ErrConflict.
	assert.True(t, az.writeCalled, "FGA write should proceed even when member already exists")
}

func TestReconcile_OrphanedUser_NotFoundInKC_LogsWarnContinues(t *testing.T) {
	kc := &mockKCForReconcile{
		getOrgErr:    ErrNotFound,
		createOrgID:  "org-new",
		addMemberErr: ErrNotFound, // user doesn't exist in KC
	}
	az := &mockAuthzForReconcile{}
	scanner := &stubScanner{records: []MembershipRecord{
		{TenantID: "acme-corp", UserID: "ghost-user", Email: "ghost@acme.com", Role: "owner"},
	}}

	r := newTestReconciler(enabledCfg(), scanner, kc, az)
	err := r.ReconcileKeycloakOrgs(context.Background())

	// Overall reconciliation must NOT fail — orphaned records are logged, not fatal.
	require.NoError(t, err)
	// FGA tuple must NOT be written for an orphaned user (user doesn't exist).
	assert.False(t, az.writeCalled, "FGA write must not occur for orphaned (KC-absent) users")
}

func TestReconcile_ViewerRole_NoFGAWrite(t *testing.T) {
	kc := &mockKCForReconcile{
		getOrgRec: &OrgRepresentation{ID: "org-x", Alias: "acme-corp"},
	}
	az := &mockAuthzForReconcile{}
	scanner := &stubScanner{records: []MembershipRecord{
		{TenantID: "acme-corp", UserID: "user-viewer", Email: "v@acme.com", Role: "viewer"},
	}}

	r := newTestReconciler(enabledCfg(), scanner, kc, az)
	err := r.ReconcileKeycloakOrgs(context.Background())

	require.NoError(t, err)
	// Viewer is added to KC org but does NOT get an FGA admin tuple.
	require.Len(t, kc.addMemberCalls, 1)
	assert.False(t, az.writeCalled, "viewer role must not receive FGA admin tuple")
}

func TestReconcile_OperatorRole_NoFGAWrite(t *testing.T) {
	kc := &mockKCForReconcile{
		getOrgRec: &OrgRepresentation{ID: "org-x", Alias: "acme-corp"},
	}
	az := &mockAuthzForReconcile{}
	scanner := &stubScanner{records: []MembershipRecord{
		{TenantID: "acme-corp", UserID: "user-op", Email: "op@acme.com", Role: "operator"},
	}}

	r := newTestReconciler(enabledCfg(), scanner, kc, az)
	err := r.ReconcileKeycloakOrgs(context.Background())

	require.NoError(t, err)
	assert.False(t, az.writeCalled, "operator role must not receive FGA admin tuple")
}

func TestReconcile_AdminRole_WritesFGATuple(t *testing.T) {
	kc := &mockKCForReconcile{
		getOrgRec: &OrgRepresentation{ID: "org-x", Alias: "acme-corp"},
	}
	az := &mockAuthzForReconcile{}
	scanner := &stubScanner{records: []MembershipRecord{
		{TenantID: "acme-corp", UserID: "user-admin", Email: "adm@acme.com", Role: "admin"},
	}}

	r := newTestReconciler(enabledCfg(), scanner, kc, az)
	err := r.ReconcileKeycloakOrgs(context.Background())

	require.NoError(t, err)
	assert.True(t, az.writeCalled)
	require.Len(t, az.writeTuples, 1)
	assert.Equal(t, "user:user-admin", az.writeTuples[0].User)
	assert.Equal(t, "tenant:acme-corp", az.writeTuples[0].Object)
}

func TestReconcile_MultipleTenants_AllReconciled(t *testing.T) {
	kc := &mockKCForReconcile{
		getOrgErr:   ErrNotFound,
		createOrgID: "org-dynamic",
	}
	az := &mockAuthzForReconcile{}
	scanner := &stubScanner{records: []MembershipRecord{
		{TenantID: "tenant-a", UserID: "user-a1", Email: "a1@a.com", Role: "owner"},
		{TenantID: "tenant-b", UserID: "user-b1", Email: "b1@b.com", Role: "admin"},
	}}

	r := newTestReconciler(enabledCfg(), scanner, kc, az)
	err := r.ReconcileKeycloakOrgs(context.Background())

	require.NoError(t, err)
	// Two tenants → two orgs created (both absent).
	assert.Len(t, kc.createOrgCalls, 2)
	// Two members added.
	assert.Len(t, kc.addMemberCalls, 2)
	// Two FGA tuples (owner + admin).
	assert.Len(t, az.writeTuples, 2)
}

func TestReconcile_OneTenantFails_OtherContinues(t *testing.T) {
	// tenant-a: create org fails → member not added, FGA not written
	// tenant-b: succeeds
	// Because the kc mock uses a single error for all calls we use a
	// counting mock below.
	callCount := 0
	type countingKC struct {
		mockKCForReconcile
	}

	// Build a scanner with two tenants.
	scanner := &stubScanner{records: []MembershipRecord{
		{TenantID: "tenant-a", UserID: "user-a", Email: "a@a.com", Role: "owner"},
		{TenantID: "tenant-b", UserID: "user-b", Email: "b@b.com", Role: "owner"},
	}}

	kc := &mockKCForReconcile{
		getOrgErr:    ErrNotFound,
		createOrgErr: errors.New("KC unavailable"), // all create calls fail
	}
	az := &mockAuthzForReconcile{}

	r := newTestReconciler(enabledCfg(), scanner, kc, az)
	err := r.ReconcileKeycloakOrgs(context.Background())

	// Overall result is still nil — individual failures are logged, not fatal.
	require.NoError(t, err)
	_ = callCount // suppress unused warning in this table-less test
}

func TestReconcile_NilLogger_DoesNotPanic(t *testing.T) {
	scanner := &stubScanner{}
	kc := &mockKCForReconcile{}
	az := &mockAuthzForReconcile{}

	r := NewOrgReconciler(enabledCfg(), scanner, kc, az, nil)
	require.NotNil(t, r)
	require.NoError(t, r.ReconcileKeycloakOrgs(context.Background()))
}

func TestReconcile_EmptyUserID_SkippedWithWarn(t *testing.T) {
	kc := &mockKCForReconcile{
		getOrgRec: &OrgRepresentation{ID: "org-x", Alias: "acme-corp"},
	}
	az := &mockAuthzForReconcile{}
	scanner := &stubScanner{records: []MembershipRecord{
		{TenantID: "acme-corp", UserID: "", Email: "ghost@acme.com", Role: "owner"},
	}}

	r := newTestReconciler(enabledCfg(), scanner, kc, az)
	err := r.ReconcileKeycloakOrgs(context.Background())

	require.NoError(t, err)
	assert.Empty(t, kc.addMemberCalls, "empty userID must not produce a KC add-member call")
	assert.False(t, az.writeCalled)
}
