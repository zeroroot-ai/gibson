package admin

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/internal/platform/idp"

	tenantv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/tenant/v1"
)

// ---------------------------------------------------------------------------
// Test fakes specific to ListMembers
// ---------------------------------------------------------------------------

// membersAuthorizer is a configurable stub for ListUsers + BatchCheck used by
// the ListMembers tests. It holds a list of member user refs and a set of user
// IDs that should be admins.
type membersAuthorizer struct {
	// members is the slice returned by ListUsers for the tenant object.
	members []string
	// admins is the set of user IDs (without "user:" prefix) that the
	// BatchCheck call should consider admins.
	admins map[string]bool
	// listUsersErr is returned by ListUsers when non-nil.
	listUsersErr error
	// batchCheckErr is returned by BatchCheck when non-nil.
	batchCheckErr error
}

func (m *membersAuthorizer) Check(_ context.Context, _, _, _ string) (bool, error) {
	return false, nil
}

func (m *membersAuthorizer) BatchCheck(_ context.Context, checks []authz.CheckRequest) ([]bool, error) {
	if m.batchCheckErr != nil {
		return nil, m.batchCheckErr
	}
	out := make([]bool, len(checks))
	for i, c := range checks {
		// c.User is "user:<id>", strip prefix to look up in admins map.
		uid := c.User
		if len(uid) > 5 && uid[:5] == "user:" {
			uid = uid[5:]
		}
		out[i] = m.admins[uid]
	}
	return out, nil
}

func (m *membersAuthorizer) Write(_ context.Context, _ []authz.Tuple) error  { return nil }
func (m *membersAuthorizer) Delete(_ context.Context, _ []authz.Tuple) error { return nil }
func (m *membersAuthorizer) ListObjects(_ context.Context, _, _, _ string) ([]string, error) {
	return nil, nil
}

func (m *membersAuthorizer) ListUsers(_ context.Context, _, _, _ string) ([]string, error) {
	if m.listUsersErr != nil {
		return nil, m.listUsersErr
	}
	return m.members, nil
}

func (m *membersAuthorizer) StoreID() string { return "test" }
func (m *membersAuthorizer) ModelID() string { return "test" }
func (m *membersAuthorizer) Close() error    { return nil }

// membersIdPClient is a configurable stub for idp.AdminClient used by ListMembers tests.
// The profiles map key is the accountID.
type membersIdPClient struct {
	profiles map[string]*idp.UserProfile
	failFor  map[string]bool // accountIDs that should return an error

	// recorded membership projection calls (gibson#621)
	added   []idp.TenantMembershipRequest
	removed []idp.TenantMembershipRequest
	addErr  error

	// EnsureHumanUser recording (gibson#633)
	ensuredEmails []string
	ensureUserID  string
	ensureErr     error
}

func (c *membersIdPClient) CreateServiceAccount(_ context.Context, _ idp.CreateServiceAccountRequest) (*idp.ServiceAccount, error) {
	return nil, nil
}
func (c *membersIdPClient) DeleteServiceAccount(_ context.Context, _ string) error { return nil }
func (c *membersIdPClient) ListServiceAccounts(_ context.Context, _ idp.ListServiceAccountsRequest) (*idp.ListServiceAccountsResponse, error) {
	return nil, nil
}
func (c *membersIdPClient) UpdateUserProfile(_ context.Context, _ string, _ idp.UpdateUserProfileRequest) (*idp.UserProfile, error) {
	return nil, nil
}
func (c *membersIdPClient) GetUserProfile(_ context.Context, accountID string) (*idp.UserProfile, error) {
	if c.failFor[accountID] {
		return nil, idp.ErrNotFound
	}
	p, ok := c.profiles[accountID]
	if !ok {
		return nil, idp.ErrNotFound
	}
	return p, nil
}
func (c *membersIdPClient) AddTenantMember(_ context.Context, req idp.TenantMembershipRequest) error {
	if c.addErr != nil {
		return c.addErr
	}
	c.added = append(c.added, req)
	return nil
}
func (c *membersIdPClient) RemoveTenantMember(_ context.Context, req idp.TenantMembershipRequest) error {
	c.removed = append(c.removed, req)
	return nil
}
func (c *membersIdPClient) RevokeUserSessions(_ context.Context, _ string) (idp.RevokeUserSessionsResult, error) {
	return idp.RevokeUserSessionsResult{}, nil
}
func (c *membersIdPClient) ListUserSessions(_ context.Context, _ string) ([]idp.SessionInfo, error) {
	return nil, nil
}
func (c *membersIdPClient) RevokeSession(_ context.Context, _ string) error { return nil }
func (c *membersIdPClient) EnsureHumanUser(_ context.Context, req idp.EnsureHumanUserRequest) (string, error) {
	c.ensuredEmails = append(c.ensuredEmails, req.Email)
	if c.ensureErr != nil {
		return "", c.ensureErr
	}
	if c.ensureUserID == "" {
		return "user-ensured", nil
	}
	return c.ensureUserID, nil
}
func (c *membersIdPClient) Close() error { return nil }

// staticOrgResolver is a fixed tenant->org resolver for tests.
type staticOrgResolver struct {
	orgID string
	err   error
}

func (r staticOrgResolver) ZitadelOrgID(_ context.Context, _ string) (string, error) {
	return r.orgID, r.err
}

// ---------------------------------------------------------------------------
// Test fixture for ListMembers
// ---------------------------------------------------------------------------

func newMembersTestServer(t *testing.T, az *membersAuthorizer, idpC *membersIdPClient) *TenantAdminServer {
	t.Helper()
	cfg := TenantAdminConfig{
		Reader:         &fakeTenantConfigReader{},
		Writer:         &fakeTenantConfigWriter{},
		ProbeFactory:   &fakeProbeFactory{},
		Auditor:        &fakeAuditor{},
		Reloader:       &fakeReloader{},
		SecretsService: &fakeSecretsLister{},
		Authorizer:     az,
		// Only assign IdPAdminClient when non-nil to avoid a non-nil interface
		// wrapping a nil *membersIdPClient pointer (which defeats nil checks).
	}
	if idpC != nil {
		cfg.IdPAdminClient = idpC
	}
	srv, err := NewTenantAdminServer(cfg)
	if err != nil {
		t.Fatalf("NewTenantAdminServer: %v", err)
	}
	return srv
}

// ---------------------------------------------------------------------------
// ListMembers tests
// ---------------------------------------------------------------------------

// TestListMembers_TwoMembersOneAdmin verifies the canonical two-member scenario:
// both users appear, the admin has role="admin", the member has role="member",
// and display_name/email come from the IdP stub.
func TestListMembers_TwoMembersOneAdmin(t *testing.T) {
	az := &membersAuthorizer{
		members: []string{"user:alice-id", "user:bob-id"},
		admins:  map[string]bool{"alice-id": true},
	}
	idpC := &membersIdPClient{
		profiles: map[string]*idp.UserProfile{
			"alice-id": {AccountID: "alice-id", DisplayName: "Alice Admin", Email: "alice@example.com"},
			"bob-id":   {AccountID: "bob-id", DisplayName: "Bob Member", Email: "bob@example.com"},
		},
	}

	srv := newMembersTestServer(t, az, idpC)
	ctx := ctxWithTenant(t, "acme")

	resp, err := srv.ListMembers(ctx, &tenantv1.ListMembersRequest{})
	if err != nil {
		t.Fatalf("ListMembers: %v", err)
	}
	if len(resp.GetMembers()) != 2 {
		t.Fatalf("expected 2 members, got %d", len(resp.GetMembers()))
	}

	// Results are sorted by display_name: Alice < Bob.
	alice := resp.GetMembers()[0]
	bob := resp.GetMembers()[1]

	if alice.GetUserId() != "alice-id" {
		t.Errorf("members[0].user_id: got %q, want %q", alice.GetUserId(), "alice-id")
	}
	if alice.GetRole() != "admin" {
		t.Errorf("members[0].role: got %q, want %q", alice.GetRole(), "admin")
	}
	if alice.GetDisplayName() != "Alice Admin" {
		t.Errorf("members[0].display_name: got %q, want %q", alice.GetDisplayName(), "Alice Admin")
	}
	if alice.GetEmail() != "alice@example.com" {
		t.Errorf("members[0].email: got %q", alice.GetEmail())
	}

	if bob.GetUserId() != "bob-id" {
		t.Errorf("members[1].user_id: got %q, want %q", bob.GetUserId(), "bob-id")
	}
	if bob.GetRole() != "member" {
		t.Errorf("members[1].role: got %q, want %q", bob.GetRole(), "member")
	}
	if bob.GetDisplayName() != "Bob Member" {
		t.Errorf("members[1].display_name: got %q", bob.GetDisplayName())
	}
}

// TestListMembers_NilAuthorizer checks that ListMembers returns an empty list
// (not an error) when no authorizer is wired.
func TestListMembers_NilAuthorizer(t *testing.T) {
	srv, err := NewTenantAdminServer(TenantAdminConfig{
		Reader:         &fakeTenantConfigReader{},
		Writer:         &fakeTenantConfigWriter{},
		ProbeFactory:   &fakeProbeFactory{},
		Auditor:        &fakeAuditor{},
		Reloader:       &fakeReloader{},
		SecretsService: &fakeSecretsLister{},
		// Authorizer intentionally nil
	})
	if err != nil {
		t.Fatalf("NewTenantAdminServer: %v", err)
	}

	ctx := ctxWithTenant(t, "acme")
	resp, err := srv.ListMembers(ctx, &tenantv1.ListMembersRequest{})
	if err != nil {
		t.Fatalf("ListMembers: %v", err)
	}
	if len(resp.GetMembers()) != 0 {
		t.Errorf("expected empty list when authorizer is nil, got %d members", len(resp.GetMembers()))
	}
}

// TestListMembers_RequiresTenant verifies that the RPC returns PermissionDenied
// when the context carries no tenant.
func TestListMembers_RequiresTenant(t *testing.T) {
	az := &membersAuthorizer{}
	srv := newMembersTestServer(t, az, nil)
	_, err := srv.ListMembers(context.Background(), &tenantv1.ListMembersRequest{})
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("want PermissionDenied, got %v", err)
	}
}

// TestListMembers_NameFilterCaseInsensitive checks that name_filter does a
// case-insensitive prefix match on display_name.
func TestListMembers_NameFilterCaseInsensitive(t *testing.T) {
	az := &membersAuthorizer{
		members: []string{"user:alice-id", "user:bob-id"},
		admins:  map[string]bool{},
	}
	idpC := &membersIdPClient{
		profiles: map[string]*idp.UserProfile{
			"alice-id": {AccountID: "alice-id", DisplayName: "Alice Admin", Email: "alice@example.com"},
			"bob-id":   {AccountID: "bob-id", DisplayName: "Bob Member", Email: "bob@example.com"},
		},
	}

	srv := newMembersTestServer(t, az, idpC)
	ctx := ctxWithTenant(t, "acme")

	// "ali" should match "Alice Admin" case-insensitively.
	resp, err := srv.ListMembers(ctx, &tenantv1.ListMembersRequest{NameFilter: "ali"})
	if err != nil {
		t.Fatalf("ListMembers: %v", err)
	}
	if len(resp.GetMembers()) != 1 {
		t.Fatalf("expected 1 result for filter %q, got %d", "ali", len(resp.GetMembers()))
	}
	if resp.GetMembers()[0].GetUserId() != "alice-id" {
		t.Errorf("filter returned wrong member: %v", resp.GetMembers()[0])
	}
}

// TestListMembers_NameFilterOnEmail checks that name_filter also matches on email.
func TestListMembers_NameFilterOnEmail(t *testing.T) {
	az := &membersAuthorizer{
		members: []string{"user:alice-id", "user:carol-id"},
		admins:  map[string]bool{},
	}
	idpC := &membersIdPClient{
		profiles: map[string]*idp.UserProfile{
			"alice-id": {AccountID: "alice-id", DisplayName: "Alice", Email: "alice@example.com"},
			"carol-id": {AccountID: "carol-id", DisplayName: "Carol", Email: "carol@other.org"},
		},
	}

	srv := newMembersTestServer(t, az, idpC)
	ctx := ctxWithTenant(t, "acme")

	// "carol@" matches carol's email prefix.
	resp, err := srv.ListMembers(ctx, &tenantv1.ListMembersRequest{NameFilter: "carol@"})
	if err != nil {
		t.Fatalf("ListMembers: %v", err)
	}
	if len(resp.GetMembers()) != 1 {
		t.Fatalf("expected 1 result for email filter, got %d", len(resp.GetMembers()))
	}
	if resp.GetMembers()[0].GetUserId() != "carol-id" {
		t.Errorf("wrong user returned: %q", resp.GetMembers()[0].GetUserId())
	}
}

// TestListMembers_IdPClientNil verifies graceful degradation when idpClient is
// nil — members are returned without display_name or email.
func TestListMembers_IdPClientNil(t *testing.T) {
	az := &membersAuthorizer{
		members: []string{"user:alice-id"},
		admins:  map[string]bool{"alice-id": true},
	}

	srv := newMembersTestServer(t, az, nil) // nil idpClient
	ctx := ctxWithTenant(t, "acme")

	resp, err := srv.ListMembers(ctx, &tenantv1.ListMembersRequest{})
	if err != nil {
		t.Fatalf("ListMembers: %v", err)
	}
	if len(resp.GetMembers()) != 1 {
		t.Fatalf("expected 1 member, got %d", len(resp.GetMembers()))
	}
	m := resp.GetMembers()[0]
	if m.GetUserId() != "alice-id" {
		t.Errorf("user_id: got %q, want alice-id", m.GetUserId())
	}
	if m.GetDisplayName() != "" {
		t.Errorf("expected empty display_name when idpClient is nil, got %q", m.GetDisplayName())
	}
	if m.GetEmail() != "" {
		t.Errorf("expected empty email when idpClient is nil, got %q", m.GetEmail())
	}
	if m.GetRole() != "admin" {
		t.Errorf("role: got %q, want admin", m.GetRole())
	}
}

// TestListMembers_Pagination checks that page_size and page_token work correctly.
func TestListMembers_Pagination(t *testing.T) {
	az := &membersAuthorizer{
		members: []string{"user:u1", "user:u2", "user:u3", "user:u4", "user:u5"},
		admins:  map[string]bool{},
	}
	idpC := &membersIdPClient{
		profiles: map[string]*idp.UserProfile{
			"u1": {AccountID: "u1", DisplayName: "User1"},
			"u2": {AccountID: "u2", DisplayName: "User2"},
			"u3": {AccountID: "u3", DisplayName: "User3"},
			"u4": {AccountID: "u4", DisplayName: "User4"},
			"u5": {AccountID: "u5", DisplayName: "User5"},
		},
	}

	srv := newMembersTestServer(t, az, idpC)
	ctx := ctxWithTenant(t, "acme")

	// First page: 2 members.
	resp1, err := srv.ListMembers(ctx, &tenantv1.ListMembersRequest{PageSize: 2})
	if err != nil {
		t.Fatalf("ListMembers page 1: %v", err)
	}
	if len(resp1.GetMembers()) != 2 {
		t.Fatalf("page 1: expected 2 members, got %d", len(resp1.GetMembers()))
	}
	if resp1.GetNextPageToken() == "" {
		t.Error("expected non-empty next_page_token after first page")
	}

	// Second page: 2 members.
	resp2, err := srv.ListMembers(ctx, &tenantv1.ListMembersRequest{
		PageSize:  2,
		PageToken: resp1.GetNextPageToken(),
	})
	if err != nil {
		t.Fatalf("ListMembers page 2: %v", err)
	}
	if len(resp2.GetMembers()) != 2 {
		t.Fatalf("page 2: expected 2 members, got %d", len(resp2.GetMembers()))
	}
	if resp2.GetNextPageToken() == "" {
		t.Error("expected non-empty next_page_token after second page")
	}

	// Third (final) page: 1 member, no next_page_token.
	resp3, err := srv.ListMembers(ctx, &tenantv1.ListMembersRequest{
		PageSize:  2,
		PageToken: resp2.GetNextPageToken(),
	})
	if err != nil {
		t.Fatalf("ListMembers page 3: %v", err)
	}
	if len(resp3.GetMembers()) != 1 {
		t.Fatalf("page 3: expected 1 member, got %d", len(resp3.GetMembers()))
	}
	if resp3.GetNextPageToken() != "" {
		t.Errorf("expected empty next_page_token on last page, got %q", resp3.GetNextPageToken())
	}

	// Assert all 5 user IDs appear across the three pages with no duplicates.
	seen := map[string]bool{}
	for _, page := range [][]*tenantv1.TenantMember{resp1.GetMembers(), resp2.GetMembers(), resp3.GetMembers()} {
		for _, m := range page {
			if seen[m.GetUserId()] {
				t.Errorf("duplicate user_id %q across pages", m.GetUserId())
			}
			seen[m.GetUserId()] = true
		}
	}
	if len(seen) != 5 {
		t.Errorf("expected 5 unique user IDs across pages, got %d", len(seen))
	}
}

// TestListMembers_EmptyTenant verifies that an empty FGA user list returns an
// empty response without error.
func TestListMembers_EmptyTenant(t *testing.T) {
	az := &membersAuthorizer{
		members: []string{},
		admins:  map[string]bool{},
	}

	srv := newMembersTestServer(t, az, nil)
	ctx := ctxWithTenant(t, "acme")

	resp, err := srv.ListMembers(ctx, &tenantv1.ListMembersRequest{})
	if err != nil {
		t.Fatalf("ListMembers: %v", err)
	}
	if len(resp.GetMembers()) != 0 {
		t.Errorf("expected 0 members, got %d", len(resp.GetMembers()))
	}
}

// TestListMembers_IdPProfileFailureIsNonFatal checks that a GetUserProfile
// failure for one member does not fail the entire RPC — that member is
// returned without display_name or email.
func TestListMembers_IdPProfileFailureIsNonFatal(t *testing.T) {
	az := &membersAuthorizer{
		members: []string{"user:alice-id", "user:bob-id"},
		admins:  map[string]bool{},
	}
	idpC := &membersIdPClient{
		profiles: map[string]*idp.UserProfile{
			"alice-id": {AccountID: "alice-id", DisplayName: "Alice", Email: "alice@example.com"},
		},
		failFor: map[string]bool{"bob-id": true}, // bob's profile fetch fails
	}

	srv := newMembersTestServer(t, az, idpC)
	ctx := ctxWithTenant(t, "acme")

	resp, err := srv.ListMembers(ctx, &tenantv1.ListMembersRequest{})
	if err != nil {
		t.Fatalf("ListMembers: %v", err)
	}
	if len(resp.GetMembers()) != 2 {
		t.Fatalf("expected 2 members even with IdP failure, got %d", len(resp.GetMembers()))
	}
	// Check that bob is in the list with empty display_name.
	var bobFound bool
	for _, m := range resp.GetMembers() {
		if m.GetUserId() == "bob-id" {
			bobFound = true
			if m.GetDisplayName() != "" {
				t.Errorf("bob should have empty display_name on IdP failure, got %q", m.GetDisplayName())
			}
		}
	}
	if !bobFound {
		t.Error("bob-id not found in response despite IdP failure being non-fatal")
	}
}
