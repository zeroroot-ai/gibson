package admin

import (
	"context"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/internal/platform/idp"

	adminv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

// rosterAuthorizer is a minimal authz.Authorizer for ListTeamMembers tests:
// Check (parent ownership) returns true, and ListUsers returns the roster for
// the "member" relation (no separate admins).
type rosterAuthorizer struct{ users []string }

func (r *rosterAuthorizer) Check(context.Context, string, string, string) (bool, error) {
	return true, nil
}
func (r *rosterAuthorizer) BatchCheck(context.Context, []authz.CheckRequest) ([]bool, error) {
	return nil, nil
}
func (r *rosterAuthorizer) Write(context.Context, []authz.Tuple) error  { return nil }
func (r *rosterAuthorizer) Delete(context.Context, []authz.Tuple) error { return nil }
func (r *rosterAuthorizer) ListObjects(context.Context, string, string, string) ([]string, error) {
	return nil, nil
}
func (r *rosterAuthorizer) ListUsers(_ context.Context, _, _, relation string) ([]string, error) {
	if relation == "admin" {
		return nil, nil
	}
	return r.users, nil
}
func (r *rosterAuthorizer) StoreID() string { return "test" }
func (r *rosterAuthorizer) ModelID() string { return "test" }
func (r *rosterAuthorizer) Close() error    { return nil }

// TestListTeamMembers_EnrichesIdentity locks the fix: the team roster must
// carry display name + email from the IdP (not just the raw Zitadel sub), the
// same as ListMembers. Regression for the "roster shows a UUID" bug.
func TestListTeamMembers_EnrichesIdentity(t *testing.T) {
	az := &rosterAuthorizer{users: []string{"user:alice-id"}}
	idpC := &membersIdPClient{
		profiles: map[string]*idp.UserProfile{
			"alice-id": {AccountID: "alice-id", DisplayName: "Alice Admin", Email: "alice@example.com"},
		},
	}

	srv, err := NewTenantAdminServer(TenantAdminConfig{
		Reader:         &fakeTenantConfigReader{},
		Writer:         &fakeTenantConfigWriter{},
		ProbeFactory:   &fakeProbeFactory{},
		Auditor:        &fakeAuditor{},
		Reloader:       &fakeReloader{},
		SecretsService: &fakeSecretsLister{},
		Authorizer:     az,
		IdPAdminClient: idpC,
	})
	if err != nil {
		t.Fatalf("NewTenantAdminServer: %v", err)
	}

	ctx := ctxWithTenant(t, "acme")
	resp, err := srv.ListTeamMembers(ctx, &adminv1.ListTeamMembersRequest{TeamId: "red"})
	if err != nil {
		t.Fatalf("ListTeamMembers: %v", err)
	}
	if len(resp.GetMembers()) != 1 {
		t.Fatalf("expected 1 member, got %d", len(resp.GetMembers()))
	}
	m := resp.GetMembers()[0]
	if m.GetUserId() != "alice-id" {
		t.Errorf("user_id: got %q, want %q", m.GetUserId(), "alice-id")
	}
	if m.GetDisplayName() != "Alice Admin" {
		t.Errorf("display_name not enriched: got %q, want %q", m.GetDisplayName(), "Alice Admin")
	}
	if m.GetEmail() != "alice@example.com" {
		t.Errorf("email not enriched: got %q, want %q", m.GetEmail(), "alice@example.com")
	}
}
