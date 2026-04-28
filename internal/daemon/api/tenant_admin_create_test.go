package api

import (
	"context"
	"errors"
	"testing"

	"github.com/zero-day-ai/gibson/internal/audit"
	tenantpb "github.com/zero-day-ai/gibson/internal/daemon/api/gibson/tenant/v1"
	"github.com/zero-day-ai/gibson/internal/idp"
	"github.com/zero-day-ai/sdk/auth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// newTestDaemonServer returns a minimal DaemonServer for handler unit tests.
// It does NOT set up any external dependencies (FGA, audit, IdP).
// Callers chain With* methods to add what they need.
func newTestDaemonServer(t interface{ Helper() }) *DaemonServer {
	_ = t
	return &DaemonServer{
		logger: testSlogLogger,
	}
}

// ---------------------------------------------------------------------------
// Fake IdP client for testing
// ---------------------------------------------------------------------------

type fakeIDPClient struct {
	createFn    func(ctx context.Context, req idp.CreateServiceAccountRequest) (*idp.ServiceAccount, error)
	mintFn      func(ctx context.Context, accountID string) (string, error)
	addMemberFn func(ctx context.Context, req idp.AddMembershipRequest) error
	deleteFn    func(ctx context.Context, accountID string) error
	listFn      func(ctx context.Context, req idp.ListServiceAccountsRequest) (*idp.ListServiceAccountsResponse, error)
	deleteCalls []string // tracks deleted accountIDs for rollback verification
}

func (f *fakeIDPClient) CreateServiceAccount(ctx context.Context, req idp.CreateServiceAccountRequest) (*idp.ServiceAccount, error) {
	if f.createFn != nil {
		return f.createFn(ctx, req)
	}
	return &idp.ServiceAccount{AccountID: "sa-test-id", Name: req.Name, Role: req.Role}, nil
}

func (f *fakeIDPClient) MintClientSecret(ctx context.Context, accountID string) (string, error) {
	if f.mintFn != nil {
		return f.mintFn(ctx, accountID)
	}
	return "test-secret", nil
}

func (f *fakeIDPClient) AddTenantScopeMembership(ctx context.Context, req idp.AddMembershipRequest) error {
	if f.addMemberFn != nil {
		return f.addMemberFn(ctx, req)
	}
	return nil
}

func (f *fakeIDPClient) DeleteServiceAccount(ctx context.Context, accountID string) error {
	f.deleteCalls = append(f.deleteCalls, accountID)
	if f.deleteFn != nil {
		return f.deleteFn(ctx, accountID)
	}
	return nil
}

func (f *fakeIDPClient) ListServiceAccounts(ctx context.Context, req idp.ListServiceAccountsRequest) (*idp.ListServiceAccountsResponse, error) {
	if f.listFn != nil {
		return f.listFn(ctx, req)
	}
	return &idp.ListServiceAccountsResponse{}, nil
}

func (f *fakeIDPClient) GetUserProfile(_ context.Context, _ string) (*idp.UserProfile, error) {
	return nil, idp.ErrNotFound
}

func (f *fakeIDPClient) UpdateUserProfile(_ context.Context, _ string, _ idp.UpdateUserProfileRequest) (*idp.UserProfile, error) {
	return nil, idp.ErrNotFound
}

func (f *fakeIDPClient) Close() error { return nil }

// ---------------------------------------------------------------------------
// Fake audit writer
// ---------------------------------------------------------------------------

type fakeAuditWriter struct {
	events []audit.Event
}

func (f *fakeAuditWriter) Log(event audit.Event) {
	f.events = append(f.events, event)
}

// ---------------------------------------------------------------------------
// Test context helper — injects a valid auth.Identity
// ---------------------------------------------------------------------------

func ctxWithTenantAdmin(ctx context.Context, tenantID, subject string) context.Context {
	// TenantStringFromContext reads Identity.Tenant, not a separate context key.
	// We must set the tenant in the Identity struct, not via auth.WithTenant.
	t, _ := auth.NewTenantID(tenantID)
	id := auth.Identity{
		Subject: subject,
		Issuer:  auth.IssuerOIDC,
		Tenant:  t,
	}
	return auth.WithIdentity(ctx, id)
}

// ---------------------------------------------------------------------------
// CreateAgentIdentity tests
// ---------------------------------------------------------------------------

func TestCreateAgentIdentity_HappyPath(t *testing.T) {
	fakeidp := &fakeIDPClient{}
	fakeAudit := &fakeAuditWriter{}

	srv := newTestDaemonServer(t).
		WithIdPAdminClient(fakeidp).
		WithTenantAdminAuditWriter(fakeAudit)

	ctx := ctxWithTenantAdmin(context.Background(), "acme", "user-admin")

	resp, err := srv.CreateAgentIdentity(ctx, &tenantpb.CreateAgentIdentityRequest{
		Name:        "my-agent",
		Kind:        tenantpb.PrincipalKind_PRINCIPAL_KIND_AGENT,
		Description: "A test agent",
	})
	if err != nil {
		t.Fatalf("CreateAgentIdentity: %v", err)
	}
	if resp.ClientSecret == "" {
		t.Error("expected non-empty ClientSecret")
	}
	if resp.ClientSecret != "test-secret" {
		t.Errorf("ClientSecret = %q, want %q", resp.ClientSecret, "test-secret")
	}
	if resp.PrincipalId == "" {
		t.Error("expected non-empty PrincipalId")
	}
	// Verify audit event was emitted.
	if len(fakeAudit.events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(fakeAudit.events))
	}
	if fakeAudit.events[0].Action != "agent_identity.created" {
		t.Errorf("audit action = %q, want %q", fakeAudit.events[0].Action, "agent_identity.created")
	}
	// Verify no rollback was triggered.
	if len(fakeidp.deleteCalls) != 0 {
		t.Errorf("unexpected rollback: DeleteServiceAccount called %d times", len(fakeidp.deleteCalls))
	}
}

func TestCreateAgentIdentity_InvalidName(t *testing.T) {
	fakeidp := &fakeIDPClient{}
	srv := newTestDaemonServer(t).WithIdPAdminClient(fakeidp)
	ctx := ctxWithTenantAdmin(context.Background(), "acme", "user-admin")

	for _, name := range []string{"A", "1abc", "ab", "this-name-is-way-way-too-long-for-our-regex-constraint-here-yes"} {
		_, err := srv.CreateAgentIdentity(ctx, &tenantpb.CreateAgentIdentityRequest{
			Name: name,
			Kind: tenantpb.PrincipalKind_PRINCIPAL_KIND_AGENT,
		})
		if err == nil {
			t.Errorf("name %q: expected InvalidArgument, got nil", name)
			continue
		}
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("name %q: got code %v, want InvalidArgument", name, status.Code(err))
		}
	}
}

func TestCreateAgentIdentity_AlreadyExists(t *testing.T) {
	fakeidp := &fakeIDPClient{
		createFn: func(_ context.Context, _ idp.CreateServiceAccountRequest) (*idp.ServiceAccount, error) {
			return nil, idp.ErrAlreadyExists
		},
	}
	srv := newTestDaemonServer(t).WithIdPAdminClient(fakeidp)
	ctx := ctxWithTenantAdmin(context.Background(), "acme", "user-admin")

	_, err := srv.CreateAgentIdentity(ctx, &tenantpb.CreateAgentIdentityRequest{
		Name: "dup-agent",
		Kind: tenantpb.PrincipalKind_PRINCIPAL_KIND_AGENT,
	})
	if status.Code(err) != codes.AlreadyExists {
		t.Errorf("got code %v, want AlreadyExists", status.Code(err))
	}
}

func TestCreateAgentIdentity_RollbackOnMintFailure(t *testing.T) {
	fakeidp := &fakeIDPClient{
		mintFn: func(_ context.Context, _ string) (string, error) {
			return "", errors.New("mint failed")
		},
	}
	srv := newTestDaemonServer(t).WithIdPAdminClient(fakeidp)
	ctx := ctxWithTenantAdmin(context.Background(), "acme", "user-admin")

	_, err := srv.CreateAgentIdentity(ctx, &tenantpb.CreateAgentIdentityRequest{
		Name: "rollback-agent",
		Kind: tenantpb.PrincipalKind_PRINCIPAL_KIND_AGENT,
	})
	if status.Code(err) != codes.Internal {
		t.Errorf("got code %v, want Internal", status.Code(err))
	}
	if len(fakeidp.deleteCalls) != 1 {
		t.Errorf("expected 1 rollback delete call, got %d", len(fakeidp.deleteCalls))
	}
}

func TestCreateAgentIdentity_AgentPrincipalRefused(t *testing.T) {
	fakeidp := &fakeIDPClient{}
	srv := newTestDaemonServer(t).WithIdPAdminClient(fakeidp)

	// Inject a context where the caller is itself an agent_principal.
	t2, _ := auth.NewTenantID("acme")
	id := auth.Identity{
		Subject: "agent_principal:some-agent-id",
		Issuer:  auth.IssuerOIDC,
		Tenant:  t2,
	}
	ctx := auth.WithIdentity(context.Background(), id)

	_, err := srv.CreateAgentIdentity(ctx, &tenantpb.CreateAgentIdentityRequest{
		Name: "my-agent",
		Kind: tenantpb.PrincipalKind_PRINCIPAL_KIND_AGENT,
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("got code %v, want PermissionDenied", status.Code(err))
	}
	if len(fakeidp.deleteCalls) != 0 {
		t.Error("unexpected IdP call for refused agent-principal caller")
	}
}

func TestCreateAgentIdentity_NoIdPConfigured(t *testing.T) {
	srv := newTestDaemonServer(t) // no idp client wired
	ctx := ctxWithTenantAdmin(context.Background(), "acme", "user-admin")

	_, err := srv.CreateAgentIdentity(ctx, &tenantpb.CreateAgentIdentityRequest{
		Name: "my-agent",
		Kind: tenantpb.PrincipalKind_PRINCIPAL_KIND_AGENT,
	})
	if status.Code(err) != codes.Unavailable {
		t.Errorf("got code %v, want Unavailable", status.Code(err))
	}
}
