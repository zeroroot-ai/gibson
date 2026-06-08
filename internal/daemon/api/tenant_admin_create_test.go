package api

import (
	"context"
	"errors"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/audit"
	"github.com/zeroroot-ai/gibson/internal/authz"
	"github.com/zeroroot-ai/gibson/internal/idp"
	tenantpb "github.com/zeroroot-ai/sdk/api/gen/gibson/tenant/v1"
	"github.com/zeroroot-ai/sdk/auth"
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
	mintFn      func(ctx context.Context, accountID string) (clientID, clientSecret string, err error)
	deleteFn    func(ctx context.Context, accountID string) error
	listFn      func(ctx context.Context, req idp.ListServiceAccountsRequest) (*idp.ListServiceAccountsResponse, error)
	deleteCalls []string // tracks deleted accountIDs for rollback verification

	// RevokeUserSessions recording (gibson#622)
	revokedUsers []string
	revokeResult idp.RevokeUserSessionsResult
	revokeErr    error
}

func (f *fakeIDPClient) CreateServiceAccount(ctx context.Context, req idp.CreateServiceAccountRequest) (*idp.ServiceAccount, error) {
	if f.createFn != nil {
		return f.createFn(ctx, req)
	}
	return &idp.ServiceAccount{AccountID: "sa-test-id", Name: req.Name, Role: req.Role}, nil
}

func (f *fakeIDPClient) MintClientSecret(ctx context.Context, accountID string) (string, string, error) {
	if f.mintFn != nil {
		return f.mintFn(ctx, accountID)
	}
	// Distinct from the account/user id ("sa-test-id") on purpose: the response
	// ClientId must be this loginName-based client_id, not the user id.
	return "test-client-id", "test-secret", nil
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

func (f *fakeIDPClient) AddTenantMember(_ context.Context, _ idp.TenantMembershipRequest) error {
	return nil
}
func (f *fakeIDPClient) RemoveTenantMember(_ context.Context, _ idp.TenantMembershipRequest) error {
	return nil
}
func (f *fakeIDPClient) RevokeUserSessions(_ context.Context, userID string) (idp.RevokeUserSessionsResult, error) {
	f.revokedUsers = append(f.revokedUsers, userID)
	if f.revokeErr != nil {
		return idp.RevokeUserSessionsResult{}, f.revokeErr
	}
	return f.revokeResult, nil
}
func (f *fakeIDPClient) EnsureHumanUser(_ context.Context, _ idp.EnsureHumanUserRequest) (string, error) {
	return "user-1", nil
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
	// gibson#643: ClientId must be the loginName-based OAuth client_id returned
	// by MintClientSecret ("test-client-id"), NOT the machine-user/account id
	// ("sa-test-id"). The user id yields invalid_client at the token endpoint.
	if resp.ClientId != "test-client-id" {
		t.Errorf("ClientId = %q, want %q (loginName client_id, not the user id)", resp.ClientId, "test-client-id")
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

// TestCreateAgentIdentity_FGAOnlyNoMembership is the regression test for
// gibson#605. With an authorizer wired (the production configuration), every
// principal kind must register end-to-end via the FGA path alone: there is no
// IdP project/role membership step (the interface no longer exposes one), and
// the tenant binding is the `tenant:<id> belongs_to <kind>_principal:<sub>`
// tuple. Previously a vestigial AddTenantScopeMembership call failed closed
// (HTTP 400) and broke all registration.
func TestCreateAgentIdentity_FGAOnlyNoMembership(t *testing.T) {
	cases := []struct {
		kind    tenantpb.PrincipalKind
		fgaType string
	}{
		{tenantpb.PrincipalKind_PRINCIPAL_KIND_AGENT, "agent_principal"},
		{tenantpb.PrincipalKind_PRINCIPAL_KIND_TOOL, "tool_principal"},
		{tenantpb.PrincipalKind_PRINCIPAL_KIND_PLUGIN, "plugin_principal"},
	}
	for _, tc := range cases {
		t.Run(tc.fgaType, func(t *testing.T) {
			fakeidp := &fakeIDPClient{}
			az := newFakeAuthorizer()
			srv := newTestDaemonServer(t).
				WithIdPAdminClient(fakeidp).
				WithAuthorizer(az).
				WithTenantAdminAuditWriter(&fakeAuditWriter{})

			ctx := ctxWithTenantAdmin(context.Background(), "acme", "user-admin")
			resp, err := srv.CreateAgentIdentity(ctx, &tenantpb.CreateAgentIdentityRequest{
				Name: "my-principal",
				Kind: tc.kind,
			})
			if err != nil {
				t.Fatalf("CreateAgentIdentity(%s): %v", tc.fgaType, err)
			}
			if resp.ClientSecret == "" {
				t.Error("expected non-empty ClientSecret")
			}
			// No rollback: the saga must complete without deleting the SA.
			if len(fakeidp.deleteCalls) != 0 {
				t.Errorf("unexpected rollback: DeleteServiceAccount called %d times", len(fakeidp.deleteCalls))
			}
			// FGA is the sole tenancy authority: the belongs_to tuple binds the
			// principal to its tenant.
			want := authz.Tuple{
				User:     "tenant:acme",
				Relation: "belongs_to",
				Object:   tc.fgaType + ":sa-test-id",
			}
			var found bool
			for _, tup := range az.writtenTuples() {
				if tup == want {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected belongs_to tuple %+v in writes %+v", want, az.writtenTuples())
			}
			// Tenant membership: the principal is a `member` of its tenant so
			// rule-mode client RPCs (WhoAmI etc.) authorize over its CG-JWT
			// (ADR-0045). Model allows <kind>_principal as a tenant member.
			wantMember := authz.Tuple{
				User:     tc.fgaType + ":sa-test-id",
				Relation: "member",
				Object:   "tenant:acme",
			}
			var foundMember bool
			for _, tup := range az.writtenTuples() {
				if tup == wantMember {
					foundMember = true
					break
				}
			}
			if !foundMember {
				t.Errorf("expected member tuple %+v in writes %+v", wantMember, az.writtenTuples())
			}
			// ADR-0046 kind->grant policy: agents and tools are clients/invokers
			// and are granted direct_execute on the system backplane
			// (component:_system) so their client RPCs authorize; plugins are
			// invoked-only and are NOT granted it.
			wantSysExec := authz.Tuple{
				User:     tc.fgaType + ":sa-test-id",
				Relation: "direct_execute",
				Object:   "component:_system",
			}
			var foundSysExec bool
			for _, tup := range az.writtenTuples() {
				if tup == wantSysExec {
					foundSysExec = true
					break
				}
			}
			wantPresent := tc.fgaType == "agent_principal" || tc.fgaType == "tool_principal"
			if foundSysExec != wantPresent {
				t.Errorf("direct_execute component:_system for %s: got present=%v, want %v (writes %+v)",
					tc.fgaType, foundSysExec, wantPresent, az.writtenTuples())
			}
		})
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
		mintFn: func(_ context.Context, _ string) (string, string, error) {
			return "", "", errors.New("mint failed")
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

// TestBuildEnrollCommand pins the exact copy-pasteable command the
// dashboard wizard and CLI surface to customers. It MUST be a runnable
// `gibson component register` invocation against the shipped ADK CLI —
// not `gibson-cli agent enroll` (wrong binary, and `agent enroll`
// provisions a *new* identity and rejects these flags). See #590.
func TestBuildEnrollCommand(t *testing.T) {
	tests := []struct {
		name      string
		gibsonURL string
		clientID  string
		want      string
	}{
		{
			name:      "populated url",
			gibsonURL: "https://api.zeroroot.ai",
			clientID:  "1234567890123456",
			want:      "gibson component register --client-id 1234567890123456 --client-secret - --gibson-url https://api.zeroroot.ai",
		},
		{
			name:      "empty url falls back to placeholder",
			gibsonURL: "",
			clientID:  "1234567890123456",
			want:      "gibson component register --client-id 1234567890123456 --client-secret - --gibson-url <gibson-url>",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := buildEnrollCommand(tc.gibsonURL, tc.clientID)
			if got != tc.want {
				t.Errorf("buildEnrollCommand() =\n  %q\nwant\n  %q", got, tc.want)
			}
		})
	}
}

// TestClientCapabilityGrants_KindPolicy pins the ADR-0046 kind->grant table:
// agents and tools are clients (granted execute on the system backplane),
// plugins are invoked-only (no client grant).
func TestClientCapabilityGrants_KindPolicy(t *testing.T) {
	sysExec := authz.Tuple{User: "p:x", Relation: "direct_execute", Object: "component:_system"}
	cases := []struct {
		fgaType string
		want    []authz.Tuple
	}{
		{"agent_principal", []authz.Tuple{sysExec}},
		{"tool_principal", []authz.Tuple{sysExec}},
		{"plugin_principal", nil},
	}
	for _, tc := range cases {
		got := clientCapabilityGrants("p:x", tc.fgaType)
		if len(got) != len(tc.want) {
			t.Errorf("%s: got %d grants, want %d (%v)", tc.fgaType, len(got), len(tc.want), got)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("%s grant[%d] = %+v, want %+v", tc.fgaType, i, got[i], tc.want[i])
			}
		}
	}
}
