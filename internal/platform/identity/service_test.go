// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package identity

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	identitypb "github.com/zeroroot-ai/sdk/api/gen/gibson/identity/v1"
	"github.com/zeroroot-ai/sdk/auth"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
)

// fakeAuthorizer is a minimal authz.Authorizer for testing. Only
// ListObjects is exercised by IdentityServer.WhoAmI.
type fakeAuthorizer struct {
	listObjectsFn func(user, relation, objectType string) ([]string, error)
	// checkFn, when set, backs Check — used by the can_revoke_sessions
	// capability tests (gibson#628). When nil, Check returns the legacy
	// "not implemented" error so existing tests keep their behaviour.
	checkFn func(user, relation, object string) (bool, error)
	// listUsersOfTypeFn backs ListUsersOfType, the typed principal lookup.
	listUsersOfTypeFn func(objectType, object, relation, userType string) ([]string, error)
}

func (f *fakeAuthorizer) Check(_ context.Context, user, relation, object string) (bool, error) {
	if f.checkFn != nil {
		return f.checkFn(user, relation, object)
	}
	return false, errors.New("not implemented")
}
func (f *fakeAuthorizer) BatchCheck(_ context.Context, _ []authz.CheckRequest) ([]bool, error) {
	return nil, errors.New("not implemented")
}
func (f *fakeAuthorizer) Write(_ context.Context, _ []authz.Tuple) error  { return nil }
func (f *fakeAuthorizer) Delete(_ context.Context, _ []authz.Tuple) error { return nil }
func (f *fakeAuthorizer) ListObjects(_ context.Context, user, relation, objectType string) ([]string, error) {
	return f.listObjectsFn(user, relation, objectType)
}
func (f *fakeAuthorizer) ListUsers(_ context.Context, _, _, _ string) ([]string, error) {
	return nil, errors.New("not implemented")
}
func (f *fakeAuthorizer) StoreID() string { return "test" }
func (f *fakeAuthorizer) ModelID() string { return "test" }
func (f *fakeAuthorizer) Close() error    { return nil }

// fakeLookup implements PrincipalLookup for tests.
type fakeLookup struct {
	records map[string]PrincipalRecord
}

func (f *fakeLookup) Resolve(_ context.Context, principalID string) (PrincipalRecord, error) {
	rec, ok := f.records[principalID]
	if !ok {
		return PrincipalRecord{}, ErrPrincipalNotFound
	}
	return rec, nil
}

// ctxWithIdentity injects an auth.Identity + tenant into the context
// the way ext-authz would in production.
func ctxWithIdentity(t *testing.T, subject, tenant string) context.Context {
	t.Helper()
	tid, err := auth.NewTenantID(tenant)
	if err != nil {
		t.Fatalf("NewTenantID(%q): %v", tenant, err)
	}
	id := auth.Identity{Subject: subject, Tenant: tid}
	return auth.WithIdentity(context.Background(), id)
}

func TestWhoAmI_SelfQueryAggregatesGrants(t *testing.T) {
	subject := "agent_principal:abc-123"
	authzr := &fakeAuthorizer{
		listObjectsFn: func(user, relation, objectType string) ([]string, error) {
			if user != subject {
				t.Fatalf("listObjects user mismatch: got %q want %q", user, subject)
			}
			switch {
			case objectType == "component" && relation == "can_read":
				return []string{"component:gitlab", "component:nmap"}, nil
			case objectType == "component" && relation == "can_configure":
				return []string{"component:gitlab"}, nil
			case objectType == "component" && relation == "can_execute":
				return []string{"component:nmap"}, nil
			case objectType == "plugin" && relation == "can_invoke":
				return nil, nil
			}
			return nil, nil
		},
	}

	srv, err := NewServer(Config{Authorizer: authzr, Lookup: &fakeLookup{}})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	ctx := ctxWithIdentity(t, subject, "zeroroot-ai")
	resp, err := srv.WhoAmI(ctx, &identitypb.WhoAmIRequest{})
	if err != nil {
		t.Fatalf("WhoAmI: %v", err)
	}

	if resp.GetPrincipalId() != subject {
		t.Errorf("principal_id = %q, want %q", resp.GetPrincipalId(), subject)
	}
	if resp.GetKind() != identitypb.PrincipalKind_PRINCIPAL_KIND_AGENT {
		t.Errorf("kind = %v, want PRINCIPAL_KIND_AGENT", resp.GetKind())
	}
	if got := len(resp.GetComponentGrants()); got != 2 {
		t.Errorf("component_grants len = %d, want 2", got)
	}
	for _, g := range resp.GetComponentGrants() {
		switch g.GetComponentRef() {
		case "component:gitlab":
			if !g.GetCanRead() || !g.GetCanConfigure() {
				t.Errorf("gitlab missing read+configure: %+v", g)
			}
		case "component:nmap":
			if !g.GetCanRead() || !g.GetCanExecute() {
				t.Errorf("nmap missing read+execute: %+v", g)
			}
		}
	}
	if len(resp.GetPluginGrants()) != 0 {
		t.Errorf("agent should have no plugin grants; got %v", resp.GetPluginGrants())
	}
}

// emptyGrantsList returns empty for the component/plugin grant lookups so a
// can_revoke_sessions test can focus on the admin/team relations. It defers
// the ("admin","team") lookup to teamFn.
func emptyGrantsList(teamFn func() []string) func(user, relation, objectType string) ([]string, error) {
	return func(_, relation, objectType string) ([]string, error) {
		if objectType == "team" && relation == "admin" {
			return teamFn(), nil
		}
		return nil, nil
	}
}

// TestWhoAmI_CanRevokeSessions covers the coarse capability flag (gibson#628):
// a tenant admin or a team admin gets true; everyone else gets false; and a
// typed component principal short-circuits to false without any FGA Check.
func TestWhoAmI_CanRevokeSessions(t *testing.T) {
	const tenant = "zeroroot-ai"

	cases := []struct {
		name        string
		subject     string
		tenantAdmin bool
		adminTeams  []string
		wantRevoke  bool
		wantNoCheck bool // Check must not be called (component principal)
	}{
		{name: "tenant admin", subject: "u-1", tenantAdmin: true, wantRevoke: true},
		{name: "team admin only", subject: "u-2", tenantAdmin: false, adminTeams: []string{"team:eng"}, wantRevoke: true},
		{name: "plain member", subject: "u-3", tenantAdmin: false, adminTeams: nil, wantRevoke: false},
		{name: "component principal short-circuits", subject: "agent_principal:a-1", wantRevoke: false, wantNoCheck: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			authzr := &fakeAuthorizer{
				listObjectsFn: emptyGrantsList(func() []string { return tc.adminTeams }),
				checkFn: func(user, relation, object string) (bool, error) {
					if tc.wantNoCheck {
						t.Fatalf("Check must not be called for a component principal (got %q %q %q)", user, relation, object)
					}
					if user == "user:"+tc.subject && relation == "admin" && object == "tenant:"+tenant {
						return tc.tenantAdmin, nil
					}
					return false, nil
				},
			}
			srv, err := NewServer(Config{Authorizer: authzr, Lookup: &fakeLookup{}})
			if err != nil {
				t.Fatalf("NewServer: %v", err)
			}
			resp, err := srv.WhoAmI(ctxWithIdentity(t, tc.subject, tenant), &identitypb.WhoAmIRequest{})
			if err != nil {
				t.Fatalf("WhoAmI: %v", err)
			}
			if got := resp.GetCanRevokeSessions(); got != tc.wantRevoke {
				t.Errorf("CanRevokeSessions = %v, want %v", got, tc.wantRevoke)
			}
		})
	}
}

// TestWhoAmI_CanRevokeSessions_FGAErrorNonFatal verifies the capability check
// is non-fatal: an FGA failure leaves the flag false but WhoAmI still returns
// the core identity payload (gibson#628).
func TestWhoAmI_CanRevokeSessions_FGAErrorNonFatal(t *testing.T) {
	authzr := &fakeAuthorizer{
		listObjectsFn: emptyGrantsList(func() []string { return nil }),
		checkFn: func(_, _, _ string) (bool, error) {
			return false, errors.New("fga unavailable")
		},
	}
	srv, err := NewServer(Config{Authorizer: authzr, Lookup: &fakeLookup{}})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	resp, err := srv.WhoAmI(ctxWithIdentity(t, "u-err", "zeroroot-ai"), &identitypb.WhoAmIRequest{})
	if err != nil {
		t.Fatalf("WhoAmI must succeed despite a capability-check FGA error: %v", err)
	}
	if resp.GetCanRevokeSessions() {
		t.Error("CanRevokeSessions must be false when the FGA check errors (fail-closed)")
	}
	if resp.GetPrincipalId() != "u-err" {
		t.Errorf("core identity must still be returned; principal_id = %q", resp.GetPrincipalId())
	}
}

func TestWhoAmI_AdminCrossTenantRejected(t *testing.T) {
	authzr := &fakeAuthorizer{
		listObjectsFn: func(user, relation, objectType string) ([]string, error) {
			return nil, nil
		},
	}
	lookup := &fakeLookup{
		records: map[string]PrincipalRecord{
			"agent_principal:other": {
				PrincipalID: "agent_principal:other",
				TenantID:    "OTHER-TENANT",
				Name:        "agent_principal:other",
				Kind:        identitypb.PrincipalKind_PRINCIPAL_KIND_AGENT,
			},
		},
	}
	srv, _ := NewServer(Config{Authorizer: authzr, Lookup: lookup})

	ctx := ctxWithIdentity(t, "user:admin", "zeroroot-ai")
	_, err := srv.WhoAmI(ctx, &identitypb.WhoAmIRequest{
		TargetPrincipalId: "agent_principal:other",
	})
	if err == nil {
		t.Fatal("expected PermissionDenied for cross-tenant target, got nil")
	}
}

func TestWhoAmI_TargetNotFound(t *testing.T) {
	srv, _ := NewServer(Config{
		Authorizer: &fakeAuthorizer{listObjectsFn: func(_, _, _ string) ([]string, error) { return nil, nil }},
		Lookup:     &fakeLookup{},
	})
	ctx := ctxWithIdentity(t, "user:admin", "zeroroot-ai")
	_, err := srv.WhoAmI(ctx, &identitypb.WhoAmIRequest{
		TargetPrincipalId: "agent_principal:does-not-exist",
	})
	if err == nil {
		t.Fatal("expected NotFound for unknown principal, got nil")
	}
}

// ListUsersOfType backs the typed principal lookup. It is on authz.Authorizer
// because a gate reached by type assertion was silently skipped by every
// double that did not implement it. With no function set it lists nothing.
func (f *fakeAuthorizer) ListUsersOfType(_ context.Context, objectType, object, relation, userType string) ([]string, error) {
	if f.listUsersOfTypeFn == nil {
		return nil, nil
	}
	return f.listUsersOfTypeFn(objectType, object, relation, userType)
}

// strictFGA mimics OpenFGA's request validation: a user that is not
// type:id is rejected with an invalid-argument error. It records the users
// it saw for the plugin can_invoke listing.
func strictFGA(pluginUsers *[]string) *fakeAuthorizer {
	return &fakeAuthorizer{
		listObjectsFn: func(user, relation, objectType string) ([]string, error) {
			// FGA rejects a bare id and a user value that keeps a SPIFFE
			// scheme ("spiffe://..." is not a type:id object).
			if !strings.Contains(user, ":") || strings.HasPrefix(user, "spiffe://") {
				return nil, &authz.FgaError{
					Sentinel: authz.ErrInvalidArgument,
					Message:  "invalid 'user' value: the 'user' field must be an object",
				}
			}
			if objectType == "plugin" && relation == "can_invoke" {
				*pluginUsers = append(*pluginUsers, user)
				return []string{"plugin:p1"}, nil
			}
			return nil, nil
		},
	}
}

// TestWhoAmI_HumanCaller: a human OIDC caller carries a bare subject. WhoAmI
// must send FGA the user:<sub> form, not the bare subject (gibson#455).
func TestWhoAmI_HumanCaller(t *testing.T) {
	var pluginUsers []string
	srv, err := NewServer(Config{Authorizer: strictFGA(&pluginUsers), Lookup: &fakeLookup{}})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	ctx := ctxWithIdentity(t, "human-sub-1", "tenant-a")
	resp, err := srv.WhoAmI(ctx, &identitypb.WhoAmIRequest{})
	if err != nil {
		t.Fatalf("WhoAmI: %v", err)
	}
	if got := resp.GetPrincipalId(); got != "human-sub-1" {
		t.Errorf("principal_id = %q, want human-sub-1", got)
	}
	if len(pluginUsers) != 1 || pluginUsers[0] != "user:human-sub-1" {
		t.Errorf("plugin can_invoke user = %v, want [user:human-sub-1]", pluginUsers)
	}
	if len(resp.GetPluginGrants()) != 1 {
		t.Errorf("plugin grants = %v, want 1", resp.GetPluginGrants())
	}
}

// TestWhoAmI_FGAErrorStatus: an FGA validation fault is InvalidArgument and an
// outage is Unavailable. Neither is a bare Internal.
func TestWhoAmI_FGAErrorStatus(t *testing.T) {
	for _, tc := range []struct {
		name     string
		sentinel error
		want     codes.Code
	}{
		{"invalid", authz.ErrInvalidArgument, codes.InvalidArgument},
		{"unavailable", authz.ErrFgaUnavailable, codes.Unavailable},
		{"timeout", authz.ErrFgaTimeout, codes.DeadlineExceeded},
		{"other", errors.New("boom"), codes.Internal},
	} {
		t.Run(tc.name, func(t *testing.T) {
			az := &fakeAuthorizer{listObjectsFn: func(_, relation, _ string) ([]string, error) {
				if relation == "can_invoke" {
					return nil, &authz.FgaError{Sentinel: tc.sentinel, Message: "x"}
				}
				return nil, nil
			}}
			srv, err := NewServer(Config{Authorizer: az, Lookup: &fakeLookup{}})
			if err != nil {
				t.Fatalf("NewServer: %v", err)
			}
			ctx := ctxWithIdentity(t, "human-sub-1", "tenant-a")
			_, err = srv.WhoAmI(ctx, &identitypb.WhoAmIRequest{})
			if got := status.Code(err); got != tc.want {
				t.Fatalf("code = %v (%v), want %v", got, err, tc.want)
			}
		})
	}
}

// TestFGALookup_HumanTargetUsesUserRef: the admin variant resolves a bare
// human subject through FGALookup. FGA must see user:<sub>.
func TestFGALookup_HumanTargetUsesUserRef(t *testing.T) {
	var seen string
	lk := &FGALookup{Authorizer: &fakeAuthorizer{
		listObjectsFn: func(user, _, _ string) ([]string, error) {
			seen = user
			return []string{"tenant:acme"}, nil
		},
	}}
	rec, err := lk.Resolve(context.Background(), "human-sub-1")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if seen != "user:human-sub-1" {
		t.Errorf("FGA user = %q, want user:human-sub-1", seen)
	}
	if rec.TenantID != "acme" || rec.PrincipalID != "human-sub-1" {
		t.Errorf("record = %+v", rec)
	}
}

// ctxWithCredential is ctxWithIdentity with an explicit credential class.
func ctxWithCredential(t *testing.T, subject, tenant string, cred auth.CredentialType) context.Context {
	t.Helper()
	tid, err := auth.NewTenantID(tenant)
	if err != nil {
		t.Fatalf("NewTenantID(%q): %v", tenant, err)
	}
	return auth.WithIdentity(context.Background(), auth.Identity{
		Subject: subject, Tenant: tid, CredentialType: cred,
	})
}

// TestWhoAmI_SelfKind: the self case reports the kind of the caller. A person
// who signed in through OIDC is USER. A typed component principal keeps its
// prefix kind. A caller that is neither stays UNSPECIFIED.
func TestWhoAmI_SelfKind(t *testing.T) {
	for _, tc := range []struct {
		name    string
		subject string
		cred    auth.CredentialType
		want    identitypb.PrincipalKind
	}{
		{"oidc person", "392845542176063539", auth.CredentialOIDCUser, identitypb.PrincipalKind_PRINCIPAL_KIND_USER},
		{"service account", "svc-sub-1", auth.CredentialClientCredentials, identitypb.PrincipalKind_PRINCIPAL_KIND_UNSPECIFIED},
		{"agent principal", "agent_principal:a1", auth.CredentialClientCredentials, identitypb.PrincipalKind_PRINCIPAL_KIND_AGENT},
		{"typed principal over oidc credential", "tool_principal:t1", auth.CredentialOIDCUser, identitypb.PrincipalKind_PRINCIPAL_KIND_TOOL},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, err := NewServer(Config{Authorizer: &fakeAuthorizer{
				listObjectsFn: func(_, _, _ string) ([]string, error) { return nil, nil },
				checkFn:       func(_, _, _ string) (bool, error) { return false, nil },
			}, Lookup: &fakeLookup{}})
			if err != nil {
				t.Fatalf("NewServer: %v", err)
			}
			resp, err := srv.WhoAmI(ctxWithCredential(t, tc.subject, "tenant-a", tc.cred), &identitypb.WhoAmIRequest{})
			if err != nil {
				t.Fatalf("WhoAmI: %v", err)
			}
			if got := resp.GetKind(); got != tc.want {
				t.Errorf("kind = %s, want %s", got, tc.want)
			}
		})
	}
}

// TestNewServer_RefusesAMissingDependency proves that no IdentityServer
// exists without its authorizer and its lookup (gibson#681). Each request
// path can then use both without a nil check.
func TestNewServer_RefusesAMissingDependency(t *testing.T) {
	cases := map[string]Config{
		"no authorizer": {Lookup: &fakeLookup{}},
		"no lookup":     {Authorizer: &fakeAuthorizer{}},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			srv, err := NewServer(cfg)
			if err == nil || srv != nil {
				t.Fatalf("NewServer(%s) = %v, %v; want nil and an error", name, srv, err)
			}
		})
	}
}

// TestFGALookup_TypedPrincipalReadsItsTenant: a machine principal holds its
// tenant as the user of its belongs_to relation, (tenant:<id>, belongs_to,
// <type>:<id>). The lookup lists the tenants on that relation of the
// principal (gibson#1162). The old query asked for tenant#belongs_to, which
// the model does not have, and FGA refused it.
func TestFGALookup_TypedPrincipalReadsItsTenant(t *testing.T) {
	for _, tc := range []struct {
		id   string
		typ  string
		kind identitypb.PrincipalKind
	}{
		{"plugin_principal:github.primary", "plugin_principal", identitypb.PrincipalKind_PRINCIPAL_KIND_PLUGIN},
		{"agent_principal:a1", "agent_principal", identitypb.PrincipalKind_PRINCIPAL_KIND_AGENT},
		{"tool_principal:t1", "tool_principal", identitypb.PrincipalKind_PRINCIPAL_KIND_TOOL},
	} {
		var got [4]string
		lk := &FGALookup{Authorizer: &fakeAuthorizer{
			listObjectsFn: func(_, _, _ string) ([]string, error) {
				return nil, errors.New("a typed principal must not be read with ListObjects")
			},
			listUsersOfTypeFn: func(objectType, object, relation, userType string) ([]string, error) {
				got = [4]string{objectType, object, relation, userType}
				return []string{"tenant:primary"}, nil
			},
		}}
		rec, err := lk.Resolve(context.Background(), tc.id)
		if err != nil {
			t.Fatalf("%s: Resolve: %v", tc.id, err)
		}
		if want := [4]string{tc.typ, tc.id, "belongs_to", "tenant"}; got != want {
			t.Errorf("%s: ListUsersOfType%v, want %v", tc.id, got, want)
		}
		if rec.TenantID != "primary" || rec.PrincipalID != tc.id || rec.Kind != tc.kind {
			t.Errorf("%s: record = %+v", tc.id, rec)
		}
	}
}

// TestFGALookup_NoTenantIsNotFound: a principal with no tenant tuple is
// not found, and an FGA error is an error.
func TestFGALookup_NoTenantIsNotFound(t *testing.T) {
	empty := &FGALookup{Authorizer: &fakeAuthorizer{}}
	if _, err := empty.Resolve(context.Background(), "plugin_principal:gone.primary"); !errors.Is(err, ErrPrincipalNotFound) {
		t.Errorf("err = %v, want ErrPrincipalNotFound", err)
	}
	broken := &FGALookup{Authorizer: &fakeAuthorizer{
		listUsersOfTypeFn: func(_, _, _, _ string) ([]string, error) { return nil, errors.New("fga down") },
	}}
	if _, err := broken.Resolve(context.Background(), "plugin_principal:x.primary"); err == nil ||
		errors.Is(err, ErrPrincipalNotFound) {
		t.Errorf("err = %v, want the FGA error", err)
	}
}

// TestFGALookup_QueriesExistInTheModel reads the embedded model: each
// relation the lookup asks for exists on its type and admits the user type
// the lookup asks for. FGA refuses a query on a relation the model does not
// have, which is how the old query failed on every call (gibson#1162).
func TestFGALookup_QueriesExistInTheModel(t *testing.T) {
	raw, err := authz.ModelJSON()
	if err != nil {
		t.Fatalf("ModelJSON: %v", err)
	}
	var model struct {
		TypeDefinitions []struct {
			Type     string `json:"type"`
			Metadata struct {
				Relations map[string]struct {
					DirectlyRelatedUserTypes []struct {
						Type string `json:"type"`
					} `json:"directly_related_user_types"`
				} `json:"relations"`
			} `json:"metadata"`
		} `json:"type_definitions"`
	}
	if err := json.Unmarshal([]byte(raw), &model); err != nil {
		t.Fatalf("parse model: %v", err)
	}
	if len(model.TypeDefinitions) == 0 {
		t.Fatal("the model parsed to no type definitions: this check would pass on nothing")
	}
	admits := func(objectType, relation, userType string) bool {
		for _, td := range model.TypeDefinitions {
			if td.Type != objectType {
				continue
			}
			for _, u := range td.Metadata.Relations[relation].DirectlyRelatedUserTypes {
				if u.Type == userType {
					return true
				}
			}
		}
		return false
	}
	for _, q := range [][3]string{
		{"agent_principal", "belongs_to", "tenant"},
		{"tool_principal", "belongs_to", "tenant"},
		{"plugin_principal", "belongs_to", "tenant"},
		{"tenant", "member", "user"},
	} {
		if !admits(q[0], q[1], q[2]) {
			t.Errorf("the model has no %s#%s that admits %s, which FGALookup asks for", q[0], q[1], q[2])
		}
	}
}

// TestWhoAmI_SPIFFECaller: a SPIFFE caller is asked about in the form of its
// FGA tuples (principal.IDOf): its id without the scheme. The raw
// spiffe://... id is a user value that FGA rejects (gibson#1212).
func TestWhoAmI_SPIFFECaller(t *testing.T) {
	var pluginUsers []string
	var adminChecks []string
	fga := strictFGA(&pluginUsers)
	fga.checkFn = func(user, relation, object string) (bool, error) {
		adminChecks = append(adminChecks, user+" "+relation+" "+object)
		return relation == "admin" && object == "tenant:tenant-a" && user == "user:zeroroot.ai/platform/e2e-runner", nil
	}
	srv, err := NewServer(Config{Authorizer: fga, Lookup: &fakeLookup{}})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	ctx := ctxWithIdentity(t, "spiffe://zeroroot.ai/platform/e2e-runner", "tenant-a")
	resp, err := srv.WhoAmI(ctx, &identitypb.WhoAmIRequest{})
	if err != nil {
		t.Fatalf("WhoAmI: %v", err)
	}
	if got := resp.GetPrincipalId(); got != "zeroroot.ai/platform/e2e-runner" {
		t.Errorf("principal_id = %q, want zeroroot.ai/platform/e2e-runner", got)
	}
	if len(pluginUsers) != 1 || pluginUsers[0] != "user:zeroroot.ai/platform/e2e-runner" {
		t.Errorf("plugin can_invoke user = %v, want [user:zeroroot.ai/platform/e2e-runner]", pluginUsers)
	}
	if len(adminChecks) == 0 || adminChecks[0] != "user:zeroroot.ai/platform/e2e-runner admin tenant:tenant-a" {
		t.Errorf("can_revoke_sessions checks = %v, want the tenant admin check in the tuple form", adminChecks)
	}
	if !resp.GetCanRevokeSessions() {
		t.Error("a SPIFFE tenant admin can revoke sessions")
	}
}

// A rejected credential and a missing store are a fault of the daemon, so they
// are FailedPrecondition and not the Internal default.
func TestFGAStatus_PermanentFaultsAreFailedPrecondition(t *testing.T) {
	for name, cause := range map[string]error{
		"unauthenticated": authz.ErrFgaUnauthenticated,
		"not found":       authz.ErrFgaNotFound,
	} {
		if got := status.Code(fgaStatus("check", cause)); got != codes.FailedPrecondition {
			t.Errorf("%s: want FailedPrecondition, got %v", name, got)
		}
	}
	if got := status.Code(fgaStatus("check", authz.ErrFgaUnavailable)); got != codes.Unavailable {
		t.Errorf("an outage must stay Unavailable, got %v", got)
	}
}
