// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package admin

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	identitypb "github.com/zeroroot-ai/sdk/api/gen/gibson/identity/v1"
	"github.com/zeroroot-ai/sdk/auth"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/internal/platform/identity"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

// tenantSecrets is a SecretNameLister with a fixed list for each tenant.
type tenantSecrets map[string][]string

func (t tenantSecrets) List(_ context.Context, tenant auth.TenantID) ([]string, error) {
	return t[tenant.String()], nil
}

const (
	grantTenant   = "acme"
	otherTenant   = "globex"
	grantPlugin   = "plugin_principal:p-1"
	foreignPlugin = "plugin_principal:p-9"
)

func secretGrantLookup() *stubLookup {
	return &stubLookup{records: map[string]identity.PrincipalRecord{
		grantPlugin:           {PrincipalID: grantPlugin, TenantID: grantTenant, Kind: identitypb.PrincipalKind_PRINCIPAL_KIND_PLUGIN},
		foreignPlugin:         {PrincipalID: foreignPlugin, TenantID: otherTenant, Kind: identitypb.PrincipalKind_PRINCIPAL_KIND_PLUGIN},
		"agent_principal:a-1": {PrincipalID: "agent_principal:a-1", TenantID: grantTenant, Kind: identitypb.PrincipalKind_PRINCIPAL_KIND_AGENT},
	}}
}

func newSecretGrantServer(t *testing.T, az authz.Authorizer) *GrantsAdminServer {
	t.Helper()
	srv, err := NewGrantsAdminServer(GrantsAdminConfig{
		Reader:      noopReader{},
		Authorizer:  az,
		Lookup:      secretGrantLookup(),
		SecretNames: tenantSecrets{grantTenant: {"cred:github_token", "cred:db"}, otherTenant: {"cred:theirs"}},
	})
	if err != nil {
		t.Fatalf("NewGrantsAdminServer: %v", err)
	}
	return srv
}

func wantCode(t *testing.T, err error, code codes.Code) {
	t.Helper()
	if status.Code(err) != code {
		t.Fatalf("want %s, got %v", code, err)
	}
}

func TestWriteSecretGrants_WritesCanResolveInTheCallersTenant(t *testing.T) {
	az := &stubAuthorizer{present: map[string]bool{}}
	srv := newSecretGrantServer(t, az)

	resp, err := srv.WriteSecretGrants(adminCtx(t, grantTenant), &tenantv1.WriteSecretGrantsRequest{
		TargetPrincipalId: grantPlugin,
		SecretNames:       []string{"cred:github_token", "cred:github_token"},
	})
	if err != nil {
		t.Fatalf("WriteSecretGrants: %v", err)
	}
	if resp.GetWritten() != 1 || resp.GetAlreadyPresent() != 0 {
		t.Fatalf("counts = (%d, %d), want (1, 0)", resp.GetWritten(), resp.GetAlreadyPresent())
	}
	want := authz.Tuple{User: grantPlugin, Relation: "can_resolve", Object: authz.SecretObject(grantTenant, "cred:github_token")}
	if len(az.wrote) != 1 || az.wrote[0] != want {
		t.Fatalf("wrote %+v, want [%+v]", az.wrote, want)
	}
}

func TestWriteSecretGrants_AnEmptyGrantIsValid(t *testing.T) {
	az := &stubAuthorizer{present: map[string]bool{}}
	srv := newSecretGrantServer(t, az)
	resp, err := srv.WriteSecretGrants(adminCtx(t, grantTenant), &tenantv1.WriteSecretGrantsRequest{TargetPrincipalId: grantPlugin})
	if err != nil {
		t.Fatalf("WriteSecretGrants: %v", err)
	}
	if resp.GetWritten() != 0 || len(az.wrote) != 0 {
		t.Fatalf("an empty grant wrote %d tuples", len(az.wrote))
	}
}

func TestWriteSecretGrants_RefusesASecretOfAnotherTenant(t *testing.T) {
	az := &stubAuthorizer{present: map[string]bool{}}
	srv := newSecretGrantServer(t, az)
	_, err := srv.WriteSecretGrants(adminCtx(t, grantTenant), &tenantv1.WriteSecretGrantsRequest{
		TargetPrincipalId: grantPlugin,
		SecretNames:       []string{"cred:theirs"},
	})
	wantCode(t, err, codes.NotFound)
	if len(az.wrote) != 0 {
		t.Fatalf("a refused grant wrote %+v", az.wrote)
	}
}

func TestWriteSecretGrants_RefusesAPrincipalOfAnotherTenant(t *testing.T) {
	az := &stubAuthorizer{present: map[string]bool{}}
	srv := newSecretGrantServer(t, az)
	_, err := srv.WriteSecretGrants(adminCtx(t, grantTenant), &tenantv1.WriteSecretGrantsRequest{
		TargetPrincipalId: foreignPlugin,
		SecretNames:       []string{"cred:db"},
	})
	wantCode(t, err, codes.NotFound)
	if len(az.wrote) != 0 {
		t.Fatalf("a refused grant wrote %+v", az.wrote)
	}
}

func TestWriteSecretGrants_RefusesAnAgentOrToolTarget(t *testing.T) {
	az := &stubAuthorizer{present: map[string]bool{}}
	srv := newSecretGrantServer(t, az)
	for _, target := range []string{"agent_principal:a-1", "tool_principal:t-1"} {
		_, err := srv.WriteSecretGrants(adminCtx(t, grantTenant), &tenantv1.WriteSecretGrantsRequest{
			TargetPrincipalId: target,
			SecretNames:       []string{"cred:db"},
		})
		wantCode(t, err, codes.InvalidArgument)
	}
	if len(az.wrote) != 0 {
		t.Fatalf("a refused grant wrote %+v", az.wrote)
	}
}

func TestWriteSecretGrants_IsOffWithoutTheSecretsStack(t *testing.T) {
	srv, err := NewGrantsAdminServer(GrantsAdminConfig{
		Reader: noopReader{}, Authorizer: &stubAuthorizer{}, Lookup: secretGrantLookup(),
	})
	if err != nil {
		t.Fatalf("NewGrantsAdminServer: %v", err)
	}
	_, err = srv.WriteSecretGrants(adminCtx(t, grantTenant), &tenantv1.WriteSecretGrantsRequest{TargetPrincipalId: grantPlugin})
	wantCode(t, err, codes.Unimplemented)
}

func TestNewGrantsAdminServer_SecretNamesNeedAnAuthorizer(t *testing.T) {
	_, err := NewGrantsAdminServer(GrantsAdminConfig{Reader: noopReader{}, SecretNames: tenantSecrets{}})
	if err == nil {
		t.Fatal("expected an error when SecretNames comes without an Authorizer")
	}
}
