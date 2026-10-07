// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/platform/idp/zitadel"
	"github.com/zeroroot-ai/gibson/internal/platform/zitadelconn/zitadelconntest"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

// TestListMembers_BootstrapOwnerProfileThroughTheRealClient is the profile
// half of gibson#482 on the real path. The first-admin job creates the owner
// in the org of the tenant (EnsureHumanUserNoPassword(ctx, orgID, ...)), not
// in the org of the admin client. The fake Zitadel answers the v1 profile
// call only under the owning org, as Zitadel does, and reports not found for
// any other org. Before gibson#349 the client sent its own org, so the owner
// row had no name and no email.
func TestListMembers_BootstrapOwnerProfileThroughTheRealClient(t *testing.T) {
	const ownerID, tenantOrg = "392629408583647281", "org-tenant-acme"
	srv := zitadelconntest.New(t, "", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v2/users/"+ownerID:
			_ = json.NewEncoder(w).Encode(map[string]any{"details": map[string]string{"resourceOwner": tenantOrg}})
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/management/v1/users/"+ownerID):
			if r.Header.Get("x-zitadel-orgid") != tenantOrg {
				w.WriteHeader(http.StatusNotFound)
				_ = json.NewEncoder(w).Encode(map[string]any{"code": 5, "message": "User could not be found"})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"user": map[string]any{
				"id": ownerID, "state": "USER_STATE_ACTIVE",
				"human": map[string]any{
					"profile": map[string]string{"displayName": "First Admin"},
					"email":   map[string]string{"email": "admin@example.com"},
				},
			}})
		default:
			http.NotFound(w, r)
		}
	}))
	client, err := zitadel.New(context.Background(), zitadel.Config{
		Issuer:       "https://" + srv.Domain,
		ClientID:     "admin-client",
		ClientSecret: "admin-secret",
		OrgID:        "org-platform",
		Endpoint:     srv.Endpoint(t),
	})
	if err != nil {
		t.Fatalf("zitadel.New: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	az := &membersAuthorizer{members: []string{"user:" + ownerID}, owners: map[string]bool{ownerID: true}}
	cfg := TenantAdminConfig{
		Reader: &fakeTenantConfigReader{}, Writer: &fakeTenantConfigWriter{}, ProbeFactory: &fakeProbeFactory{},
		Auditor: &fakeAuditor{}, Reloader: &fakeReloader{}, SecretsService: &fakeSecretsLister{},
		Authorizer: az, IdPAdminClient: client,
	}
	srvAdmin, err := NewTenantAdminServer(cfg)
	if err != nil {
		t.Fatalf("NewTenantAdminServer: %v", err)
	}

	resp, err := srvAdmin.ListMembers(ctxWithTenant(t, "acme"), &tenantv1.ListMembersRequest{})
	if err != nil {
		t.Fatalf("ListMembers: %v", err)
	}
	if len(resp.GetMembers()) != 1 {
		t.Fatalf("members = %v, want the owner", resp.GetMembers())
	}
	m := resp.GetMembers()[0]
	if m.GetRole() != "owner" || m.GetDisplayName() != "First Admin" || m.GetEmail() != "admin@example.com" {
		t.Fatalf("owner row = %+v, want role owner, a name and an email", m)
	}
}
