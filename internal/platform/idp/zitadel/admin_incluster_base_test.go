// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package zitadel_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/platform/idp"
	"github.com/zeroroot-ai/gibson/internal/platform/idp/zitadel"
)

// TestCreateHumanUser_RoutesToInClusterBase_AgainstTenantOrg is the regression
// test for gibson#1560: on a self-hosted install the first-admin bootstrap could
// not create the founding owner because the daemon's Zitadel admin client sent
// its Management API calls to the external Issuer host — the customer API gateway
// (Envoy's jwt_authn + ext_authz chain) — which 403s admin writes. The in-cluster
// listener the daemon is meant to dial (Config.DiscoveryURL) proxies the
// Management API straight through, so writes must ride the DiscoveryURL path.
//
// This test proves the client, when DiscoveryURL is set:
//
//  1. sends CreateHumanUser to the in-cluster base (DiscoveryURL), NOT Issuer —
//     Issuer is a non-resolvable sentinel, so any egress to it fails the run;
//  2. targets the Zitadel Management create endpoint (/management/v1/users/human),
//     the surface the in-cluster proxy exposes — never the /v2 resource API;
//  3. selects the freshly-provisioned tenant org via the x-zitadel-orgid header,
//     even though the admin client's default OrgID is the platform admin org.
func TestCreateHumanUser_RoutesToInClusterBase_AgainstTenantOrg(t *testing.T) {
	const (
		adminOrg  = "111111111111111111" // client default org (platform admin org)
		tenantOrg = "387872765320888363" // the per-tenant org the owner belongs to
	)

	var (
		servedDiscovery bool
		createPath      string
		createOrgHeader string
		createBody      map[string]interface{}
	)

	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/.well-known/openid-configuration":
			servedDiscovery = true
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"token_endpoint": srvURL + "/oauth/v2/token"})
		case r.URL.Path == "/oauth/v2/token":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "test-admin-token", "token_type": "Bearer", "expires_in": 3600,
			})
		case r.Method == http.MethodPost && r.URL.Path == "/management/v1/users/human":
			createPath = r.URL.Path
			createOrgHeader = r.Header.Get("x-zitadel-orgid")
			raw, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(raw, &createBody)
			jsonResp(w, http.StatusOK, map[string]string{"userId": "owner-user-id"})
		default:
			// A /v2/... call, or a call to any other path, is a bug under test.
			http.Error(w, "unexpected path "+r.URL.Path, http.StatusNotFound)
		}
	}))
	srvURL = srv.URL
	t.Cleanup(srv.Close)

	cfg := zitadel.Config{
		// Issuer is a host that does NOT resolve. If the client dials it for
		// discovery, token, or the management call, the run fails — proving the
		// in-cluster DiscoveryURL path carries ALL traffic, not just discovery.
		Issuer:       "https://public-gateway.gibson-1560.invalid",
		DiscoveryURL: srv.URL,
		ClientID:     "gibson-daemon",
		ClientSecret: "admin-secret",
		OrgID:        adminOrg,
	}

	client, err := zitadel.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New (must dial the in-cluster DiscoveryURL, not the sentinel Issuer): %v", err)
	}
	defer closeClient(t, client)

	res, err := client.CreateHumanUser(context.Background(), idp.CreateHumanUserRequest{
		OrgID:         tenantOrg,
		Email:         "owner@tenant.example",
		GivenName:     "Founding",
		FamilyName:    "Owner",
		Password:      "s3cret-passw0rd!",
		EmailVerified: true,
	})
	if err != nil {
		t.Fatalf("CreateHumanUser against the tenant org: %v", err)
	}
	if res.UserID != "owner-user-id" {
		t.Errorf("UserID = %q, want owner-user-id", res.UserID)
	}
	if !servedDiscovery {
		t.Error("discovery was not served by the in-cluster base — the client dialed the Issuer host")
	}
	if createPath != "/management/v1/users/human" {
		t.Errorf("create hit %q, want /management/v1/users/human (the Management API, not /v2)", createPath)
	}
	if createOrgHeader != tenantOrg {
		t.Errorf("x-zitadel-orgid = %q, want the tenant org %q (not the admin default %q)",
			createOrgHeader, tenantOrg, adminOrg)
	}
	if createBody["initialPassword"] != "s3cret-passw0rd!" {
		t.Errorf("initialPassword not forwarded: %v", createBody["initialPassword"])
	}
}
