// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package zitadel_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/platform/idp"
	"github.com/zeroroot-ai/gibson/internal/platform/idp/zitadel"
	"github.com/zeroroot-ai/gibson/internal/platform/zitadelconn"
	"github.com/zeroroot-ai/gibson/internal/platform/zitadelconn/zitadelconntest"
)

// TestCreateHumanUser_ReachesTheServiceAndSelectsTheInstance is the regression
// test for the staging failure of 2026-09-23 (hosted#185, ADR-0092).
//
// The first-admin bootstrap could not create the founding owner. Its admin
// client dialed the public issuer host; hostAliases sent that to the public
// Envoy edge; the edge's auth chain rejected the admin write with 403, which
// surfaced as "admin client lacks permission: CreateHumanUser:create". The
// earlier test for the same symptom (gibson#1560) used a fake that answered
// every request whatever its host, so it could not see the problem.
//
// This fake behaves like Zitadel: a request that does not name the instance in
// x-zitadel-instance-host gets 404. The client must therefore:
//
//  1. connect only to the in-cluster base, never to a public name (the claimed
//     host is under .invalid, so any attempt to dial it fails the run);
//  2. name the instance on the token request and on the Management call;
//  3. use the fixed token path and never fetch a discovery document;
//  4. send CreateHumanUser to the Management API with the tenant org in
//     x-zitadel-orgid, not the admin client's default org.
func TestCreateHumanUser_ReachesTheServiceAndSelectsTheInstance(t *testing.T) {
	const (
		adminOrg  = "111111111111111111"
		tenantOrg = "387872765320888363"
	)
	var (
		createOrgHeader string
		createBody      map[string]interface{}
	)
	srv := zitadelconntest.New(t, "", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/management/v1/users/human" {
			createOrgHeader = r.Header.Get("x-zitadel-orgid")
			raw, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(raw, &createBody)
			jsonResp(w, http.StatusOK, map[string]string{"userId": "owner-user-id"})
			return
		}
		http.Error(w, "unexpected path "+r.URL.Path, http.StatusNotFound)
	}))

	client, err := zitadel.New(context.Background(), zitadel.Config{
		Issuer:       "https://" + srv.Domain,
		ClientID:     "gibson-daemon",
		ClientSecret: "admin-secret",
		OrgID:        adminOrg,
		Endpoint:     srv.Endpoint(t),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
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
	if n := srv.Refused(); n != 0 {
		t.Errorf("%d request(s) did not name the instance; every request must carry %s", n, zitadelconn.InstanceHostHeader)
	}
	if !srv.HasPath(http.MethodPost, "/oauth/v2/token") {
		t.Errorf("the token request did not reach the in-cluster base: %v", srv.Paths())
	}
	if srv.HasPath(http.MethodGet, "/.well-known/openid-configuration") {
		t.Error("the client fetched a discovery document; ADR-0092 uses fixed paths")
	}
	if !srv.HasPath(http.MethodPost, "/management/v1/users/human") {
		t.Errorf("create did not reach the Management API: %v", srv.Paths())
	}
	if createOrgHeader != tenantOrg {
		t.Errorf("x-zitadel-orgid = %q, want the tenant org %q (not the admin default %q)",
			createOrgHeader, tenantOrg, adminOrg)
	}
	if createBody["initialPassword"] != "s3cret-passw0rd!" {
		t.Errorf("initialPassword not forwarded: %v", createBody["initialPassword"])
	}
}

// A client built without the instance header is what staging ran. The fake
// refuses it at the token request, before any Management call.
func TestNew_RefusedWhenTheInstanceIsNotNamed(t *testing.T) {
	srv := zitadelconntest.New(t, "", nil)
	wrong, err := zitadelconn.New(srv.URL, "some-other-host.invalid")
	if err != nil {
		t.Fatal(err)
	}
	_, err = zitadel.New(context.Background(), zitadel.Config{
		Issuer: "https://" + srv.Domain, ClientID: "c", ClientSecret: "s", Endpoint: wrong,
	})
	if err == nil {
		t.Fatal("New succeeded against an instance it did not name")
	}
	if srv.Refused() == 0 {
		t.Error("the fake never saw the refused request")
	}
}

func TestNew_RequiresAnEndpoint(t *testing.T) {
	_, err := zitadel.New(context.Background(), zitadel.Config{
		Issuer: "https://app.example.invalid", ClientID: "c", ClientSecret: "s",
	})
	if !errors.Is(err, idp.ErrUnreachable) {
		t.Fatalf("want ErrUnreachable without an endpoint, got %v", err)
	}
}
