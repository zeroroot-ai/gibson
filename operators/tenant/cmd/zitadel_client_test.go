// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"context"
	"net/http"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/platform/zitadelconn"
	"github.com/zeroroot-ai/gibson/internal/platform/zitadelconn/zitadelconntest"
)

func testEndpoint(t *testing.T) zitadelconn.Endpoint {
	t.Helper()
	ep, err := zitadelconn.New("http://gibson-zitadel:8080", "app.example.test")
	if err != nil {
		t.Fatalf("endpoint: %v", err)
	}
	return ep
}

func TestNewZitadelClient_UsesTheOperatorsOwnCredentials(t *testing.T) {
	c, err := newZitadelClient(context.Background(), testEndpoint(t), "tenant-operator", "s3cret")
	if err != nil || c == nil {
		t.Fatalf("newZitadelClient = %v, %v; want a client", c, err)
	}
}

// TestNewZitadelClient_RefusesWithoutCredentials: with no client credentials
// there is no token, and the operator must not start (one-code-path).
func TestNewZitadelClient_RefusesWithoutCredentials(t *testing.T) {
	if _, err := newZitadelClient(context.Background(), testEndpoint(t), "", ""); err == nil {
		t.Fatal("newZitadelClient without client credentials = nil error, want refusal")
	}
}

// TestNewZitadelClient_RefusesAZeroEndpoint: an endpoint that zitadelconn
// never validated is refused, and the operator must not start (ADR-0092).
func TestNewZitadelClient_RefusesAZeroEndpoint(t *testing.T) {
	if _, err := newZitadelClient(context.Background(), zitadelconn.Endpoint{}, "tenant-operator", "s3cret"); err == nil {
		t.Fatal("newZitadelClient with a zero endpoint = nil error, want refusal")
	}
}

// TestNewPlatformTokenSource_AsksTheServiceNotTheIssuer is the gibson#222
// regression test. The token the operator sends to the dashboard comes from
// the in-cluster Zitadel Service, selected by the instance header. The fake
// answers 404 to a request that names no instance, and its claimed host can
// never resolve, so a client that dials the public issuer fails here.
func TestNewPlatformTokenSource_AsksTheServiceNotTheIssuer(t *testing.T) {
	fake := zitadelconntest.New(t, "", nil)
	ts, err := newPlatformTokenSource(context.Background(), fake.Endpoint(t), "tenant-operator", "s3cret")
	if err != nil {
		t.Fatalf("newPlatformTokenSource: %v", err)
	}
	tok, err := ts.Token()
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if tok.AccessToken != zitadelconntest.AccessToken {
		t.Errorf("access token = %q, want the token the Service issued", tok.AccessToken)
	}
	if n := fake.Refused(); n != 0 {
		t.Errorf("the fake refused %d request(s); the token request must carry the instance header", n)
	}
	if !fake.HasPath(http.MethodPost, "/oauth/v2/token") {
		t.Error("the token request did not reach the Service")
	}
}

func TestNewPlatformTokenSource_RefusesWithoutCredentials(t *testing.T) {
	if _, err := newPlatformTokenSource(context.Background(), testEndpoint(t), "", ""); err == nil {
		t.Fatal("newPlatformTokenSource without client credentials = nil error, want refusal")
	}
}

func TestNewTenantRoleGrants_UsesTheOperatorsOwnCredentials(t *testing.T) {
	g, err := newTenantRoleGrants(context.Background(), testEndpoint(t), "tenant-operator", "s3cret", "PROJ-1")
	if err != nil || g == nil {
		t.Fatalf("newTenantRoleGrants = %v, %v; want grants", g, err)
	}
}

func TestNewTenantRoleGrants_RefusesWithoutCredentials(t *testing.T) {
	if _, err := newTenantRoleGrants(context.Background(), testEndpoint(t), "", "", "PROJ-1"); err == nil {
		t.Fatal("newTenantRoleGrants without client credentials = nil error, want refusal")
	}
}
