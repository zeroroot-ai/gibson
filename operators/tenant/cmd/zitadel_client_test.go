// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/platform/zitadelconn"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
)

// TestBuildTenantOperatorZitadelClient_Success verifies a valid URL and
// external domain produce a usable client, with no network call made at
// construction time (the token is only fetched lazily on first request).
func TestBuildTenantOperatorZitadelClient_Success(t *testing.T) {
	c, err := buildTenantOperatorZitadelClient("client-id", "client-secret", "http://gibson-zitadel:8080", "app.example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c == nil {
		t.Fatal("expected a non-nil client")
	}
}

// TestBuildTenantOperatorZitadelClient_BadExternalDomain verifies a
// misconfigured ZITADEL_EXTERNAL_DOMAIN (e.g. one carrying a port, which
// zitadelconn refuses per ADR-0092) surfaces as an error rather than a
// client that silently misroutes every request.
func TestBuildTenantOperatorZitadelClient_BadExternalDomain(t *testing.T) {
	_, err := buildTenantOperatorZitadelClient("client-id", "client-secret", "http://gibson-zitadel:8080", "app.example.com:8443")
	if err == nil {
		t.Fatal("expected an error for a ported external domain")
	}
}

// TestBuildTenantOperatorZitadelClient_TokenObtainedFromOwnCredentials
// verifies the returned client requests a token using the given
// clientID/clientSecret and carries it on a real Management API call as a
// bearer token, and that the token request itself claims the external
// domain by header (ADR-0092) rather than dialing it.
func TestBuildTenantOperatorZitadelClient_TokenObtainedFromOwnCredentials(t *testing.T) {
	var gotAuth, gotHost, gotTokenInstanceHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/v2/token" {
			gotTokenInstanceHeader = r.Header.Get(zitadelconn.InstanceHostHeader)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"test-token","token_type":"Bearer","expires_in":3600}`))
			return
		}
		gotAuth = r.Header.Get("Authorization")
		gotHost = r.Host
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"result":[]}`))
	}))
	t.Cleanup(srv.Close)

	c, err := buildTenantOperatorZitadelClient("client-id", "client-secret", srv.URL, "app.example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := c.GetOrganization(context.Background(), "org-1"); !errors.Is(err, clients.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for an empty result set, got %v", err)
	}
	if gotAuth != "Bearer test-token" {
		t.Errorf("expected the operator's own client_credentials token, got Authorization=%q", gotAuth)
	}
	if gotHost != "app.example.com" {
		t.Errorf("expected the Management API request's Host to be forged to the external domain, got %q", gotHost)
	}
	if gotTokenInstanceHeader != "app.example.com" {
		t.Errorf("expected the token request to claim the instance by header (ADR-0092), got %q", gotTokenInstanceHeader)
	}
}
