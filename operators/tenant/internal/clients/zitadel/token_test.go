// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package zitadel

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/oauth2"

	"github.com/zeroroot-ai/gibson/internal/platform/zitadelconn"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
)

// TestTokenSources_ClientCredentialsForTheOperatorsOwnUser proves the client
// authenticates with a client_credentials token for the operator's own
// machine user: the grant, the scopes, the instance header, and the token on
// the API call that follows. One token serves both calls.
func TestTokenSources_ClientCredentialsForTheOperatorsOwnUser(t *testing.T) {
	var tokenCalls int
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/v2/token":
			tokenCalls++
			if got := r.Header.Get(zitadelconn.InstanceHostHeader); got != "app.example.test" {
				t.Errorf("token request instance header = %q, want app.example.test", got)
			}
			if err := r.ParseForm(); err != nil {
				t.Fatalf("parse form: %v", err)
			}
			if got := r.PostForm.Get("grant_type"); got != "client_credentials" {
				t.Errorf("grant_type = %q, want client_credentials", got)
			}
			if got := r.PostForm.Get("scope"); !strings.Contains(got, "urn:zitadel:iam:org:project:id:zitadel:aud") {
				t.Errorf("scope = %q, want the zitadel audience scope", got)
			}
			id, secret, ok := r.BasicAuth()
			if !ok || id != "tenant-operator" || secret != "s3cret" {
				t.Errorf("client auth = %q/%q (basic=%v), want the operator's own client", id, secret, ok)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"op-token","token_type":"Bearer","expires_in":3600}`))
		case "/v2/organizations/_search":
			gotAuth = r.Header.Get("Authorization")
			if got := r.Header.Get(zitadelconn.InstanceHostHeader); got != testDomain {
				t.Errorf("API request instance header = %q, want %s", got, testDomain)
			}
			if r.Host == testDomain {
				t.Errorf("API request Host = %q: the client must not forge the Host header (ADR-0092)", r.Host)
			}
			writeJSON(w, http.StatusOK, map[string]any{"result": []any{}})
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected", http.StatusInternalServerError)
		}
	}))
	t.Cleanup(srv.Close)

	ep, err := zitadelconn.New(srv.URL, testDomain)
	if err != nil {
		t.Fatalf("endpoint: %v", err)
	}
	ts, err := NewTokenSources(context.Background(), ep, "tenant-operator", "s3cret")
	if err != nil {
		t.Fatalf("NewTokenSources: %v", err)
	}
	c := mustNew(t, srv.URL, ts.API)
	for range 2 {
		if _, err := c.GetOrganization(context.Background(), "org-1"); !errors.Is(err, clients.ErrNotFound) {
			t.Fatalf("GetOrganization: %v, want ErrNotFound from the empty search", err)
		}
	}
	if gotAuth != "Bearer op-token" {
		t.Errorf("API Authorization = %q, want the operator's own token", gotAuth)
	}
	if tokenCalls != 1 {
		t.Errorf("token requests = %d, want 1 (the token is cached)", tokenCalls)
	}
}

func testEndpoint(t *testing.T) zitadelconn.Endpoint {
	t.Helper()
	ep, err := zitadelconn.New("http://zitadel:8080", testDomain)
	if err != nil {
		t.Fatalf("endpoint: %v", err)
	}
	return ep
}

func TestTokenSources_RefuseMissingCredentials(t *testing.T) {
	for _, tc := range []struct{ id, secret string }{{"", "s"}, {"id", ""}} {
		if _, err := NewTokenSources(context.Background(), testEndpoint(t), tc.id, tc.secret); err == nil {
			t.Errorf("NewTokenSources(%q, %q) = nil error, want refusal", tc.id, tc.secret)
		}
	}
}

// TestTokenSources_RefuseAZeroEndpoint: a token request with no validated
// endpoint has nowhere to go and no host to claim.
func TestTokenSources_RefuseAZeroEndpoint(t *testing.T) {
	if _, err := NewTokenSources(context.Background(), zitadelconn.Endpoint{}, "id", "s"); err == nil {
		t.Error("NewTokenSources with a zero endpoint = nil error, want refusal")
	}
}

// TestTokenSources_PlatformNamesThePlatformAudience pins the audience scope
// of the token the operator sends to the dashboard, and proves that its
// request goes to the Service with the instance header (gibson#222). Envoy
// jwt_authn rejects a token without gibson-platform in its audience.
func TestTokenSources_PlatformNamesThePlatformAudience(t *testing.T) {
	var gotScope string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		gotScope = r.PostForm.Get("scope")
		if got := r.Header.Get(zitadelconn.InstanceHostHeader); got != testDomain {
			t.Errorf("token request instance header = %q, want %s", got, testDomain)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"p","token_type":"Bearer","expires_in":3600}`))
	}))
	t.Cleanup(srv.Close)
	ep, err := zitadelconn.New(srv.URL, testDomain)
	if err != nil {
		t.Fatalf("endpoint: %v", err)
	}
	ts, err := NewTokenSources(context.Background(), ep, "tenant-operator", "s3cret")
	if err != nil {
		t.Fatalf("NewTokenSources: %v", err)
	}
	if _, err := ts.Platform.Token(); err != nil {
		t.Fatalf("Token: %v", err)
	}
	if !strings.Contains(gotScope, "urn:zitadel:iam:org:project:id:gibson-platform:aud") {
		t.Errorf("scope = %q, want the gibson-platform audience scope", gotScope)
	}
}

type failingTokens struct{}

func (failingTokens) Token() (*oauth2.Token, error) { return nil, errors.New("token endpoint down") }

// TestRequest_TokenFailureIsTransient proves a failed token fetch sends no
// request and surfaces as unreachable, so the saga retries instead of failing
// the tenant.
func TestRequest_TokenFailureIsTransient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		t.Errorf("no API request may go out without a token, got %s %s", r.Method, r.URL.Path)
	}))
	t.Cleanup(srv.Close)
	c := mustNew(t, srv.URL, failingTokens{})
	_, err := c.CreateOrganization(context.Background(), "t", "t")
	if !errors.Is(err, clients.ErrUnreachable) {
		t.Fatalf("CreateOrganization with a failing token source: %v, want ErrUnreachable", err)
	}
}
