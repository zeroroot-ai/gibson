// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package zitadelconn_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/platform/zitadelconn"
	"github.com/zeroroot-ai/gibson/internal/platform/zitadelconn/zitadelconntest"
)

func TestNew_ValidatesTheTwoFacts(t *testing.T) {
	cases := []struct {
		name, url, host string
		wantErr         string
	}{
		{"service url and bare host", "http://gibson-zitadel.gibson.svc.cluster.local:8080", "app.example.com", ""},
		{"trailing slash is fine", "http://gibson-zitadel:8080/", "app.example.com", ""},
		{"empty url", "", "app.example.com", "ZITADEL_URL is empty"},
		{"url without scheme", "gibson-zitadel:8080", "app.example.com", "must use http or https"},
		{"url with a path", "http://gibson-zitadel:8080/oauth", "app.example.com", "no path"},
		{"url with a query", "http://gibson-zitadel:8080?x=1", "app.example.com", "no path, query"},
		{"empty host", "http://gibson-zitadel:8080", "", "ZITADEL_EXTERNAL_DOMAIN is empty"},
		{"host with a port", "http://gibson-zitadel:8080", "app.example.com:443", "carries a port"},
		{"host with a nodeport", "http://gibson-zitadel:8080", "app.example.com:30443", "carries a port"},
		{"host with a scheme", "http://gibson-zitadel:8080", "https://app.example.com", "bare host"},
		{"host with a path", "http://gibson-zitadel:8080", "app.example.com/x", "bare host"},
		{"host with spaces", "http://gibson-zitadel:8080", " app.example.com", "bare host"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := zitadelconn.New(tc.url, tc.host)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("New: unexpected error %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("New: want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestEndpoint_BuildsFixedPathsOnTheConnectBase(t *testing.T) {
	e, err := zitadelconn.New("http://gibson-zitadel.gibson.svc.cluster.local:8080/", "App.Example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := e.TokenURL(), "http://gibson-zitadel.gibson.svc.cluster.local:8080/oauth/v2/token"; got != want {
		t.Errorf("TokenURL = %q, want %q", got, want)
	}
	if got, want := e.JWKSURL(), "http://gibson-zitadel.gibson.svc.cluster.local:8080/oauth/v2/keys"; got != want {
		t.Errorf("JWKSURL = %q, want %q", got, want)
	}
	if got, want := e.URL("/management/v1/users/human"), "http://gibson-zitadel.gibson.svc.cluster.local:8080/management/v1/users/human"; got != want {
		t.Errorf("URL = %q, want %q", got, want)
	}
	if got := e.Host(); got != "app.example.com" {
		t.Errorf("Host = %q, want the lower-cased bare host", got)
	}
}

func TestFromEnv_NamesEveryMissingVar(t *testing.T) {
	t.Setenv(zitadelconn.EnvURL, "")
	t.Setenv(zitadelconn.EnvExternalDomain, "")
	_, err := zitadelconn.FromEnv()
	if err == nil || !strings.Contains(err.Error(), "ZITADEL_URL") || !strings.Contains(err.Error(), "ZITADEL_EXTERNAL_DOMAIN") {
		t.Fatalf("FromEnv: want both names in the error, got %v", err)
	}

	t.Setenv(zitadelconn.EnvURL, "http://gibson-zitadel:8080")
	t.Setenv(zitadelconn.EnvExternalDomain, "app.example.com")
	e, err := zitadelconn.FromEnv()
	if err != nil || e.IsZero() {
		t.Fatalf("FromEnv: want a usable endpoint, got %v", err)
	}
}

// The fake refuses a request that names no instance, exactly as Zitadel does;
// the endpoint's client names it on every request.
func TestHTTPClient_SelectsTheInstanceOnEveryRequest(t *testing.T) {
	srv := zitadelconntest.New(t, "", nil)
	e := srv.Endpoint(t)

	plain, err := http.Get(e.URL("/.well-known/openid-configuration"))
	if err != nil {
		t.Fatal(err)
	}
	_ = plain.Body.Close()
	if plain.StatusCode != http.StatusNotFound {
		t.Fatalf("plain client: want 404 Instance not found, got %d", plain.StatusCode)
	}

	resp, err := e.HTTPClient(5*time.Second).Post(e.TokenURL(), "application/x-www-form-urlencoded", strings.NewReader("grant_type=client_credentials"))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("endpoint client: want 200 from the token endpoint, got %d", resp.StatusCode)
	}
	if !srv.HasPath(http.MethodPost, "/oauth/v2/token") {
		t.Fatalf("the fake never saw the token request: %v", srv.Paths())
	}
}

func TestTransport_DoesNotMutateTheCallersRequest(t *testing.T) {
	srv := zitadelconntest.New(t, "", nil)
	e := srv.Endpoint(t)
	req, err := http.NewRequest(http.MethodGet, e.JWKSURL(), http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := (&http.Client{Transport: e.Transport(nil)}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if req.Header.Get(zitadelconn.InstanceHostHeader) != "" {
		t.Fatal("Transport set the instance header on the caller's request")
	}
}

func TestNew_RefusesAnUnparsableOrHostlessURL(t *testing.T) {
	for _, raw := range []string{"http://[::1", "http://"} {
		if _, err := zitadelconn.New(raw, "app.example.com"); err == nil {
			t.Errorf("New(%q): want an error", raw)
		}
	}
}

func TestEndpoint_ZeroValueIsUnusable(t *testing.T) {
	var e zitadelconn.Endpoint
	if !e.IsZero() || e.BaseURL() != "" {
		t.Fatalf("zero Endpoint: IsZero=%v BaseURL=%q, want true and empty", e.IsZero(), e.BaseURL())
	}
}

func TestTransport_WrapsATransportError(t *testing.T) {
	e, err := zitadelconn.New("http://127.0.0.1:1", "app.example.com") // nothing listens
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.HTTPClient(time.Second).Get(e.JWKSURL())
	if err == nil || !strings.Contains(err.Error(), "zitadelconn:") {
		t.Fatalf("want the dial error wrapped by zitadelconn, got %v", err)
	}
}
