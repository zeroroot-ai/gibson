// Copyright 2026 Hack the Planet LLC
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package zitadel

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// TestNew_TrimsPATWhitespace pins the defensive trim that prevents Go's
// net/http from rejecting Authorization headers containing CR/LF/tab.
// Regression for the trailing-newline loop observed during 2026-05-13
// cluster bringup, where `echo "$pat" | kubectl create secret` minted an
// iam-admin-pat with a trailing 0x0a and the OIDCClient reconciler logged
// "transient Zitadel error" forever.
func TestNew_TrimsPATWhitespace(t *testing.T) {
	const cleanPAT = "token-abc"

	cases := []struct {
		name string
		pat  string
	}{
		{"plain", cleanPAT},
		{"trailing newline", cleanPAT + "\n"},
		{"trailing CRLF", cleanPAT + "\r\n"},
		{"trailing tab", cleanPAT + "\t"},
		{"trailing space", cleanPAT + " "},
		{"leading whitespace", "  " + cleanPAT},
		{"surrounding whitespace", " \t" + cleanPAT + "\r\n "},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var gotAuth string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotAuth = r.Header.Get("Authorization")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{}`))
			}))
			t.Cleanup(srv.Close)

			c := New(srv.URL, tc.pat, "").(*httpClient)
			if err := c.doJSON(context.Background(), http.MethodGet, "/probe", nil, &struct{}{}); err != nil {
				t.Fatalf("doJSON: %v", err)
			}
			want := "Bearer " + cleanPAT
			if gotAuth != want {
				t.Fatalf("Authorization header = %q, want %q", gotAuth, want)
			}
		})
	}
}

// TestAddOrgMember_PinsOrgIDHeader verifies AddOrgMember POSTs to the
// org-scoped members endpoint and pins the request to the given org via
// the x-zitadel-orgid header, so an org-scoped role grant lands on the
// project's owning org rather than the PAT's default org.
func TestAddOrgMember_PinsOrgIDHeader(t *testing.T) {
	const orgID = "ORG-XYZ"
	var (
		gotPath  string
		gotOrgID string
		gotBody  string
		hits     int32
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		gotPath = r.URL.Path
		gotOrgID = r.Header.Get("x-zitadel-orgid")
		buf := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(buf)
		gotBody = string(buf)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)

	c := New(srv.URL, "pat", "")
	if err := c.AddOrgMember(context.Background(), orgID, "UID-1", []string{"ORG_OWNER"}); err != nil {
		t.Fatalf("AddOrgMember: %v", err)
	}
	if atomic.LoadInt32(&hits) != 1 {
		t.Fatalf("expected 1 request, got %d", hits)
	}
	if wantPath := "/management/v1/orgs/" + orgID + "/members"; gotPath != wantPath {
		t.Fatalf("path = %q, want %q", gotPath, wantPath)
	}
	if gotOrgID != orgID {
		t.Fatalf("x-zitadel-orgid = %q, want %q", gotOrgID, orgID)
	}
	if !strings.Contains(gotBody, "ORG_OWNER") || !strings.Contains(gotBody, "UID-1") {
		t.Fatalf("body = %q, want it to contain userId + ORG_OWNER", gotBody)
	}
}

// TestCreateOIDCClient_SetsAccessTokenLifetime pins gibson#622 / platform-operator#80:
// a non-empty AccessTokenLifetime is sent in the OIDC app create body so the
// CLI device-grant app's access tokens are bounded to 15m. Empty leaves it off.
func TestCreateOIDCClient_SetsAccessTokenLifetime(t *testing.T) {
	for _, tc := range []struct {
		name       string
		lifetime   string
		wantInBody bool
	}{
		{name: "set", lifetime: "900s", wantInBody: true},
		{name: "empty", lifetime: "", wantInBody: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var gotBody string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				buf := make([]byte, r.ContentLength)
				_, _ = r.Body.Read(buf)
				gotBody = string(buf)
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"appId":"APP-1","clientId":"CID-1","clientSecret":""}`))
			}))
			t.Cleanup(srv.Close)

			c := New(srv.URL, "pat", "")
			_, _, _, err := c.CreateOIDCClient(context.Background(), CreateOIDCClientRequest{
				ProjectID:           "PROJ-1",
				Name:                "gibson-cli",
				ApplicationType:     "NATIVE",
				GrantTypes:          []string{"OIDC_GRANT_TYPE_DEVICE_CODE"},
				AccessTokenLifetime: tc.lifetime,
			})
			if err != nil {
				t.Fatalf("CreateOIDCClient: %v", err)
			}
			has := strings.Contains(gotBody, `"accessTokenLifetime":"900s"`)
			if has != tc.wantInBody {
				t.Fatalf("accessTokenLifetime in body = %v, want %v (body=%q)", has, tc.wantInBody, gotBody)
			}
		})
	}
}

// TestCreateOIDCClient_TranslatesGrantAndResponseTypes pins platform-operator#84:
// the OIDCClient CR's bare enum vocabulary (DEVICE_CODE, AUTHORIZATION_CODE,
// REFRESH_TOKEN, CODE) must be translated to Zitadel's prefixed wire enums in
// the app-create body. Zitadel silently drops unrecognized bare values and
// falls back to the app-type default, so device_code never registers and
// `gibson login`'s device flow fails at the token endpoint.
func TestCreateOIDCClient_TranslatesGrantAndResponseTypes(t *testing.T) {
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(buf)
		gotBody = string(buf)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"appId":"APP-1","clientId":"CID-1","clientSecret":"S"}`))
	}))
	t.Cleanup(srv.Close)

	c := New(srv.URL, "pat", "")
	_, _, _, err := c.CreateOIDCClient(context.Background(), CreateOIDCClientRequest{
		ProjectID:       "PROJ-1",
		Name:            "gibson-native-login",
		ApplicationType: "NATIVE",
		GrantTypes:      []string{"DEVICE_CODE", "AUTHORIZATION_CODE", "REFRESH_TOKEN"},
		ResponseTypes:   []string{"CODE"},
	})
	if err != nil {
		t.Fatalf("CreateOIDCClient: %v", err)
	}
	for _, want := range []string{
		"OIDC_GRANT_TYPE_DEVICE_CODE",
		"OIDC_GRANT_TYPE_AUTHORIZATION_CODE",
		"OIDC_GRANT_TYPE_REFRESH_TOKEN",
		"OIDC_RESPONSE_TYPE_CODE",
	} {
		if !strings.Contains(gotBody, want) {
			t.Errorf("request body missing %q\nbody=%s", want, gotBody)
		}
	}
	// The bare CR forms must NOT leak through (would be silently dropped by
	// Zitadel). Guard against a quoted bare token, e.g. "DEVICE_CODE".
	if strings.Contains(gotBody, `"DEVICE_CODE"`) {
		t.Errorf("request body leaked bare DEVICE_CODE\nbody=%s", gotBody)
	}
}

// TestAddOrgMember_EmptyOrgIDIsInvalidInput pins the guard that rejects an
// empty orgID rather than POSTing to a malformed /orgs//members path.
func TestAddOrgMember_EmptyOrgIDIsInvalidInput(t *testing.T) {
	c := New("http://example.invalid", "pat", "")
	err := c.AddOrgMember(context.Background(), "", "UID-1", []string{"ORG_OWNER"})
	if err == nil {
		t.Fatal("expected error for empty orgID, got nil")
	}
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("error = %v, want it to wrap ErrInvalidInput", err)
	}
}

// TestEnsureRegistrationDisabled covers the deploy#886 guard: registration
// is turned off via a GET-then-PUT on the instance login policy, the PUT
// preserves every other live field, and an already-disabled policy is a
// no-op (no PUT).
func TestEnsureRegistrationDisabled(t *testing.T) {
	t.Run("flips allowRegister and preserves other fields", func(t *testing.T) {
		var (
			gets, puts int32
			putBody    string
		)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/admin/v1/policies/login" {
				t.Errorf("unexpected path %q", r.URL.Path)
			}
			switch r.Method {
			case http.MethodGet:
				atomic.AddInt32(&gets, 1)
				// allowRegister true + a couple of other live fields that the
				// PUT must echo back, plus a read-only field that must NOT be
				// sent back.
				_, _ = w.Write([]byte(`{"policy":{"allowRegister":true,"allowUsernamePassword":true,"allowExternalIdp":true,"passwordCheckLifetime":"240h0m0s","isDefault":true}}`))
			case http.MethodPut:
				atomic.AddInt32(&puts, 1)
				buf := make([]byte, r.ContentLength)
				_, _ = r.Body.Read(buf)
				putBody = string(buf)
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{}`))
			default:
				t.Errorf("unexpected method %s", r.Method)
			}
		}))
		t.Cleanup(srv.Close)

		c := New(srv.URL, "pat", "")
		changed, err := c.EnsureRegistrationDisabled(context.Background())
		if err != nil {
			t.Fatalf("EnsureRegistrationDisabled: %v", err)
		}
		if !changed {
			t.Fatalf("changed = false, want true (allowRegister was on)")
		}
		if atomic.LoadInt32(&gets) != 1 || atomic.LoadInt32(&puts) != 1 {
			t.Fatalf("gets=%d puts=%d, want 1 and 1", gets, puts)
		}
		if !strings.Contains(putBody, `"allowRegister":false`) {
			t.Fatalf("PUT body = %q, want allowRegister:false", putBody)
		}
		// Live fields preserved.
		if !strings.Contains(putBody, `"allowUsernamePassword":true`) ||
			!strings.Contains(putBody, `"passwordCheckLifetime":"240h0m0s"`) {
			t.Fatalf("PUT body = %q, want preserved login + lifetime fields", putBody)
		}
		// Read-only field dropped.
		if strings.Contains(putBody, "isDefault") {
			t.Fatalf("PUT body = %q, must not echo read-only isDefault", putBody)
		}
	})

	t.Run("no-op when already disabled", func(t *testing.T) {
		var puts int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet:
				_, _ = w.Write([]byte(`{"policy":{"allowRegister":false,"allowUsernamePassword":true}}`))
			case http.MethodPut:
				atomic.AddInt32(&puts, 1)
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{}`))
			}
		}))
		t.Cleanup(srv.Close)

		c := New(srv.URL, "pat", "")
		changed, err := c.EnsureRegistrationDisabled(context.Background())
		if err != nil {
			t.Fatalf("EnsureRegistrationDisabled: %v", err)
		}
		if changed {
			t.Fatalf("changed = true, want false (already disabled)")
		}
		if atomic.LoadInt32(&puts) != 0 {
			t.Fatalf("puts = %d, want 0 (no write when already disabled)", puts)
		}
	})

	t.Run("no-op when allowRegister omitted from GET (protojson drops false bools)", func(t *testing.T) {
		// Regression for the wedge: live Zitadel omits allowRegister from the
		// login-policy GET once it is false, so the idempotency check must treat
		// a MISSING key as already-disabled. The old `ok && !allow` check re-PUT
		// allowRegister=false here, and Zitadel rejects that no-op with
		// `400 ... has not been changed (INSTANCE-5M9vdd)`, wedging the bootstrap.
		var puts int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet:
				// allowRegister absent — exactly what Zitadel returns when false.
				_, _ = w.Write([]byte(`{"policy":{"allowUsernamePassword":true,"isDefault":true}}`))
			case http.MethodPut:
				atomic.AddInt32(&puts, 1)
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"code":9,"message":"Default Login Policy has not been changed (INSTANCE-5M9vdd)"}`))
			}
		}))
		t.Cleanup(srv.Close)

		c := New(srv.URL, "pat", "")
		changed, err := c.EnsureRegistrationDisabled(context.Background())
		if err != nil {
			t.Fatalf("EnsureRegistrationDisabled: %v", err)
		}
		if changed {
			t.Fatalf("changed = true, want false (already disabled via omitted key)")
		}
		if atomic.LoadInt32(&puts) != 0 {
			t.Fatalf("puts = %d, want 0 (must not PUT when allowRegister is omitted)", puts)
		}
	})
}
