// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package zitadel

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/platform/tenantrole"
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

// TestRemoveIAMMember_DeletesAndIsIdempotentOn404 verifies RemoveIAMMember
// issues a DELETE to the IAM member's URL and treats a 404 (never a
// member, or already removed) as idempotent success — the same contract
// the Client interface documents for every mutating call.
func TestRemoveIAMMember_DeletesAndIsIdempotentOn404(t *testing.T) {
	cases := []struct {
		name   string
		status int
	}{
		{"member exists", http.StatusOK},
		{"already gone", http.StatusNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var gotMethod, gotPath string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotMethod = r.Method
				gotPath = r.URL.Path
				w.WriteHeader(tc.status)
				if tc.status < 300 {
					_, _ = w.Write([]byte(`{}`))
				}
			}))
			t.Cleanup(srv.Close)

			c := New(srv.URL, "pat", "")
			if err := c.RemoveIAMMember(context.Background(), "UID-1"); err != nil {
				t.Fatalf("RemoveIAMMember: %v", err)
			}
			if gotMethod != http.MethodDelete {
				t.Fatalf("method = %q, want DELETE", gotMethod)
			}
			if want := "/admin/v1/members/UID-1"; gotPath != want {
				t.Fatalf("path = %q, want %q", gotPath, want)
			}
		})
	}
}

// TestRemoveOrgMember_PinsOrgIDHeader mirrors
// TestAddOrgMember_PinsOrgIDHeader: RemoveOrgMember DELETEs the org-scoped
// member URL and pins the request to orgID via the x-zitadel-orgid header.
func TestRemoveOrgMember_PinsOrgIDHeader(t *testing.T) {
	const orgID = "ORG-XYZ"
	var (
		gotMethod string
		gotPath   string
		gotOrgID  string
		hits      int32
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotOrgID = r.Header.Get("x-zitadel-orgid")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)

	c := New(srv.URL, "pat", "")
	if err := c.RemoveOrgMember(context.Background(), orgID, "UID-1"); err != nil {
		t.Fatalf("RemoveOrgMember: %v", err)
	}
	if atomic.LoadInt32(&hits) != 1 {
		t.Fatalf("expected 1 request, got %d", hits)
	}
	if gotMethod != http.MethodDelete {
		t.Fatalf("method = %q, want DELETE", gotMethod)
	}
	if want := "/management/v1/orgs/" + orgID + "/members/UID-1"; gotPath != want {
		t.Fatalf("path = %q, want %q", gotPath, want)
	}
	if gotOrgID != orgID {
		t.Fatalf("x-zitadel-orgid = %q, want %q", gotOrgID, orgID)
	}
}

// TestRemoveOrgMember_EmptyOrgIDIsInvalidInput mirrors
// TestAddOrgMember_EmptyOrgIDIsInvalidInput.
func TestRemoveOrgMember_EmptyOrgIDIsInvalidInput(t *testing.T) {
	c := New("http://example.invalid", "pat", "")
	err := c.RemoveOrgMember(context.Background(), "", "UID-1")
	if err == nil {
		t.Fatal("expected error for empty orgID, got nil")
	}
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("error = %v, want it to wrap ErrInvalidInput", err)
	}
}

// TestRemoveIAMMember_ConstructionErrorPropagates and
// TestRemoveOrgMember_ConstructionErrorPropagates exercise the errClient
// fallback: New() returns a client that fails every call with the original
// url.Parse error when apiURL cannot be parsed at all. A malformed percent-
// escape ("%zz") is the simplest input net/url reliably rejects.
func TestRemoveIAMMember_ConstructionErrorPropagates(t *testing.T) {
	c := New("http://example.invalid/%zz", "pat", "")
	err := c.RemoveIAMMember(context.Background(), "UID-1")
	if err == nil {
		t.Fatal("expected the construction error to propagate, got nil")
	}
}

func TestRemoveOrgMember_ConstructionErrorPropagates(t *testing.T) {
	c := New("http://example.invalid/%zz", "pat", "")
	err := c.RemoveOrgMember(context.Background(), "ORG-1", "UID-1")
	if err == nil {
		t.Fatal("expected the construction error to propagate, got nil")
	}
}

// TestRemoveIAMMember_PropagatesNonNotFoundError and
// TestRemoveOrgMember_PropagatesNonNotFoundError cover the "genuinely
// failed" branch: a non-404 error from the server (e.g. 500, 401) must
// come back to the caller, not be swallowed the way a 404 is.
func TestRemoveIAMMember_PropagatesNonNotFoundError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"message":"internal"}`))
	}))
	t.Cleanup(srv.Close)

	c := New(srv.URL, "pat", "")
	err := c.RemoveIAMMember(context.Background(), "UID-1")
	if err == nil {
		t.Fatal("expected a 500 to propagate as an error, got nil")
	}
}

func TestRemoveOrgMember_PropagatesNonNotFoundError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"message":"internal"}`))
	}))
	t.Cleanup(srv.Close)

	c := New(srv.URL, "pat", "")
	err := c.RemoveOrgMember(context.Background(), "ORG-1", "UID-1")
	if err == nil {
		t.Fatal("expected a 500 to propagate as an error, got nil")
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

// fakeProjectRoleServer is a minimal stateful fake of the v2
// ProjectService role calls, enough to test EnsureProjectRoles'
// convergence without pulling in zitadelconntest.Identity (that fake
// enforces the x-zitadel-instance-host header this client does not send).
type fakeProjectRoleServer struct {
	mu    sync.Mutex
	roles map[string]string // roleKey -> displayName

	adds, updates, removes int

	// failList/failAdd/failUpdate/failRemove force the matching call to
	// answer with an upstream failure (never already_exists/not_found, so
	// the client's success-shaped-error handling in EnsureProjectRoles
	// cannot swallow it) — used to exercise EnsureProjectRoles' four error
	// return branches.
	failList, failAdd, failUpdate, failRemove bool
}

func (f *fakeProjectRoleServer) writeUpstreamError(w http.ResponseWriter) {
	w.WriteHeader(http.StatusInternalServerError)
	_ = json.NewEncoder(w).Encode(map[string]string{"code": "internal", "message": "Errors.Internal"})
}

func (f *fakeProjectRoleServer) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		f.mu.Lock()
		defer f.mu.Unlock()
		switch r.URL.Path {
		case "/zitadel.project.v2.ProjectService/ListProjectRoles":
			if f.failList {
				f.writeUpstreamError(w)
				return
			}
			type roleOut struct {
				RoleKey     string `json:"roleKey"`
				DisplayName string `json:"displayName"`
			}
			roles := make([]roleOut, 0, len(f.roles))
			for k, v := range f.roles {
				roles = append(roles, roleOut{RoleKey: k, DisplayName: v})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"roles": roles})
		case "/zitadel.project.v2.ProjectService/AddProjectRole":
			if f.failAdd {
				f.writeUpstreamError(w)
				return
			}
			var req struct{ RoleKey, DisplayName string }
			_ = json.NewDecoder(r.Body).Decode(&req)
			if _, exists := f.roles[req.RoleKey]; exists {
				w.WriteHeader(http.StatusConflict)
				_ = json.NewEncoder(w).Encode(map[string]string{"code": "already_exists", "message": "Errors.Project.Role.AlreadyExists"})
				return
			}
			f.roles[req.RoleKey] = req.DisplayName
			f.adds++
			_ = json.NewEncoder(w).Encode(map[string]any{})
		case "/zitadel.project.v2.ProjectService/UpdateProjectRole":
			if f.failUpdate {
				f.writeUpstreamError(w)
				return
			}
			var req struct{ RoleKey, DisplayName string }
			_ = json.NewDecoder(r.Body).Decode(&req)
			f.roles[req.RoleKey] = req.DisplayName
			f.updates++
			_ = json.NewEncoder(w).Encode(map[string]any{})
		case "/zitadel.project.v2.ProjectService/RemoveProjectRole":
			if f.failRemove {
				f.writeUpstreamError(w)
				return
			}
			var req struct{ RoleKey string }
			_ = json.NewDecoder(r.Body).Decode(&req)
			delete(f.roles, req.RoleKey)
			f.removes++
			_ = json.NewEncoder(w).Encode(map[string]any{})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

func TestEnsureProjectRoles_AddsMissingRenamesAndRemovesExtra(t *testing.T) {
	f := &fakeProjectRoleServer{roles: map[string]string{
		"owner":    "Owner",
		"obsolete": "Old Role",
		"admin":    "Wrong Name",
	}}
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)

	c := New(srv.URL, "pat", "")
	changed, err := c.EnsureProjectRoles(context.Background(), "PROJ-1", tenantrole.All)
	if err != nil {
		t.Fatalf("EnsureProjectRoles: %v", err)
	}
	if !changed {
		t.Fatal("changed = false, want true")
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	want := map[string]string{"owner": "Owner", "admin": "Admin", "editor": "Editor", "viewer": "Viewer"}
	if len(f.roles) != len(want) {
		t.Fatalf("roles = %v, want %v", f.roles, want)
	}
	for k, v := range want {
		if f.roles[k] != v {
			t.Errorf("roles[%q] = %q, want %q", k, f.roles[k], v)
		}
	}
	if f.adds != 2 { // editor, viewer
		t.Errorf("adds = %d, want 2", f.adds)
	}
	if f.updates != 1 { // admin renamed
		t.Errorf("updates = %d, want 1", f.updates)
	}
	if f.removes != 1 { // obsolete
		t.Errorf("removes = %d, want 1", f.removes)
	}
}

func TestEnsureProjectRoles_NoOpOnASecondCall(t *testing.T) {
	f := &fakeProjectRoleServer{roles: map[string]string{}}
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)

	c := New(srv.URL, "pat", "")
	if _, err := c.EnsureProjectRoles(context.Background(), "PROJ-1", tenantrole.All); err != nil {
		t.Fatalf("first EnsureProjectRoles: %v", err)
	}
	changed, err := c.EnsureProjectRoles(context.Background(), "PROJ-1", tenantrole.All)
	if err != nil {
		t.Fatalf("second EnsureProjectRoles: %v", err)
	}
	if changed {
		t.Fatal("changed = true on the second call, want false (already converged)")
	}
}

// TestEnsureProjectRoles_PropagatesEachUpstreamError exercises the four
// error-return branches of EnsureProjectRoles: a failure from
// ListProjectRoles, AddProjectRole, UpdateProjectRole or RemoveProjectRole
// (each answering something other than the shape EnsureProjectRoles
// already treats as success — already_exists / not_found) must surface as
// a wrapped error naming the failing call, and must never mark the sync as
// fully converged.
func TestEnsureProjectRoles_PropagatesEachUpstreamError(t *testing.T) {
	tests := []struct {
		name          string
		configure     func(f *fakeProjectRoleServer)
		wantErrSubstr string
	}{
		{
			name:          "list fails",
			configure:     func(f *fakeProjectRoleServer) { f.failList = true },
			wantErrSubstr: "ListProjectRoles",
		},
		{
			name: "add fails",
			configure: func(f *fakeProjectRoleServer) {
				f.roles = map[string]string{} // owner is missing, forces an Add
				f.failAdd = true
			},
			wantErrSubstr: "AddProjectRole",
		},
		{
			name: "update fails",
			configure: func(f *fakeProjectRoleServer) {
				f.roles = map[string]string{
					"owner": "Wrong Name", "admin": "Admin", "editor": "Editor", "viewer": "Viewer",
				} // owner's display name differs, forces an Update
				f.failUpdate = true
			},
			wantErrSubstr: "UpdateProjectRole",
		},
		{
			name: "remove fails",
			configure: func(f *fakeProjectRoleServer) {
				f.roles = map[string]string{
					"owner": "Owner", "admin": "Admin", "editor": "Editor", "viewer": "Viewer",
					"obsolete": "Old Role", // not in tenantrole.All, forces a Remove
				}
				f.failRemove = true
			},
			wantErrSubstr: "RemoveProjectRole",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fakeProjectRoleServer{}
			tt.configure(f)
			srv := httptest.NewServer(f.handler())
			t.Cleanup(srv.Close)

			c := New(srv.URL, "pat", "")
			if _, err := c.EnsureProjectRoles(context.Background(), "PROJ-1", tenantrole.All); err == nil {
				t.Fatal("EnsureProjectRoles: got nil error, want one naming the failing call")
			} else if !strings.Contains(err.Error(), tt.wantErrSubstr) {
				t.Errorf("EnsureProjectRoles error = %q, want it to mention %q", err, tt.wantErrSubstr)
			}
		})
	}
}

// TestEnsureProjectRoles_ErrClientReturnsConstructionError covers the
// errClient stub: New returns an errClient when it cannot parse apiURL,
// and every method on it — including EnsureProjectRoles — must return
// that same construction error rather than panic or silently succeed.
func TestEnsureProjectRoles_ErrClientReturnsConstructionError(t *testing.T) {
	c := New("http://%zz", "pat", "")
	_, err := c.EnsureProjectRoles(context.Background(), "PROJ-1", tenantrole.All)
	if err == nil {
		t.Fatal("EnsureProjectRoles on an errClient: got nil error, want the construction error")
	}
	if !strings.Contains(err.Error(), "invalid apiURL") {
		t.Errorf("EnsureProjectRoles error = %q, want it to mention the invalid apiURL", err)
	}
}
