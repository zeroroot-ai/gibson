// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package zitadel

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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

// TestNew_InvalidURL_ErrClientSurfacesEveryMethod pins that a New() call
// with an unparseable apiURL returns an errClient whose every method
// (including the sign-in policy methods) surfaces the construction error,
// rather than a nil Client that panics on first use.
func TestNew_InvalidURL_ErrClientSurfacesEveryMethod(t *testing.T) {
	c := New("://bad-url", "pat", "")
	if _, err := c.EnsureLoginPolicy(context.Background(), signInPolicyWant); err == nil {
		t.Error("EnsureLoginPolicy: expected the construction error, got nil")
	}
	if _, err := c.EnsureDomainPolicy(context.Background(), DomainPolicy{}); err == nil {
		t.Error("EnsureDomainPolicy: expected the construction error, got nil")
	}
}

// ---------------------------------------------------------------------------
// EnsureLoginPolicy / EnsureDomainPolicy (ADR-0093 section 9 / decision 1)
// ---------------------------------------------------------------------------

// signInPolicyWant is the LoginPolicy every test in this file exercises
// against — the actual ADR-0093 values, not a synthetic stand-in, so the
// tests double as a pin on the policy's shape.
var signInPolicyWant = LoginPolicy{
	AllowUsernamePassword: true,
	AllowRegister:         false,
	AllowExternalIDP:      false,
	ForceMFA:              true,
	ForceMFALocalOnly:     false,
	PasswordlessAllowed:   true,
	AllowDomainDiscovery:  false,
	MFAInitSkipLifetime:   0,
	SecondFactors:         []string{"SECOND_FACTOR_TYPE_OTP", "SECOND_FACTOR_TYPE_U2F"},
	MultiFactors:          []string{"MULTI_FACTOR_TYPE_U2F_WITH_VERIFICATION"},
}

// loginPolicyFakeServer wires up a fake Zitadel login-policy surface: GET
// returns the live policy, PUT rejects a no-op with the real 400
// (INSTANCE-5M9vdd), and the factor sub-resources accept a search plus
// idempotent add/remove, rejecting an add-that-exists with 409 and a
// remove-of-absent with 404, exactly like real Zitadel.
//
// Setting secondFactorsErr / multiFactorsErr / addErr / removeErr / putErr
// makes the matching endpoint answer 500 instead, so callers can exercise
// EnsureLoginPolicy's error-propagation branches.
type loginPolicyFakeServer struct {
	t            *testing.T
	livePolicy   map[string]any
	liveSecond   []string
	liveMulti    []string
	puts         int32
	putBody      string
	addedOrder   []string // "second_factors:TYPE" / "multi_factors:TYPE" in call order
	removedOrder []string

	putErr           bool
	secondFactorsErr bool
	multiFactorsErr  bool
	addErr           bool
	removeErr        bool
}

func newLoginPolicyFakeServer(t *testing.T, policy map[string]any, second, multi []string) (*httptest.Server, *loginPolicyFakeServer) {
	t.Helper()
	f := &loginPolicyFakeServer{t: t, livePolicy: policy, liveSecond: second, liveMulti: multi}
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/v1/policies/login", f.handleLoginPolicy)
	mux.HandleFunc("/admin/v1/policies/login/second_factors/_search", func(w http.ResponseWriter, _ *http.Request) {
		if f.secondFactorsErr {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		writeJSONPolicy(w, map[string]any{"result": f.liveSecond})
	})
	mux.HandleFunc("/admin/v1/policies/login/multi_factors/_search", func(w http.ResponseWriter, _ *http.Request) {
		if f.multiFactorsErr {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		writeJSONPolicy(w, map[string]any{"result": f.liveMulti})
	})
	mux.HandleFunc("/admin/v1/policies/login/second_factors", func(w http.ResponseWriter, r *http.Request) {
		f.handleAdd(w, r, "second_factors", &f.liveSecond)
	})
	mux.HandleFunc("/admin/v1/policies/login/multi_factors", func(w http.ResponseWriter, r *http.Request) {
		f.handleAdd(w, r, "multi_factors", &f.liveMulti)
	})
	mux.HandleFunc("/admin/v1/policies/login/second_factors/", func(w http.ResponseWriter, r *http.Request) {
		f.handleRemove(w, r, "second_factors", &f.liveSecond)
	})
	mux.HandleFunc("/admin/v1/policies/login/multi_factors/", func(w http.ResponseWriter, r *http.Request) {
		f.handleRemove(w, r, "multi_factors", &f.liveMulti)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, f
}

func (f *loginPolicyFakeServer) handleLoginPolicy(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSONPolicy(w, map[string]any{"policy": f.livePolicy})
	case http.MethodPut:
		if f.putErr {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		buf := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(buf)
		var newBody map[string]any
		_ = json.Unmarshal(buf, &newBody)
		// Real Zitadel rejects a PUT that changes nothing, on every field
		// the request names, with 400 INSTANCE-5M9vdd. Compare the
		// incoming body against the live policy restricted to the keys
		// the request itself sent — that is the same comparison
		// Zitadel's full-replace PUT makes.
		noop := true
		for k, v := range newBody {
			if !reflect.DeepEqual(f.livePolicy[k], v) {
				noop = false
				break
			}
		}
		if noop {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"code":9,"message":"Default Login Policy has not been changed (INSTANCE-5M9vdd)"}`))
			return
		}
		atomic.AddInt32(&f.puts, 1)
		f.putBody = string(buf)
		for k, v := range newBody {
			f.livePolicy[k] = v
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	default:
		f.t.Errorf("unexpected method %s on login policy", r.Method)
	}
}

func (f *loginPolicyFakeServer) handleAdd(w http.ResponseWriter, r *http.Request, kind string, live *[]string) {
	if r.Method != http.MethodPost {
		f.t.Errorf("unexpected method %s on %s add", r.Method, kind)
		return
	}
	if f.addErr {
		http.Error(w, "boom", http.StatusInternalServerError)
		return
	}
	var body struct {
		Type string `json:"type"`
	}
	buf := make([]byte, r.ContentLength)
	_, _ = r.Body.Read(buf)
	_ = json.Unmarshal(buf, &body)
	for _, existing := range *live {
		if existing == body.Type {
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"code":6,"message":"MFA.AlreadyExists"}`))
			return
		}
	}
	*live = append(*live, body.Type)
	f.addedOrder = append(f.addedOrder, kind+":"+body.Type)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{}`))
}

func (f *loginPolicyFakeServer) handleRemove(w http.ResponseWriter, r *http.Request, kind string, live *[]string) {
	if r.Method != http.MethodDelete {
		f.t.Errorf("unexpected method %s on %s remove", r.Method, kind)
		return
	}
	if f.removeErr {
		http.Error(w, "boom", http.StatusInternalServerError)
		return
	}
	typ := strings.TrimPrefix(r.URL.Path, "/admin/v1/policies/login/"+kind+"/")
	idx := -1
	for i, existing := range *live {
		if existing == typ {
			idx = i
			break
		}
	}
	if idx == -1 {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"code":5,"message":"MFA.NotExisting"}`))
		return
	}
	*live = append((*live)[:idx], (*live)[idx+1:]...)
	f.removedOrder = append(f.removedOrder, kind+":"+typ)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{}`))
}

func writeJSONPolicy(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	buf, _ := json.Marshal(v)
	_, _ = w.Write(buf)
}

// TestEnsureLoginPolicy_FreshInstanceDefaultsCorrected covers the first
// reconcile against a freshly-installed Zitadel: MFA off, external IdPs on,
// registration on, a long skip lifetime, and the default multi factor
// instead of the passkey. One PUT must fix every field, and the multi
// factor set must converge to exactly the passkey.
func TestEnsureLoginPolicy_FreshInstanceDefaultsCorrected(t *testing.T) {
	srv, f := newLoginPolicyFakeServer(t, map[string]any{
		// forceMfa missing (=false), allowExternalIdp true, allowRegister
		// true, passwordlessType ALLOWED, a long mfaInitSkipLifetime, plus
		// a read-only field that must not be echoed back.
		"allowExternalIdp":      true,
		"allowRegister":         true,
		"allowUsernamePassword": true,
		"passwordlessType":      "PASSWORDLESS_TYPE_ALLOWED",
		"mfaInitSkipLifetime":   "2592000s",
		"passwordCheckLifetime": "240h0m0s",
		"isDefault":             true,
	}, []string{"SECOND_FACTOR_TYPE_OTP", "SECOND_FACTOR_TYPE_U2F"}, []string{"MULTI_FACTOR_TYPE_U2F_WITH_PIN"})

	c := New(srv.URL, "pat", "")
	corrected, err := c.EnsureLoginPolicy(context.Background(), signInPolicyWant)
	if err != nil {
		t.Fatalf("EnsureLoginPolicy: %v", err)
	}
	if len(corrected) == 0 {
		t.Fatal("corrected is empty, want at least forceMfa/allowExternalIdp/allowRegister/mfaInitSkipLifetime/+multi factor/-multi factor")
	}
	if atomic.LoadInt32(&f.puts) != 1 {
		t.Fatalf("puts = %d, want 1", f.puts)
	}
	for _, want := range []string{
		`"forceMfa":true`,
		`"allowExternalIdp":false`,
		`"allowRegister":false`,
		`"allowDomainDiscovery":false`,
		`"mfaInitSkipLifetime":"0s"`,
		`"allowUsernamePassword":true`, // live field echoed
		`"passwordCheckLifetime":"240h0m0s"`,
	} {
		if !strings.Contains(f.putBody, want) {
			t.Errorf("PUT body missing %q\nbody=%s", want, f.putBody)
		}
	}
	if strings.Contains(f.putBody, "isDefault") {
		t.Errorf("PUT body must not echo read-only isDefault\nbody=%s", f.putBody)
	}
	// Multi factor: U2F_WITH_PIN removed, U2F_WITH_VERIFICATION added.
	// Second factors already matched, so no add/remove there.
	if len(f.addedOrder) != 1 || f.addedOrder[0] != "multi_factors:MULTI_FACTOR_TYPE_U2F_WITH_VERIFICATION" {
		t.Errorf("addedOrder = %v, want exactly the passkey multi factor", f.addedOrder)
	}
	if len(f.removedOrder) != 1 || f.removedOrder[0] != "multi_factors:MULTI_FACTOR_TYPE_U2F_WITH_PIN" {
		t.Errorf("removedOrder = %v, want exactly the default multi factor removed", f.removedOrder)
	}
}

// TestEnsureLoginPolicy_AlreadyEqualIsNoOp is the regression test for
// INSTANCE-5M9vdd: a live policy already equal to want must produce zero
// PUT/add/remove calls, since Zitadel rejects a no-op PUT and the old code
// retried that rejection forever.
func TestEnsureLoginPolicy_AlreadyEqualIsNoOp(t *testing.T) {
	srv, f := newLoginPolicyFakeServer(t, map[string]any{
		"allowUsernamePassword": true,
		"allowRegister":         false,
		"allowExternalIdp":      false,
		"forceMfa":              true,
		"forceMfaLocalOnly":     false,
		"passwordlessType":      "PASSWORDLESS_TYPE_ALLOWED",
		"allowDomainDiscovery":  false,
		"mfaInitSkipLifetime":   "0s",
	}, signInPolicyWant.SecondFactors, signInPolicyWant.MultiFactors)

	c := New(srv.URL, "pat", "")
	corrected, err := c.EnsureLoginPolicy(context.Background(), signInPolicyWant)
	if err != nil {
		t.Fatalf("EnsureLoginPolicy: %v", err)
	}
	if len(corrected) != 0 {
		t.Fatalf("corrected = %v, want empty (already equal)", corrected)
	}
	if atomic.LoadInt32(&f.puts) != 0 {
		t.Fatalf("puts = %d, want 0 (must not send a no-op PUT)", f.puts)
	}
	if len(f.addedOrder) != 0 || len(f.removedOrder) != 0 {
		t.Fatalf("addedOrder=%v removedOrder=%v, want none (already matches)", f.addedOrder, f.removedOrder)
	}
}

// TestEnsureLoginPolicy_SecondFactorsExtrasRemoved covers a live second
// factor set with two extras: only the extras are removed, nothing is
// added.
func TestEnsureLoginPolicy_SecondFactorsExtrasRemoved(t *testing.T) {
	srv, f := newLoginPolicyFakeServer(t, map[string]any{"forceMfa": true},
		[]string{"SECOND_FACTOR_TYPE_OTP", "SECOND_FACTOR_TYPE_U2F", "SECOND_FACTOR_TYPE_OTP_EMAIL", "SECOND_FACTOR_TYPE_OTP_SMS"},
		signInPolicyWant.MultiFactors)

	c := New(srv.URL, "pat", "")
	if _, err := c.EnsureLoginPolicy(context.Background(), signInPolicyWant); err != nil {
		t.Fatalf("EnsureLoginPolicy: %v", err)
	}
	second := 0
	for _, a := range f.addedOrder {
		if strings.HasPrefix(a, "second_factors:") {
			second++
		}
	}
	if second != 0 {
		t.Errorf("second_factors adds = %d, want 0", second)
	}
	var removed []string
	for _, rmv := range f.removedOrder {
		if strings.HasPrefix(rmv, "second_factors:") {
			removed = append(removed, rmv)
		}
	}
	if len(removed) != 2 {
		t.Errorf("second_factors removes = %v, want exactly OTP_EMAIL and OTP_SMS removed", removed)
	}
}

// TestEnsureLoginPolicy_SecondFactorsMissingAdded covers a live second
// factor set missing U2F: only U2F is added.
func TestEnsureLoginPolicy_SecondFactorsMissingAdded(t *testing.T) {
	srv, f := newLoginPolicyFakeServer(t, map[string]any{"forceMfa": true},
		[]string{"SECOND_FACTOR_TYPE_OTP"}, signInPolicyWant.MultiFactors)

	c := New(srv.URL, "pat", "")
	if _, err := c.EnsureLoginPolicy(context.Background(), signInPolicyWant); err != nil {
		t.Fatalf("EnsureLoginPolicy: %v", err)
	}
	if len(f.addedOrder) != 1 || f.addedOrder[0] != "second_factors:SECOND_FACTOR_TYPE_U2F" {
		t.Errorf("addedOrder = %v, want exactly U2F added", f.addedOrder)
	}
}

// TestEnsureLoginPolicy_MultiFactorsEmptyGetsPasskeyAdded covers an empty
// live multi factor set: the passkey is added.
func TestEnsureLoginPolicy_MultiFactorsEmptyGetsPasskeyAdded(t *testing.T) {
	srv, f := newLoginPolicyFakeServer(t, map[string]any{"forceMfa": true},
		signInPolicyWant.SecondFactors, nil)

	c := New(srv.URL, "pat", "")
	if _, err := c.EnsureLoginPolicy(context.Background(), signInPolicyWant); err != nil {
		t.Fatalf("EnsureLoginPolicy: %v", err)
	}
	if len(f.addedOrder) != 1 || f.addedOrder[0] != "multi_factors:MULTI_FACTOR_TYPE_U2F_WITH_VERIFICATION" {
		t.Errorf("addedOrder = %v, want exactly the passkey added", f.addedOrder)
	}
}

// TestEnsureLoginPolicy_NoPolicyIsPermanentError covers a GET response with
// no "policy" key: a permanent error, not a retryable one.
func TestEnsureLoginPolicy_NoPolicyIsPermanentError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)

	c := New(srv.URL, "pat", "")
	_, err := c.EnsureLoginPolicy(context.Background(), signInPolicyWant)
	if err == nil {
		t.Fatal("expected error for empty policy response, got nil")
	}
	if !IsPermanent(err) {
		t.Fatalf("error = %v, want it to wrap ErrPermanent", err)
	}
}

// TestEnsureLoginPolicy_GETError covers a transport/5xx failure on the
// initial GET, distinct from the "no policy in a 200" permanent-error case.
func TestEnsureLoginPolicy_GETError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	c := New(srv.URL, "pat", "")
	if _, err := c.EnsureLoginPolicy(context.Background(), signInPolicyWant); err == nil {
		t.Fatal("expected error from a failing GET, got nil")
	}
}

// TestEnsureLoginPolicy_PUTError covers the PUT itself failing after a real
// change was detected.
func TestEnsureLoginPolicy_PUTError(t *testing.T) {
	srv, f := newLoginPolicyFakeServer(t, map[string]any{"forceMfa": false},
		signInPolicyWant.SecondFactors, signInPolicyWant.MultiFactors)
	f.putErr = true

	c := New(srv.URL, "pat", "")
	if _, err := c.EnsureLoginPolicy(context.Background(), signInPolicyWant); err == nil {
		t.Fatal("expected error from a failing PUT, got nil")
	}
}

// TestEnsureLoginPolicy_SecondFactorsListError covers the second_factors
// _search call failing: the error must propagate out of EnsureLoginPolicy.
func TestEnsureLoginPolicy_SecondFactorsListError(t *testing.T) {
	srv, f := newLoginPolicyFakeServer(t, map[string]any{
		"allowUsernamePassword": true, "allowRegister": false, "allowExternalIdp": false,
		"forceMfa": true, "forceMfaLocalOnly": false, "passwordlessType": "PASSWORDLESS_TYPE_ALLOWED",
		"allowDomainDiscovery": false, "mfaInitSkipLifetime": "0s",
	}, signInPolicyWant.SecondFactors, signInPolicyWant.MultiFactors)
	f.secondFactorsErr = true

	c := New(srv.URL, "pat", "")
	if _, err := c.EnsureLoginPolicy(context.Background(), signInPolicyWant); err == nil {
		t.Fatal("expected error from a failing second_factors list, got nil")
	}
}

// TestEnsureLoginPolicy_MultiFactorsListError covers the multi_factors
// _search call failing after second_factors already succeeded.
func TestEnsureLoginPolicy_MultiFactorsListError(t *testing.T) {
	srv, f := newLoginPolicyFakeServer(t, map[string]any{
		"allowUsernamePassword": true, "allowRegister": false, "allowExternalIdp": false,
		"forceMfa": true, "forceMfaLocalOnly": false, "passwordlessType": "PASSWORDLESS_TYPE_ALLOWED",
		"allowDomainDiscovery": false, "mfaInitSkipLifetime": "0s",
	}, signInPolicyWant.SecondFactors, signInPolicyWant.MultiFactors)
	f.multiFactorsErr = true

	c := New(srv.URL, "pat", "")
	if _, err := c.EnsureLoginPolicy(context.Background(), signInPolicyWant); err == nil {
		t.Fatal("expected error from a failing multi_factors list, got nil")
	}
}

// TestEnsureLoginPolicy_FactorAddError covers a factor add call failing
// with a real error (not the 409 AlreadyExists idempotency case).
func TestEnsureLoginPolicy_FactorAddError(t *testing.T) {
	srv, f := newLoginPolicyFakeServer(t, map[string]any{"forceMfa": true},
		[]string{"SECOND_FACTOR_TYPE_OTP"}, signInPolicyWant.MultiFactors)
	f.addErr = true

	c := New(srv.URL, "pat", "")
	if _, err := c.EnsureLoginPolicy(context.Background(), signInPolicyWant); err == nil {
		t.Fatal("expected error from a failing factor add, got nil")
	}
}

// TestEnsureLoginPolicy_FactorRemoveError covers a factor remove call
// failing with a real error (not the 404 NotExisting idempotency case).
func TestEnsureLoginPolicy_FactorRemoveError(t *testing.T) {
	srv, f := newLoginPolicyFakeServer(t, map[string]any{"forceMfa": true},
		[]string{"SECOND_FACTOR_TYPE_OTP", "SECOND_FACTOR_TYPE_U2F", "SECOND_FACTOR_TYPE_OTP_SMS"},
		signInPolicyWant.MultiFactors)
	f.removeErr = true

	c := New(srv.URL, "pat", "")
	if _, err := c.EnsureLoginPolicy(context.Background(), signInPolicyWant); err == nil {
		t.Fatal("expected error from a failing factor remove, got nil")
	}
}

// TestEnsureLoginPolicy_AddsBeforeRemoves proves the add-before-remove
// ordering directly, using a sequence counter shared across both handlers.
func TestEnsureLoginPolicy_AddsBeforeRemoves(t *testing.T) {
	var (
		seq       int32
		addSeq    int32 = -1
		removeSeq int32 = -1
	)
	live := []string{"SECOND_FACTOR_TYPE_OTP_SMS"} // must be removed
	// want = signInPolicyWant.SecondFactors = {OTP, U2F}; OTP already live,
	// U2F must be added, OTP_SMS must be removed.
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/v1/policies/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			writeJSONPolicy(w, map[string]any{"policy": map[string]any{"forceMfa": true}})
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	})
	mux.HandleFunc("/admin/v1/policies/login/second_factors/_search", func(w http.ResponseWriter, _ *http.Request) {
		writeJSONPolicy(w, map[string]any{"result": append([]string{"SECOND_FACTOR_TYPE_OTP"}, live...)})
	})
	mux.HandleFunc("/admin/v1/policies/login/multi_factors/_search", func(w http.ResponseWriter, _ *http.Request) {
		writeJSONPolicy(w, map[string]any{"result": signInPolicyWant.MultiFactors})
	})
	mux.HandleFunc("/admin/v1/policies/login/second_factors", func(w http.ResponseWriter, _ *http.Request) {
		n := atomic.AddInt32(&seq, 1)
		atomic.StoreInt32(&addSeq, n)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	})
	mux.HandleFunc("/admin/v1/policies/login/second_factors/", func(w http.ResponseWriter, _ *http.Request) {
		n := atomic.AddInt32(&seq, 1)
		atomic.StoreInt32(&removeSeq, n)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	})
	mux.HandleFunc("/admin/v1/policies/login/multi_factors", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	})
	mux.HandleFunc("/admin/v1/policies/login/multi_factors/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := New(srv.URL, "pat", "")
	if _, err := c.EnsureLoginPolicy(context.Background(), signInPolicyWant); err != nil {
		t.Fatalf("EnsureLoginPolicy: %v", err)
	}
	if addSeq < 0 || removeSeq < 0 {
		t.Fatalf("expected both an add and a remove call, got addSeq=%d removeSeq=%d", addSeq, removeSeq)
	}
	if addSeq > removeSeq {
		t.Fatalf("remove (seq %d) happened before add (seq %d), want add first", removeSeq, addSeq)
	}
}

// TestEnsureDomainPolicy_FlipsAndPreservesLiveBooleans covers ADR-0093
// decision 1: usernames unique install-wide via userLoginMustBeDomain=false,
// with the other live booleans (including
// smtpSenderAddressMatchesInstanceDomain) echoed back unchanged.
func TestEnsureDomainPolicy_FlipsAndPreservesLiveBooleans(t *testing.T) {
	var puts int32
	var putBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/v1/policies/domain" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		switch r.Method {
		case http.MethodGet:
			writeJSONPolicy(w, map[string]any{"policy": map[string]any{
				"userLoginMustBeDomain":                  true,
				"validateOrgDomains":                     true,
				"smtpSenderAddressMatchesInstanceDomain": true,
			}})
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
	changed, err := c.EnsureDomainPolicy(context.Background(), DomainPolicy{UserLoginMustBeDomain: false})
	if err != nil {
		t.Fatalf("EnsureDomainPolicy: %v", err)
	}
	if !changed {
		t.Fatal("changed = false, want true")
	}
	if atomic.LoadInt32(&puts) != 1 {
		t.Fatalf("puts = %d, want 1", puts)
	}
	if !strings.Contains(putBody, `"userLoginMustBeDomain":false`) {
		t.Fatalf("PUT body = %q, want userLoginMustBeDomain:false", putBody)
	}
	if !strings.Contains(putBody, `"validateOrgDomains":true`) {
		t.Fatalf("PUT body = %q, want validateOrgDomains echoed", putBody)
	}
	if !strings.Contains(putBody, `"smtpSenderAddressMatchesInstanceDomain":true`) {
		t.Fatalf("PUT body = %q, want smtpSenderAddressMatchesInstanceDomain echoed", putBody)
	}
}

// TestEnsureDomainPolicy_NoOpWhenAlreadyEqual covers a missing key meaning
// false, so an empty live policy already matches want=false.
func TestEnsureDomainPolicy_NoOpWhenAlreadyEqual(t *testing.T) {
	var puts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			writeJSONPolicy(w, map[string]any{"policy": map[string]any{}})
		case http.MethodPut:
			atomic.AddInt32(&puts, 1)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	t.Cleanup(srv.Close)

	c := New(srv.URL, "pat", "")
	changed, err := c.EnsureDomainPolicy(context.Background(), DomainPolicy{UserLoginMustBeDomain: false})
	if err != nil {
		t.Fatalf("EnsureDomainPolicy: %v", err)
	}
	if changed {
		t.Fatal("changed = true, want false")
	}
	if atomic.LoadInt32(&puts) != 0 {
		t.Fatalf("puts = %d, want 0", puts)
	}
}

// TestEnsureDomainPolicy_GETError covers a transport/5xx failure on GET.
func TestEnsureDomainPolicy_GETError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	c := New(srv.URL, "pat", "")
	if _, err := c.EnsureDomainPolicy(context.Background(), DomainPolicy{UserLoginMustBeDomain: false}); err == nil {
		t.Fatal("expected error from a failing GET, got nil")
	}
}

// TestEnsureDomainPolicy_PUTError covers the PUT itself failing after a
// real change was detected.
func TestEnsureDomainPolicy_PUTError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			writeJSONPolicy(w, map[string]any{"policy": map[string]any{"userLoginMustBeDomain": true}})
		case http.MethodPut:
			http.Error(w, "boom", http.StatusInternalServerError)
		}
	}))
	t.Cleanup(srv.Close)

	c := New(srv.URL, "pat", "")
	if _, err := c.EnsureDomainPolicy(context.Background(), DomainPolicy{UserLoginMustBeDomain: false}); err == nil {
		t.Fatal("expected error from a failing PUT, got nil")
	}
}

// TestParseProtoDuration_InvalidStringIsZero covers the unparseable-string
// branch: parseProtoDuration must not propagate the parse error, since a
// malformed value has the same practical meaning as an absent one.
func TestParseProtoDuration_InvalidStringIsZero(t *testing.T) {
	if got := parseProtoDuration("not-a-duration"); got != 0 {
		t.Errorf("parseProtoDuration(invalid) = %v, want 0", got)
	}
	if got := parseProtoDuration(nil); got != 0 {
		t.Errorf("parseProtoDuration(nil) = %v, want 0", got)
	}
	if got := parseProtoDuration("2592000s"); got != 2592000*time.Second {
		t.Errorf("parseProtoDuration(2592000s) = %v, want 2592000s", got)
	}
	if got := protoDuration(0); got != "0s" {
		t.Errorf("protoDuration(0) = %q, want %q", got, "0s")
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
			// The real response shape: projectRoles[] with "key".
			type roleOut struct {
				Key         string `json:"key"`
				DisplayName string `json:"displayName"`
			}
			roles := make([]roleOut, 0, len(f.roles))
			for k, v := range f.roles {
				roles = append(roles, roleOut{Key: k, DisplayName: v})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"projectRoles": roles})
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

// liveListProjectRolesBody is a ListProjectRoles response body recorded from
// Zitadel v4.18.0 on kind (2026-09-26), with one extra undeclared role. The
// fakes above mirror this shape; this test pins the client to the recorded
// bytes, so a fake that drifts from Zitadel cannot hide a decoding bug again.
const liveListProjectRolesBody = `{"pagination":{"totalResult":"5", "appliedLimit":"100"}, "projectRoles":[` +
	`{"projectId":"392527900672262186", "key":"viewer", "creationDate":"2026-09-26T22:14:21.043473Z", "changeDate":"2026-09-26T22:14:21.043473Z", "displayName":"Viewer"}, ` +
	`{"projectId":"392527900672262186", "key":"editor", "creationDate":"2026-09-26T22:14:21.030320Z", "changeDate":"2026-09-26T22:14:21.030320Z", "displayName":"Editor"}, ` +
	`{"projectId":"392527900672262186", "key":"admin", "creationDate":"2026-09-26T22:14:21.011597Z", "changeDate":"2026-09-26T22:14:21.011597Z", "displayName":"Admin"}, ` +
	`{"projectId":"392527900672262186", "key":"owner", "creationDate":"2026-09-26T22:14:20.896858Z", "changeDate":"2026-09-26T22:14:20.896858Z", "displayName":"Owner"}, ` +
	`{"projectId":"392527900672262186", "key":"legacy", "creationDate":"2026-09-26T22:14:20.896858Z", "changeDate":"2026-09-26T22:14:20.896858Z", "displayName":"Legacy"}]}`

// TestEnsureProjectRoles_DecodesTheRecordedZitadelResponse proves the client
// reads the real response: the four declared roles are left alone, and the
// one undeclared role is removed (owner decision D4). Before the fix the
// client read "roles"/"roleKey", saw an empty list, re-added all four roles
// on every reconcile and never removed anything.
func TestEnsureProjectRoles_DecodesTheRecordedZitadelResponse(t *testing.T) {
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/zitadel.project.v2.ProjectService/ListProjectRoles" {
			_, _ = w.Write([]byte(liveListProjectRolesBody))
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)

	c := New(srv.URL, "pat", "")
	changed, err := c.EnsureProjectRoles(context.Background(), "392527900672262186", tenantrole.All)
	if err != nil {
		t.Fatalf("EnsureProjectRoles: %v", err)
	}
	if !changed {
		t.Fatal("changed = false, want true (the undeclared role is removed)")
	}
	want := []string{
		"/zitadel.project.v2.ProjectService/ListProjectRoles",
		"/zitadel.project.v2.ProjectService/RemoveProjectRole",
	}
	if len(calls) != len(want) || calls[0] != want[0] || calls[1] != want[1] {
		t.Fatalf("calls = %v, want %v (no Add, no Update, one Remove)", calls, want)
	}
}
