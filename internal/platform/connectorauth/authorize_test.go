// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package connectorauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// PKCE
// ---------------------------------------------------------------------------

func TestGeneratePKCE_ChallengeIsTheS256OfTheVerifier(t *testing.T) {
	p, err := GeneratePKCE()
	if err != nil {
		t.Fatal(err)
	}
	if p.Method != "S256" {
		t.Errorf("method = %q, want S256", p.Method)
	}
	sum := sha256.Sum256([]byte(p.Verifier))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if p.Challenge != want {
		t.Errorf("challenge = %q, want the S256 of the verifier %q", p.Challenge, want)
	}
	// RFC 7636 §4.1: the verifier is 43..128 characters.
	if len(p.Verifier) < 43 || len(p.Verifier) > 128 {
		t.Errorf("verifier length = %d, outside the RFC 7636 window", len(p.Verifier))
	}
}

func TestGeneratePKCE_IsFreshEachTime(t *testing.T) {
	a, err := GeneratePKCE()
	if err != nil {
		t.Fatal(err)
	}
	b, err := GeneratePKCE()
	if err != nil {
		t.Fatal(err)
	}
	if a.Verifier == b.Verifier {
		t.Error("two PKCE pairs must not share a verifier")
	}
}

func TestGenerateState_IsUnguessableAndUnique(t *testing.T) {
	a, err := GenerateState()
	if err != nil {
		t.Fatal(err)
	}
	b, err := GenerateState()
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Error("two states must differ")
	}
	if len(a) < 40 {
		t.Errorf("state %q is too short to be unguessable", a)
	}
}

// ---------------------------------------------------------------------------
// PendingStore TTL
// ---------------------------------------------------------------------------

func TestPendingStore_TakeReturnsThePendingWithinTTL(t *testing.T) {
	base := time.Unix(1_700_000_000, 0).UTC()
	now := base
	store := NewPendingStore(5*time.Minute, func() time.Time { return now })

	store.Put(&PendingAuthorization{State: "s1", Connector: "connector-gitlab", CreatedAt: now})

	now = base.Add(4 * time.Minute) // still inside the window
	pa, ok := store.Take("s1")
	if !ok {
		t.Fatal("a pending inside the TTL must be returned")
	}
	if pa.Connector != "connector-gitlab" {
		t.Errorf("connector = %q, want connector-gitlab", pa.Connector)
	}
}

func TestPendingStore_TakeDropsAnExpiredPending(t *testing.T) {
	base := time.Unix(1_700_000_000, 0).UTC()
	now := base
	store := NewPendingStore(5*time.Minute, func() time.Time { return now })

	store.Put(&PendingAuthorization{State: "s1", CreatedAt: now})

	now = base.Add(6 * time.Minute) // past the window
	if _, ok := store.Take("s1"); ok {
		t.Error("a pending past the TTL must not be returned")
	}
}

func TestPendingStore_StateIsSingleUse(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	store := NewPendingStore(5*time.Minute, func() time.Time { return now })
	store.Put(&PendingAuthorization{State: "s1", CreatedAt: now})

	if _, ok := store.Take("s1"); !ok {
		t.Fatal("first Take must succeed")
	}
	if _, ok := store.Take("s1"); ok {
		t.Error("a state must not be usable twice")
	}
}

func TestPendingStore_TakeUnknownStateIsFalse(t *testing.T) {
	store := NewPendingStore(0, nil) // defaults
	if _, ok := store.Take("never-stored"); ok {
		t.Error("an unknown state must return false")
	}
}

// ---------------------------------------------------------------------------
// Authorize-URL construction
// ---------------------------------------------------------------------------

func TestBuildAuthorizeURL_CarriesEveryRequiredParameter(t *testing.T) {
	raw, err := BuildAuthorizeURL(
		"https://gitlab.com/oauth/authorize",
		"client-abc",
		"https://api.example.com/connectors/oauth/callback",
		"api read_api",
		"state-xyz",
		"challenge-123",
	)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("result is not a URL: %v", err)
	}
	q := u.Query()
	want := map[string]string{
		"response_type":         "code",
		"client_id":             "client-abc",
		"redirect_uri":          "https://api.example.com/connectors/oauth/callback",
		"scope":                 "api read_api",
		"state":                 "state-xyz",
		"code_challenge":        "challenge-123",
		"code_challenge_method": "S256",
	}
	for k, v := range want {
		if got := q.Get(k); got != v {
			t.Errorf("query %q = %q, want %q", k, got, v)
		}
	}
	if u.Scheme != "https" || u.Host != "gitlab.com" || u.Path != "/oauth/authorize" {
		t.Errorf("endpoint changed: %s", u.Redacted())
	}
}

func TestBuildAuthorizeURL_OmitsEmptyScope(t *testing.T) {
	raw, err := BuildAuthorizeURL("https://gitlab.com/oauth/authorize", "c", "https://cb", "", "st", "ch")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(raw, "scope=") {
		t.Errorf("an empty scope must be omitted, got %s", raw)
	}
}

// ---------------------------------------------------------------------------
// Discovery + registration + exchange against a fake vendor
// ---------------------------------------------------------------------------

func TestDiscover_FindsRFC8414Metadata(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"issuer":"ISS","authorization_endpoint":"https://v/authorize","token_endpoint":"https://v/token","registration_endpoint":"https://v/register"}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	meta, err := Discover(context.Background(), srv.Client(), srv.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	if meta.TokenEndpoint != "https://v/token" || meta.RegistrationEndpoint != "https://v/register" {
		t.Errorf("metadata = %+v", meta)
	}
}

func TestExchangeCode_ReturnsAGrantFromTheVendorRefreshToken(t *testing.T) {
	var gotForm url.Values
	vendor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotForm = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at","refresh_token":"rt-vendor","expires_in":3600,"scope":"api"}`))
	}))
	defer vendor.Close()

	pa := &PendingAuthorization{
		State:         "s",
		Verifier:      "verifier-1",
		Connector:     "connector-gitlab",
		TokenEndpoint: vendor.URL,
		ClientID:      "client-abc",
		RedirectURI:   "https://cb",
		Scope:         "api",
		AuthorizedBy:  "user:user-1",
	}
	grant, err := ExchangeCode(context.Background(), vendor.Client(), pa, "the-code", func() time.Time {
		return time.Unix(1_700_000_000, 0).UTC()
	})
	if err != nil {
		t.Fatal(err)
	}
	if grant.RefreshToken != "rt-vendor" {
		t.Errorf("refresh token = %q, want the vendor's rt-vendor", grant.RefreshToken)
	}
	if grant.AuthorizedBy != "user:user-1" {
		t.Errorf("authorized_by = %q, want user:user-1", grant.AuthorizedBy)
	}
	// The exchange must send the PKCE verifier and the authorization_code grant.
	if gotForm.Get("grant_type") != "authorization_code" || gotForm.Get("code_verifier") != "verifier-1" {
		t.Errorf("exchange form = %v", gotForm)
	}
}

func TestExchangeCode_FailsWhenTheVendorReturnsNoRefreshToken(t *testing.T) {
	vendor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at","expires_in":3600}`))
	}))
	defer vendor.Close()

	pa := &PendingAuthorization{Connector: "connector-gitlab", TokenEndpoint: vendor.URL, ClientID: "c"}
	if _, err := ExchangeCode(context.Background(), vendor.Client(), pa, "code", nil); err == nil {
		t.Error("a response with no refresh_token must fail: the daemon cannot own the rotation")
	}
}

// ---------------------------------------------------------------------------
// RegisterClient (RFC 7591)
// ---------------------------------------------------------------------------

func TestRegisterClient_RegistersAPublicPKCEClient(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"client_id":"dyn-123","client_secret":""}`))
	}))
	defer srv.Close()

	reg, err := RegisterClient(context.Background(), srv.Client(), srv.URL, "https://cb", "mcp")
	if err != nil {
		t.Fatal(err)
	}
	if reg.ClientID != "dyn-123" {
		t.Errorf("client_id = %q", reg.ClientID)
	}
	// A public PKCE client registers with token_endpoint_auth_method none.
	if gotBody["token_endpoint_auth_method"] != "none" {
		t.Errorf("auth method = %v, want none", gotBody["token_endpoint_auth_method"])
	}
}

func TestRegisterClient_RejectsAnEmptyEndpoint(t *testing.T) {
	if _, err := RegisterClient(context.Background(), nil, "", "https://cb", "mcp"); err == nil {
		t.Error("an empty registration endpoint must fail")
	}
}

func TestRegisterClient_FailsWhenTheServerRefuses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_redirect_uri"}`))
	}))
	defer srv.Close()

	if _, err := RegisterClient(context.Background(), srv.Client(), srv.URL, "https://cb", "mcp"); err == nil {
		t.Error("a 400 registration response must fail")
	}
}

func TestRegisterClient_FailsWhenNoClientID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"client_id":""}`))
	}))
	defer srv.Close()

	if _, err := RegisterClient(context.Background(), srv.Client(), srv.URL, "https://cb", "mcp"); err == nil {
		t.Error("a registration response with no client_id must fail")
	}
}

// ---------------------------------------------------------------------------
// Discover — RFC 9728 protected-resource path and failure
// ---------------------------------------------------------------------------

func TestDiscover_FollowsProtectedResourceToTheAuthServer(t *testing.T) {
	var asOrigin string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-protected-resource", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"authorization_servers":["` + asOrigin + `"]}`))
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"authorization_endpoint":"https://v/authorize","token_endpoint":"https://v/token"}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	asOrigin = srv.URL

	meta, err := Discover(context.Background(), srv.Client(), srv.URL, srv.URL+"/mcp")
	if err != nil {
		t.Fatal(err)
	}
	if meta.TokenEndpoint != "https://v/token" {
		t.Errorf("token endpoint = %q", meta.TokenEndpoint)
	}
}

func TestDiscover_FailsWhenNoMetadataDocumentExists(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	if _, err := Discover(context.Background(), srv.Client(), srv.URL, ""); err == nil {
		t.Error("no metadata document must fail discovery")
	}
}

// ---------------------------------------------------------------------------
// ExchangeCode — refused exchange
// ---------------------------------------------------------------------------

func TestExchangeCode_FailsOnARefusedExchange(t *testing.T) {
	vendor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	defer vendor.Close()

	pa := &PendingAuthorization{Connector: "connector-gitlab", TokenEndpoint: vendor.URL, ClientID: "c", ClientSecret: "shh"}
	if _, err := ExchangeCode(context.Background(), vendor.Client(), pa, "code", nil); err == nil {
		t.Error("a refused code exchange must fail")
	}
}

// ---------------------------------------------------------------------------
// Discovery + getJSON error and branch paths
// ---------------------------------------------------------------------------

func TestDiscover_TriesThePathAwareWellKnownForm(t *testing.T) {
	// A base URL that carries a path exercises the RFC 8414 §3.1 path-aware
	// candidate (origin + /.well-known/<wk> + /<path>).
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-authorization-server/tenant1", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"authorization_endpoint":"https://v/a","token_endpoint":"https://v/t"}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	meta, err := Discover(context.Background(), srv.Client(), srv.URL+"/tenant1", "")
	if err != nil {
		t.Fatal(err)
	}
	if meta.TokenEndpoint != "https://v/t" {
		t.Errorf("token endpoint = %q", meta.TokenEndpoint)
	}
}

func TestDiscover_IgnoresAProtectedResourceThatNamesNoServer(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-protected-resource", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"authorization_servers":[]}`)) // names no server
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"authorization_endpoint":"https://v/a","token_endpoint":"https://v/t"}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// The empty protected-resource is skipped; discovery falls back to the
	// instance-URL RFC 8414 document.
	meta, err := Discover(context.Background(), srv.Client(), srv.URL, srv.URL+"/mcp")
	if err != nil {
		t.Fatal(err)
	}
	if meta.TokenEndpoint != "https://v/t" {
		t.Errorf("token endpoint = %q", meta.TokenEndpoint)
	}
}

func TestDiscover_RejectsAMalformedMetadataDocument(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{not-json`))
	}))
	defer srv.Close()

	if _, err := Discover(context.Background(), srv.Client(), srv.URL, ""); err == nil {
		t.Error("a malformed metadata document must fail discovery")
	}
}

// ---------------------------------------------------------------------------
// nil-client default paths and unreachable endpoints
// ---------------------------------------------------------------------------

func TestRegisterClient_FailsWhenTheEndpointIsUnreachable(t *testing.T) {
	// A default client (nil) against a closed address exercises the transport
	// error path without a live server.
	if _, err := RegisterClient(context.Background(), shortClient(), "http://127.0.0.1:1/register", "https://cb", "mcp"); err == nil {
		t.Error("an unreachable registration endpoint must fail")
	}
}

func TestRegisterClient_RejectsAMalformedResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{not-json`))
	}))
	defer srv.Close()

	if _, err := RegisterClient(context.Background(), srv.Client(), srv.URL, "https://cb", "mcp"); err == nil {
		t.Error("a malformed registration response must fail")
	}
}

func TestExchangeCode_FailsWhenTheTokenEndpointIsUnreachable(t *testing.T) {
	pa := &PendingAuthorization{Connector: "connector-gitlab", TokenEndpoint: "http://127.0.0.1:1/token", ClientID: "c"}
	if _, err := ExchangeCode(context.Background(), shortClient(), pa, "code", nil); err == nil {
		t.Error("an unreachable token endpoint must fail")
	}
}

func TestExchangeCode_RejectsAMalformedTokenResponse(t *testing.T) {
	vendor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{not-json`))
	}))
	defer vendor.Close()

	pa := &PendingAuthorization{Connector: "connector-gitlab", TokenEndpoint: vendor.URL, ClientID: "c"}
	if _, err := ExchangeCode(context.Background(), vendor.Client(), pa, "code", nil); err == nil {
		t.Error("a malformed token response must fail")
	}
}

func TestExchangeCode_FallsBackToTheRequestedScope(t *testing.T) {
	// The vendor returns no scope, so the grant keeps the requested scope.
	vendor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"refresh_token":"rt","access_token":"at"}`))
	}))
	defer vendor.Close()

	pa := &PendingAuthorization{Connector: "connector-gitlab", TokenEndpoint: vendor.URL, ClientID: "c", Scope: "mcp"}
	grant, err := ExchangeCode(context.Background(), vendor.Client(), pa, "code", nil)
	if err != nil {
		t.Fatal(err)
	}
	if grant.Scope != "mcp" {
		t.Errorf("scope = %q, want the requested mcp", grant.Scope)
	}
}

// shortClient is an http.Client with a tight timeout so unreachable-endpoint
// tests fail fast instead of waiting on the default 30s.
func shortClient() *http.Client {
	return &http.Client{Timeout: 2 * time.Second}
}

// ---------------------------------------------------------------------------
// PendingStore garbage collection + remaining error branches
// ---------------------------------------------------------------------------

func TestPendingStore_PutGarbageCollectsExpiredEntries(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	clock := now
	store := NewPendingStore(time.Minute, func() time.Time { return clock })
	store.Put(&PendingAuthorization{State: "old", CreatedAt: now})

	// Advance past the TTL and put a second entry; the GC on Put drops "old".
	clock = now.Add(2 * time.Minute)
	store.Put(&PendingAuthorization{State: "new", CreatedAt: clock})

	if _, ok := store.Take("old"); ok {
		t.Error("the expired entry must have been garbage-collected on Put")
	}
	if _, ok := store.Take("new"); !ok {
		t.Error("the fresh entry must survive")
	}
}

func TestDiscover_RejectsAnUnparseableInstanceURL(t *testing.T) {
	// No scheme or host means no candidate metadata URLs, so discovery fails
	// with the no-document error rather than a transport error.
	if _, err := Discover(context.Background(), shortClient(), "://not-a-url", ""); err == nil {
		t.Error("an unparseable instance URL must fail discovery")
	}
}

func TestRegisterClient_RejectsAnUnbuildableRequest(t *testing.T) {
	// A control character in the endpoint makes the request unbuildable.
	if _, err := RegisterClient(context.Background(), shortClient(), "http://\x7f/register", "https://cb", "mcp"); err == nil {
		t.Error("an unbuildable registration request must fail")
	}
}

func TestExchangeCode_RejectsAnUnbuildableRequest(t *testing.T) {
	pa := &PendingAuthorization{Connector: "connector-gitlab", TokenEndpoint: "http://\x7f/token", ClientID: "c"}
	// A nil client also exercises the defaultHTTPClient path.
	if _, err := ExchangeCode(context.Background(), nil, pa, "code", nil); err == nil {
		t.Error("an unbuildable token request must fail")
	}
}

// ---------------------------------------------------------------------------
// Default-client (nil) paths
// ---------------------------------------------------------------------------

func TestDiscover_UsesADefaultClientWhenNil(t *testing.T) {
	// A nil client builds the default; a refused connection fails fast (no live
	// server), exercising the default-client and getJSON transport branches.
	if _, err := Discover(context.Background(), nil, "http://127.0.0.1:1", ""); err == nil {
		t.Error("discovery against an unreachable server must fail")
	}
}

func TestRegisterClient_UsesADefaultClientWhenNil(t *testing.T) {
	if _, err := RegisterClient(context.Background(), nil, "http://127.0.0.1:1/register", "https://cb", "mcp"); err == nil {
		t.Error("registration against an unreachable server must fail")
	}
}
