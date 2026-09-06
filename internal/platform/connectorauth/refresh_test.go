// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package connectorauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeStore is an in-memory broker. It records writes so a test can assert
// what the platform published, and to which name.
type fakeStore struct {
	mu      sync.Mutex
	data    map[string][]byte
	putErr  map[string]error
	resolve int
}

func newStore() *fakeStore {
	return &fakeStore{data: map[string][]byte{}, putErr: map[string]error{}}
}

func (f *fakeStore) Resolve(_ context.Context, name string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resolve++
	v, ok := f.data[name]
	if !ok {
		return nil, errors.New("not found")
	}
	return v, nil
}

func (f *fakeStore) Put(_ context.Context, name string, value []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.putErr[name]; err != nil {
		return err
	}
	f.data[name] = append([]byte(nil), value...)
	return nil
}

func (f *fakeStore) get(name string) []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.data[name]
}

func seedGrant(t *testing.T, s *fakeStore, connector, endpoint, refresh string) {
	t.Helper()
	blob, err := MarshalGrant(&Grant{
		RefreshToken:  refresh,
		TokenEndpoint: endpoint,
		ClientID:      "client-abc",
		Scope:         "api read_repository",
		AuthorizedBy:  "alice@example.com",
		AuthorizedAt:  time.Unix(1_700_000_000, 0).UTC(),
	})
	if err != nil {
		t.Fatalf("seed grant: %v", err)
	}
	_ = s.Put(context.Background(), GrantSecretName(connector), blob)
}

// tokenServer answers the refresh_token grant. rotate controls whether it
// issues a new refresh token, which OAuth 2.1 mandates.
func tokenServer(t *testing.T, rotate bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		body := map[string]any{"access_token": "at-new", "expires_in": 3600, "token_type": "Bearer"}
		if rotate {
			body["refresh_token"] = "rt-rotated"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	}))
}

func TestRefresh_PublishesAccessTokenToItsOwnSecret(t *testing.T) {
	s := newStore()
	srv := tokenServer(t, false)
	defer srv.Close()
	seedGrant(t, s, "gitlab", srv.URL, "rt-1")

	r, err := NewRefresher(s, srv.Client(), nil)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := r.Refresh(context.Background(), "gitlab")
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if tok.Token != "at-new" {
		t.Errorf("token = %q, want at-new", tok.Token)
	}

	// The access token lands under its OWN name, never merged into the grant,
	// and holds the RAW token bytes: the bridge presents the resolved value
	// verbatim as `Bearer <bytes>`, so a JSON wrapper would reach the vendor
	// as a malformed credential.
	if got := string(s.get(AccessSecretName("gitlab"))); got != "at-new" {
		t.Errorf("published access secret = %q, want the raw token", got)
	}

	// The expiry the refresher schedules against is platform bookkeeping and
	// lives in the separate platform-only metadata secret.
	var meta AccessToken
	if err := json.Unmarshal(s.get(AccessMetaSecretName("gitlab")), &meta); err != nil {
		t.Fatalf("access metadata secret: %v", err)
	}
	if meta.ExpiresAt.IsZero() {
		t.Error("access metadata must carry the expiry")
	}
}

// The refresh token must NEVER appear in the secret a connector can resolve.
// If it did, a compromised vendor MCP server would walk away with standing
// access rather than a credential that expires.
func TestRefresh_AccessSecretCarriesNoRefreshToken(t *testing.T) {
	s := newStore()
	srv := tokenServer(t, true)
	defer srv.Close()
	seedGrant(t, s, "gitlab", srv.URL, "rt-secret-value")

	r, _ := NewRefresher(s, srv.Client(), nil)
	if _, err := r.Refresh(context.Background(), "gitlab"); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{AccessSecretName("gitlab"), AccessMetaSecretName("gitlab")} {
		published := string(s.get(name))
		for _, forbidden := range []string{"rt-secret-value", "rt-rotated", "refresh_token", "client-abc"} {
			if strings.Contains(published, forbidden) {
				t.Errorf("%s leaked %q: %s", name, forbidden, published)
			}
		}
	}
}

// OAuth 2.1 invalidates the old refresh token on every refresh. Failing to
// persist the rotated one leaves a grant that works until the next restart and
// then never again — the exact failure a bridge-owned token could not avoid.
func TestRefresh_PersistsRotatedRefreshToken(t *testing.T) {
	s := newStore()
	srv := tokenServer(t, true)
	defer srv.Close()
	seedGrant(t, s, "gitlab", srv.URL, "rt-old")

	r, _ := NewRefresher(s, srv.Client(), nil)
	if _, err := r.Refresh(context.Background(), "gitlab"); err != nil {
		t.Fatal(err)
	}

	g, err := UnmarshalGrant(s.get(GrantSecretName("gitlab")))
	if err != nil {
		t.Fatalf("grant after rotation: %v", err)
	}
	if g.RefreshToken != "rt-rotated" {
		t.Errorf("refresh token = %q, want the rotated rt-rotated", g.RefreshToken)
	}
	if g.AuthorizedBy != "alice@example.com" {
		t.Errorf("rotation dropped the authorizing human: %q", g.AuthorizedBy)
	}
}

// If the rotated grant cannot be stored, the refresh must fail rather than
// publish an access token against a grant the vendor has already invalidated.
func TestRefresh_FailsWhenRotatedGrantCannotBePersisted(t *testing.T) {
	s := newStore()
	srv := tokenServer(t, true)
	defer srv.Close()
	seedGrant(t, s, "gitlab", srv.URL, "rt-old")
	s.putErr[GrantSecretName("gitlab")] = errors.New("broker down")

	r, _ := NewRefresher(s, srv.Client(), nil)
	if _, err := r.Refresh(context.Background(), "gitlab"); err == nil {
		t.Fatal("a failed rotation write must fail the refresh")
	}
	if s.get(AccessSecretName("gitlab")) != nil {
		t.Error("no access token may be published when the rotation write failed")
	}
}

// An operator must be able to tell a revoked grant from a misconfigured client.
func TestRefresh_SurfacesTheVendorError(t *testing.T) {
	s := newStore()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	defer srv.Close()
	seedGrant(t, s, "gitlab", srv.URL, "rt-1")

	r, _ := NewRefresher(s, srv.Client(), nil)
	_, err := r.Refresh(context.Background(), "gitlab")
	if err == nil {
		t.Fatal("a refused refresh must be an error")
	}
	if !strings.Contains(err.Error(), "invalid_grant") {
		t.Errorf("error must carry the vendor's code, got %v", err)
	}
}

// No error may carry the refresh token itself.
func TestRefresh_ErrorsNeverCarryTheRefreshToken(t *testing.T) {
	s := newStore()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
	}))
	defer srv.Close()
	seedGrant(t, s, "gitlab", srv.URL, "rt-super-secret")

	r, _ := NewRefresher(s, srv.Client(), nil)
	if _, err := r.Refresh(context.Background(), "gitlab"); err != nil {
		if strings.Contains(err.Error(), "rt-super-secret") {
			t.Fatal("an error must never carry the refresh token")
		}
	}
}

func TestRefresh_IncompleteGrantIsRefused(t *testing.T) {
	s := newStore()
	// A grant with no authorizing human is a service account nobody is
	// accountable for, which ADR-0064 refuses.
	_ = s.Put(context.Background(), GrantSecretName("gitlab"),
		[]byte(`{"refresh_token":"r","token_endpoint":"https://x/","client_id":"c"}`))

	r, _ := NewRefresher(s, nil, nil)
	if _, err := r.Refresh(context.Background(), "gitlab"); err == nil {
		t.Fatal("a grant with no authorized_by must be refused")
	}
}

func TestNeedsRefresh(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	s := newStore()
	r, _ := NewRefresher(s, nil, func() time.Time { return now })

	if !r.NeedsRefresh(context.Background(), "gitlab") {
		t.Error("absent token must need refresh")
	}

	// A published token with no metadata is a half-written state — refresh.
	_ = s.Put(context.Background(), AccessSecretName("gitlab"), []byte("at-1"))
	if !r.NeedsRefresh(context.Background(), "gitlab") {
		t.Error("token without expiry metadata must need refresh")
	}

	_ = s.Put(context.Background(), AccessMetaSecretName("gitlab"), []byte("not json"))
	if !r.NeedsRefresh(context.Background(), "gitlab") {
		t.Error("unreadable expiry metadata must need refresh")
	}

	fresh, _ := json.Marshal(AccessToken{Token: "at-1", ExpiresAt: now.Add(time.Hour)})
	_ = s.Put(context.Background(), AccessMetaSecretName("gitlab"), fresh)
	if r.NeedsRefresh(context.Background(), "gitlab") {
		t.Error("a token an hour from expiry must not need refresh")
	}

	// Inside the skew window: expiring in 30s is expired for our purposes,
	// because a token that dies in flight is indistinguishable from a revoked
	// one at the vendor.
	soon, _ := json.Marshal(AccessToken{Token: "at-1", ExpiresAt: now.Add(30 * time.Second)})
	_ = s.Put(context.Background(), AccessMetaSecretName("gitlab"), soon)
	if !r.NeedsRefresh(context.Background(), "gitlab") {
		t.Error("a token inside the skew window must need refresh")
	}

	// A widened skew treats a longer-lived token as expiring: the loop sets
	// skew above its tick interval so a token never dies between passes.
	wide, _ := NewRefresher(s, nil, func() time.Time { return now }, WithSkew(2*time.Hour))
	if !wide.NeedsRefresh(context.Background(), "gitlab") {
		t.Error("a token inside a widened skew window must need refresh")
	}
}

func TestEnsureFresh_OnlyRefreshesWhenNeeded(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	s := newStore()
	srv := tokenServer(t, false)
	defer srv.Close()
	seedGrant(t, s, "gitlab", srv.URL, "rt-1")

	r, _ := NewRefresher(s, srv.Client(), func() time.Time { return now })

	did, err := r.EnsureFresh(context.Background(), "gitlab")
	if err != nil || !did {
		t.Fatalf("first call must refresh: did=%v err=%v", did, err)
	}
	did, err = r.EnsureFresh(context.Background(), "gitlab")
	if err != nil || did {
		t.Fatalf("second call must not refresh: did=%v err=%v", did, err)
	}
}

// seedStaticGrant stores a static grant the way SetConnectorSecret does: the
// credential in the access secret, a static grant beside it, no access
// metadata (a static credential has no expiry the platform manages).
func seedStaticGrant(t *testing.T, s *fakeStore, connector, credential string) {
	t.Helper()
	blob, err := MarshalGrant(&Grant{
		Static:       true,
		AuthorizedBy: "user:user-1",
		AuthorizedAt: time.Unix(1_700_000_000, 0).UTC(),
	})
	if err != nil {
		t.Fatalf("seed static grant: %v", err)
	}
	_ = s.Put(context.Background(), AccessSecretName(connector), []byte(credential))
	_ = s.Put(context.Background(), GrantSecretName(connector), blob)
}

// A static credential is never refreshed (ADR-0015): EnsureFresh reports no
// refresh, makes no vendor call, and leaves the credential exactly as the
// tenant admin set it, pass after pass.
func TestEnsureFresh_StaticGrantIsNeverRefreshed(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	s := newStore()
	seedStaticGrant(t, s, "github", "ghp_static")

	r, _ := NewRefresher(s, &http.Client{Transport: failingTransport{}}, func() time.Time { return now })

	for i := range 2 {
		did, err := r.EnsureFresh(context.Background(), "github")
		if err != nil || did {
			t.Fatalf("pass %d: static grant must be a quiet no-op: did=%v err=%v", i, did, err)
		}
	}
	if got := string(s.get(AccessSecretName("github"))); got != "ghp_static" {
		t.Errorf("credential changed to %q; a static credential must stay as set", got)
	}
}

// A direct Refresh on a static grant is refused rather than sent to a vendor
// with an empty refresh token.
func TestRefresh_StaticGrantIsRefused(t *testing.T) {
	s := newStore()
	seedStaticGrant(t, s, "github", "ghp_static")
	r, _ := NewRefresher(s, &http.Client{Transport: failingTransport{}}, nil)

	if _, err := r.Refresh(context.Background(), "github"); err == nil {
		t.Fatal("Refresh on a static grant must fail")
	}
}

// failingTransport fails every HTTP call, so a test proves no vendor call is
// made by the absence of that failure.
type failingTransport struct{}

func (failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("unexpected vendor call")
}
