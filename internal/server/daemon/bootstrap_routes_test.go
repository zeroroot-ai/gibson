// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/platform/capabilitygrant"
)

// gibson#1272 — advertised-but-unmounted routes.
//
// The pre-auth listener publishes the bootstrap surface an unauthenticated
// client needs, and the discovery document tells that client where the surface
// is. Those two drifted: the document advertised /.well-known/jwks.json and no
// listener ever mounted it, so the endpoint 404'd while three consumers
// believed it existed.
//
// The tests below exercise the REAL mux built by nativeLoginHandler with real
// HTTP requests. A route that is not mounted returns 404 from http.ServeMux, so
// removing a mux.HandleFunc call — or advertising a path nobody serves — turns
// them red. They assert nothing about the existence of a Go symbol; a handler
// constructor with no caller is exactly the defect they exist to catch.

// testKeyProvider is a crypto.KeyProvider double returning a fixed master key,
// so the mux under test carries a real Minter and serves real key material.
type testKeyProvider struct{ key []byte }

func (k testKeyProvider) GetEncryptionKey(_ context.Context) ([]byte, error) { return k.key, nil }
func (k testKeyProvider) Name() string                                       { return "test" }
func (k testKeyProvider) Health(_ context.Context) types.HealthStatus {
	return types.HealthStatus{State: types.HealthStateHealthy}
}
func (k testKeyProvider) Close() error { return nil }

// bootstrapRegistrarStub satisfies cgBootstrapRegistrar by composing the
// register-path fake with the per-kid agent key lookup fake.
type bootstrapRegistrarStub struct {
	*fakeRegistrar
	*fakeAgentKeyLookup
}

const testDaemonKeyID = "cg-test-v1"

// newTestBootstrapMux builds the pre-auth mux exactly as the daemon does, with
// a real Minter (so the daemon key document is genuine) and stubbed storage.
func newTestBootstrapMux(t *testing.T, publicURL string) http.Handler {
	t.Helper()
	minter, err := capabilitygrant.NewMinter(context.Background(), capabilitygrant.Config{
		Issuer:      publicURL,
		Audience:    "gibson-daemon",
		KeyProvider: testKeyProvider{key: []byte(strings.Repeat("k", 32))},
		KeyID:       testDaemonKeyID,
	})
	if err != nil {
		t.Fatalf("NewMinter: %v", err)
	}
	registrar := bootstrapRegistrarStub{
		fakeRegistrar:      &fakeRegistrar{},
		fakeAgentKeyLookup: &fakeAgentKeyLookup{jwks: []byte(`{"keys":[]}`)},
	}
	return nativeLoginHandler(nativeLoginConfig{
		Issuer:    "https://idp.example.com",
		ClientID:  "cli-123",
		Scopes:    []string{"openid"},
		PublicURL: publicURL,
	}, minter, registrar, nil, nil, nil)
}

// collectAdvertisedURLs walks a decoded discovery document and returns every
// string value that is an absolute URL under base. Walking generically (rather
// than naming the fields) is the point: a field re-added later is covered
// without anyone remembering to extend this test.
func collectAdvertisedURLs(v any, base string, out *[]string) {
	switch t := v.(type) {
	case string:
		if strings.HasPrefix(t, base+"/") {
			*out = append(*out, strings.TrimPrefix(t, base))
		}
	case []any:
		for _, e := range t {
			collectAdvertisedURLs(e, base, out)
		}
	case map[string]any:
		for _, e := range t {
			collectAdvertisedURLs(e, base, out)
		}
	}
}

// TestBootstrapMux_ServesEveryAdvertisedPath is the guard for gibson#1272: every
// URL the discovery document hands to a client must be mounted on the listener
// that serves the document. It fetches the document through the mux, then
// re-requests each advertised path against that same mux.
func TestBootstrapMux_ServesEveryAdvertisedPath(t *testing.T) {
	const public = "https://api.zeroroot.ai:30443"
	srv := httptest.NewServer(newTestBootstrapMux(t, public))
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + agentConfigWellKnownPath)
	if err != nil {
		t.Fatalf("GET discovery: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("discovery status = %d, want 200", resp.StatusCode)
	}
	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decode discovery: %v", err)
	}

	var paths []string
	collectAdvertisedURLs(doc, public, &paths)
	if len(paths) == 0 {
		t.Fatal("discovery document advertised no absolute URLs — the walk found nothing to check, so this test would pass vacuously")
	}

	for _, p := range paths {
		// GET is enough to prove the route exists: a mounted POST-only handler
		// answers 405, an unmounted path answers 404 from http.ServeMux.
		r, err := http.Get(srv.URL + p)
		if err != nil {
			t.Fatalf("GET %s: %v", p, err)
		}
		_ = r.Body.Close()
		if r.StatusCode == http.StatusNotFound {
			t.Errorf("discovery advertises %s but the pre-auth listener does not mount it (404)", p)
		}
	}
}

// TestBootstrapMux_ServesDaemonDispatchKey pins the single key-resolution path
// (ADR-0045): ext-authz resolves the daemon's dispatch signing key by kid from
// this listener. Unmount capabilityGrantKeysPath and this goes red.
func TestBootstrapMux_ServesDaemonDispatchKey(t *testing.T) {
	const public = "https://api.zeroroot.ai:30443"
	srv := httptest.NewServer(newTestBootstrapMux(t, public))
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + capabilityGrantKeysPath + testDaemonKeyID)
	if err != nil {
		t.Fatalf("GET key: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 for the daemon dispatch kid", resp.StatusCode)
	}

	var doc struct {
		Keys []struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Kid string `json:"kid"`
		} `json:"keys"`
		Principal string `json:"principal"`
		Tenant    string `json:"tenant"`
		Status    string `json:"status"`
		D         string `json:"d"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("body is not a parseable key document: %v", err)
	}
	if len(doc.Keys) != 1 {
		t.Fatalf("keys = %d, want exactly the daemon signing key", len(doc.Keys))
	}
	k := doc.Keys[0]
	if k.Kid != testDaemonKeyID || k.Kty != "OKP" || k.Crv != "Ed25519" || k.X == "" {
		t.Errorf("key = %+v, want the OKP/Ed25519 daemon key under kid %q", k, testDaemonKeyID)
	}
	// Public material only. `d` is the Ed25519 private scalar; its presence
	// anywhere in this response would be a private-key disclosure.
	if doc.D != "" {
		t.Error("key document carries a `d` member — private key material must never be served")
	}
	// ext-authz's dispatch verifier accepts only a BARE document; a component
	// binding here would make the daemon key indistinguishable from a
	// registered component key. See internal/server/extauthz/cgjwt/keydoc.go.
	if doc.Principal != "" || doc.Tenant != "" || doc.Status != "" {
		t.Errorf("daemon key document must be bare, got principal=%q tenant=%q status=%q",
			doc.Principal, doc.Tenant, doc.Status)
	}
}

// TestBootstrapMux_PublishesNoKeySetDocument pins the ADR-0045 decision that
// key resolution is fetch-by-kid only. Resurrecting a JWKS-wide endpoint — or
// re-advertising one — has to be a deliberate ADR change, not a drive-by.
func TestBootstrapMux_PublishesNoKeySetDocument(t *testing.T) {
	const public = "https://api.zeroroot.ai:30443"
	srv := httptest.NewServer(newTestBootstrapMux(t, public))
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/.well-known/jwks.json")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("/.well-known/jwks.json status = %d, want 404 — ADR-0045 retires the key-set document", resp.StatusCode)
	}

	b, err := json.Marshal(buildAgentConfigDocument(public))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), "jwks_uri") {
		t.Errorf("discovery document advertises jwks_uri again: %s", b)
	}
}
