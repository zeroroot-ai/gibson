// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

// deploy#1187: the Capability-Grant per-kid key route must be reachable on the
// mTLS listener, and must stay reachable on the plain-HTTP bootstrap listener
// until the chart repoints. These tests hold both ends of that transition: the
// first fails if the mTLS mount is dropped or never lands, the second fails if
// the plain-HTTP route is removed too early.
//
// The listener itself needs a real SPIFFE X509Source, so these exercise the mux
// the listener serves — the routing decision under test — via httptest.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/infra/observability"
	"github.com/zeroroot-ai/gibson/internal/platform/capabilitygrant"
)

// serveMux runs one GET against h through a live httptest server, so path
// routing is exercised by net/http rather than asserted by inspection.
func serveMux(t *testing.T, h http.Handler, path string) *http.Response {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	resp, err := srv.Client().Get(srv.URL + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	t.Cleanup(func() {
		if cErr := resp.Body.Close(); cErr != nil {
			t.Errorf("close body: %v", cErr)
		}
	})
	return resp
}

func TestAuthzRegistryMux_ServesTheCapabilityGrantKeyRoute(t *testing.T) {
	minter := fakeKeyMinter{keyID: "cg-v1", jwks: []byte(`{"keys":[{"kty":"OKP","kid":"cg-v1"}]}`)}
	lookup := &fakeAgentKeyLookup{}

	resp := serveMux(t, authzRegistryMux(minter, lookup), capabilityGrantKeysPath+"cg-v1")

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("keys route on the mTLS mux: status = %d, want 200", resp.StatusCode)
	}
	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("keys route body is not JSON: %v", err)
	}
	if _, ok := doc["keys"]; !ok {
		t.Fatalf("keys route served a document without a `keys` member: %v", doc)
	}
}

func TestAuthzRegistryMux_StillServesTheRegistry(t *testing.T) {
	// Adding the key route must not disturb the route ext-authz already reads.
	minter := fakeKeyMinter{keyID: "cg-v1", jwks: []byte(`{"keys":[]}`)}
	lookup := &fakeAgentKeyLookup{}

	resp := serveMux(t, authzRegistryMux(minter, lookup), authzRegistryPath)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("registry route: status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/yaml" {
		t.Fatalf("registry content-type = %q, want application/yaml", ct)
	}
}

func TestAuthzRegistryMux_RejectsNonGETOnTheRegistry(t *testing.T) {
	srv := httptest.NewServer(authzRegistryMux(nil, nil))
	t.Cleanup(srv.Close)

	resp, err := srv.Client().Post(srv.URL+authzRegistryPath, "application/yaml", nil)
	if err != nil {
		t.Fatalf("POST %s: %v", authzRegistryPath, err)
	}
	t.Cleanup(func() {
		if cErr := resp.Body.Close(); cErr != nil {
			t.Errorf("close body: %v", cErr)
		}
	})
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST to the registry: status = %d, want 405", resp.StatusCode)
	}
}

func TestCGKeySources_MapNilPointersToNilInterfaces(t *testing.T) {
	// The trap this guards: a typed nil pointer assigned into an interface is
	// NOT nil, so passing the daemon's pointers straight through would mount a
	// route on a nil receiver. Both narrowing helpers must return interfaces
	// that compare equal to nil, or the routes mount and panic.
	minter, lookup := cgKeySources(nil, nil)
	if minter != nil || lookup != nil {
		t.Fatalf("cgKeySources(nil, nil) = (%v, %v), want (nil, nil)", minter, lookup)
	}
	bMinter, bSvc := cgBootstrapSources(nil, nil)
	if bMinter != nil || bSvc != nil {
		t.Fatalf("cgBootstrapSources(nil, nil) = (%v, %v), want (nil, nil)", bMinter, bSvc)
	}
}

func TestCGKeySources_PassRealPointersThrough(t *testing.T) {
	// The other half: a present source must actually reach the route, or the
	// nil-narrowing would be a way to lose the key endpoint entirely. Zero
	// values suffice — the helpers only test the pointers, never deref them.
	m, s := &capabilitygrant.Minter{}, &capabilitygrant.CapabilityGrantService{}

	minter, lookup := cgKeySources(m, s)
	if minter == nil || lookup == nil {
		t.Fatalf("cgKeySources(non-nil, non-nil) = (%v, %v), want both non-nil", minter, lookup)
	}
	bMinter, bSvc := cgBootstrapSources(m, s)
	if bMinter == nil || bSvc == nil {
		t.Fatalf("cgBootstrapSources(non-nil, non-nil) = (%v, %v), want both non-nil", bMinter, bSvc)
	}
}

func TestNewNativeLoginSubsystem_BuildsAListenerWithoutKeySources(t *testing.T) {
	logCfg := observability.ConfigFromEnv()
	logCfg.Component = "authz-registry-test"
	logger := observability.NewLogger(logCfg)
	sys := newNativeLoginSubsystem(
		nativeLoginConfig{Port: "8085", Issuer: "https://idp.example", ClientID: "cid"},
		logger, nil, nil, nil, nil)

	if sys.srv.Addr != ":8085" {
		t.Fatalf("listener addr = %q, want :8085", sys.srv.Addr)
	}
	if sys.srv.ReadHeaderTimeout == 0 {
		t.Fatal("ReadHeaderTimeout is unset; a pre-auth listener must bound header reads")
	}
	// nil key sources leave the CG routes absent rather than mounted on a nil
	// receiver — the narrowing in cgBootstrapSources doing its job end to end.
	resp := serveMux(t, sys.srv.Handler, capabilityGrantKeysPath+"cg-v1")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("keys route with no key source: status = %d, want 404", resp.StatusCode)
	}
}

func TestAuthzRegistryMux_OmitsTheKeyRouteWithoutKeySources(t *testing.T) {
	// A nil key source must leave the route absent (404), not mounted and
	// permanently 503 — the same rule the pre-auth listener follows.
	resp := serveMux(t, authzRegistryMux(nil, nil), capabilityGrantKeysPath+"cg-v1")

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unmounted keys route: status = %d, want 404", resp.StatusCode)
	}
}

// fakeCGBootstrapMinter is the pre-auth listener's Minter surface: bootstrap
// verification plus key serving.
type fakeCGBootstrapMinter struct {
	fakeBootstrapVerifier
	fakeKeyMinter
}

// fakeCGBootstrapService is the pre-auth listener's service surface:
// registration plus agent key lookup.
type fakeCGBootstrapService struct {
	*fakeRegistrar
	*fakeAgentKeyLookup
}

func TestNativeLoginMux_StillServesTheCapabilityGrantKeyRoute(t *testing.T) {
	// The plain-HTTP route is load-bearing until the chart moves to the mTLS
	// URL: deployed ext-authz instances read it to authenticate every
	// component. Deleting it here — rather than in the follow-up, after the
	// chart repoints — is a cluster-wide outage, so this test refuses the
	// premature removal.
	cfg := nativeLoginConfig{Port: "0", Issuer: "https://idp.example", ClientID: "cid"}
	minter := fakeCGBootstrapMinter{
		fakeKeyMinter: fakeKeyMinter{keyID: "cg-v1", jwks: []byte(`{"keys":[{"kty":"OKP","kid":"cg-v1"}]}`)},
	}
	svc := fakeCGBootstrapService{
		fakeRegistrar:      &fakeRegistrar{},
		fakeAgentKeyLookup: &fakeAgentKeyLookup{},
	}

	resp := serveMux(t, nativeLoginHandler(cfg, minter, svc, nil, nil, nil), capabilityGrantKeysPath+"cg-v1")

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("keys route on the plain-HTTP bootstrap listener: status = %d, want 200", resp.StatusCode)
	}
	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("keys route body is not JSON: %v", err)
	}
	if _, ok := doc["keys"]; !ok {
		t.Fatalf("keys route served a document without a `keys` member: %v", doc)
	}
}
