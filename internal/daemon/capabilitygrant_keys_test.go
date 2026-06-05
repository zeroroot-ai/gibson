package daemon

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

type fakeKeyMinter struct {
	keyID string
	jwks  []byte
	err   error
}

func (f fakeKeyMinter) KeyID() string                  { return f.keyID }
func (f fakeKeyMinter) PublicKeyJWKS() ([]byte, error) { return f.jwks, f.err }

type fakeAgentKeyLookup struct {
	gotKid string
	jwks   []byte
	err    error
}

func (f *fakeAgentKeyLookup) AgentPublicKeyJWKS(_ context.Context, kid string) ([]byte, error) {
	f.gotKid = kid
	return f.jwks, f.err
}

func getKey(t *testing.T, h http.HandlerFunc, kid string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, capabilityGrantKeysPath+kid, nil)
	rr := httptest.NewRecorder()
	h(rr, req)
	return rr
}

func TestCGKeys_DaemonKey_ServesMinterJWKS(t *testing.T) {
	minter := fakeKeyMinter{keyID: "cg-v1", jwks: []byte(`{"keys":[{"kty":"OKP","kid":"cg-v1"}]}`)}
	lookup := &fakeAgentKeyLookup{}
	rr := getKey(t, capabilityGrantKeysHandler(minter, lookup), "cg-v1")

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	if lookup.gotKid != "" {
		t.Fatalf("agent lookup should not be consulted for the daemon kid, got %q", lookup.gotKid)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type = %q, want application/json", ct)
	}
	var doc map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &doc); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
}

func TestCGKeys_AgentKid_ServesAgentJWKS(t *testing.T) {
	minter := fakeKeyMinter{keyID: "cg-v1"}
	lookup := &fakeAgentKeyLookup{jwks: []byte(`{"keys":[{"kty":"OKP","kid":"agent-xyz"}]}`)}
	rr := getKey(t, capabilityGrantKeysHandler(minter, lookup), "agent-xyz")

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	if lookup.gotKid != "agent-xyz" {
		t.Fatalf("agent lookup kid = %q, want agent-xyz", lookup.gotKid)
	}
}

func TestCGKeys_UnknownAgent_404(t *testing.T) {
	minter := fakeKeyMinter{keyID: "cg-v1"}
	lookup := &fakeAgentKeyLookup{err: context.DeadlineExceeded} // any error → withheld
	rr := getKey(t, capabilityGrantKeysHandler(minter, lookup), "missing")

	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rr.Code)
	}
}

func TestCGKeys_MissingKid_400(t *testing.T) {
	minter := fakeKeyMinter{keyID: "cg-v1"}
	lookup := &fakeAgentKeyLookup{}
	// Request the prefix itself with no kid tail.
	req := httptest.NewRequest(http.MethodGet, capabilityGrantKeysPath, nil)
	rr := httptest.NewRecorder()
	capabilityGrantKeysHandler(minter, lookup)(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
}

func TestCGKeys_WrongMethod_405(t *testing.T) {
	minter := fakeKeyMinter{keyID: "cg-v1"}
	lookup := &fakeAgentKeyLookup{}
	req := httptest.NewRequest(http.MethodPost, capabilityGrantKeysPath+"cg-v1", nil)
	rr := httptest.NewRecorder()
	capabilityGrantKeysHandler(minter, lookup)(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rr.Code)
	}
}
