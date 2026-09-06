// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package cgjwt

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/zeroroot-ai/sdk/capabilitygrant"
)

const testKeysPath = "/capabilitygrant/v1/keys/"

func mustGenKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func mintJWT(t *testing.T, priv ed25519.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tok.Header["kid"] = kid
	signed, err := tok.SignedString(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func validClaims(now time.Time) jwt.MapClaims {
	return jwt.MapClaims{
		"iss":          "https://test.daemon/gibson",
		"aud":          "test-daemon",
		"sub":          "agent",
		"tenant":       "acme",
		"mission_id":   "m",
		"task_id":      "t",
		"jti":          "j",
		"iat":          now.Unix(),
		"exp":          now.Add(15 * time.Minute).Unix(),
		"allowed_rpcs": []any{"/x.S/M"},
	}
}

// keyServer stands in for the daemon's pre-auth listener: it serves the per-kid
// key document and NOTHING else, so a verifier that reaches for a key-set
// document (or for any other path) fails loudly instead of silently working.
//
// It records the RAW request URI, not the decoded r.URL.Path. Those differ
// exactly where it matters: an unescaped traversal kid arrives on the wire as
// "/keys/../../x" (which Envoy and any normalising proxy resolve to a different
// endpoint), while an escaped one arrives as "/keys/..%2F..%2Fx" and stays a
// single path segment. r.URL.Path is identical for both, so asserting on it
// would make the escaping untestable.
type keyServer struct {
	*httptest.Server
	hits int32

	mu        sync.Mutex
	rawURIs   []string
	pathsSeen []string
}

func (k *keyServer) requestedRaw() []string {
	k.mu.Lock()
	defer k.mu.Unlock()
	return append([]string(nil), k.rawURIs...)
}

func (k *keyServer) requested() []string {
	k.mu.Lock()
	defer k.mu.Unlock()
	return append([]string(nil), k.pathsSeen...)
}

// startKeyServer serves doc at testKeysPath+kid. Pass a bare document (no
// principal/tenant/status) to model the daemon's own dispatch key.
func startKeyServer(t *testing.T, kid string, doc map[string]any) *keyServer {
	t.Helper()
	body, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	ks := &keyServer{}
	ks.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ks.mu.Lock()
		ks.rawURIs = append(ks.rawURIs, r.RequestURI)
		ks.pathsSeen = append(ks.pathsSeen, r.URL.Path)
		ks.mu.Unlock()
		atomic.AddInt32(&ks.hits, 1)
		if r.URL.Path != testKeysPath+kid {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(ks.Close)
	return ks
}

func bareKeyDoc(pub ed25519.PublicKey, kid string) map[string]any {
	return map[string]any{"keys": []any{map[string]any{
		"kty": "OKP",
		"crv": "Ed25519",
		"x":   base64.RawURLEncoding.EncodeToString(pub),
		"kid": kid,
		"alg": "EdDSA",
		"use": "sig",
	}}}
}

func newTestVerifier(t *testing.T, ks *keyServer, ttl time.Duration) *Verifier {
	t.Helper()
	v, err := NewVerifier(Config{
		KeysBaseURL:      ks.URL + strings.TrimSuffix(testKeysPath, "/"),
		ExpectedIssuer:   "https://test.daemon/gibson",
		ExpectedAudience: "test-daemon",
		TTL:              ttl,
		HTTPClient:       ks.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// TestVerifier_ResolvesKeyByKid is the ADR-0045 contract: the dispatch verifier
// resolves its key from the daemon's per-kid endpoint and never asks for a
// key-set document. gibson#1272 — the key-set document does not exist.
func TestVerifier_ResolvesKeyByKid(t *testing.T) {
	pub, priv := mustGenKey(t)
	ks := startKeyServer(t, "k1", bareKeyDoc(pub, "k1"))
	v := newTestVerifier(t, ks, time.Hour)

	tok := mintJWT(t, priv, "k1", validClaims(time.Now().UTC()))
	claims, err := v.Verify(context.Background(), tok)
	if err != nil {
		t.Fatalf("expected ok, got %v", err)
	}
	if claims.Subject != "agent" {
		t.Errorf("subject = %q, want agent", claims.Subject)
	}

	got := ks.requested()
	if len(got) != 1 || got[0] != testKeysPath+"k1" {
		t.Fatalf("requested %v, want exactly [%s]", got, testKeysPath+"k1")
	}
	for _, p := range got {
		if strings.Contains(p, "jwks.json") {
			t.Errorf("verifier fetched a key-set document at %s; key resolution is per-kid only", p)
		}
	}
}

func TestVerifier_CachesKey(t *testing.T) {
	pub, priv := mustGenKey(t)
	ks := startKeyServer(t, "k1", bareKeyDoc(pub, "k1"))
	v := newTestVerifier(t, ks, time.Hour)

	tok := mintJWT(t, priv, "k1", validClaims(time.Now().UTC()))
	for i := 0; i < 5; i++ {
		if _, err := v.Verify(context.Background(), tok); err != nil {
			t.Fatalf("iter %d: %v", i, err)
		}
	}
	if got := atomic.LoadInt32(&ks.hits); got != 1 {
		t.Fatalf("expected 1 key fetch, got %d", got)
	}
}

func TestVerifier_RefetchesAfterTTL(t *testing.T) {
	pub, priv := mustGenKey(t)
	ks := startKeyServer(t, "k1", bareKeyDoc(pub, "k1"))
	v := newTestVerifier(t, ks, 10*time.Millisecond)

	tok := mintJWT(t, priv, "k1", validClaims(time.Now().UTC()))
	_, _ = v.Verify(context.Background(), tok)
	time.Sleep(20 * time.Millisecond)
	_, _ = v.Verify(context.Background(), tok)
	if got := atomic.LoadInt32(&ks.hits); got < 2 {
		t.Fatalf("expected ≥2 key fetches after TTL expiry, got %d", got)
	}
}

func TestVerifier_BadSignatureFails(t *testing.T) {
	pubA, _ := mustGenKey(t)
	_, privB := mustGenKey(t)
	ks := startKeyServer(t, "k1", bareKeyDoc(pubA, "k1"))
	v := newTestVerifier(t, ks, time.Hour)

	tok := mintJWT(t, privB, "k1", validClaims(time.Now().UTC()))
	_, err := v.Verify(context.Background(), tok)
	if err == nil || !errors.Is(err, capabilitygrant.ErrSignature) {
		t.Fatalf("expected ErrSignature, got %v", err)
	}
}

func TestVerifier_UnknownKidFails(t *testing.T) {
	pub, priv := mustGenKey(t)
	ks := startKeyServer(t, "k1", bareKeyDoc(pub, "k1"))
	v := newTestVerifier(t, ks, time.Hour)

	tok := mintJWT(t, priv, "k2-not-registered", validClaims(time.Now().UTC()))
	_, err := v.Verify(context.Background(), tok)
	if err == nil || !errors.Is(err, capabilitygrant.ErrUnknownKey) {
		t.Fatalf("expected ErrUnknownKey, got %v", err)
	}
}

// TestVerifier_RejectsComponentKeyDocument preserves the property the retired
// key-set document had implicitly. That document held the daemon key and
// nothing else, so no component kid could ever resolve on the dispatch path.
// Per-kid resolution can reach every registered component key, so the dispatch
// verifier has to refuse a document that carries a component binding —
// otherwise a component could self-sign a token that ext-authz treats as
// daemon-minted.
func TestVerifier_RejectsComponentKeyDocument(t *testing.T) {
	pub, priv := mustGenKey(t)
	doc := bareKeyDoc(pub, "agent-xyz")
	doc["principal"] = "agent_principal:acct-1"
	doc["tenant"] = "acme"
	doc["status"] = "active"
	ks := startKeyServer(t, "agent-xyz", doc)
	v := newTestVerifier(t, ks, time.Hour)

	tok := mintJWT(t, priv, "agent-xyz", validClaims(time.Now().UTC()))
	_, err := v.Verify(context.Background(), tok)
	if err == nil || !errors.Is(err, capabilitygrant.ErrUnknownKey) {
		t.Fatalf("a component key document must not verify a dispatch CG-JWT; got %v", err)
	}
}

// TestVerifier_EscapesKidInPath — kid comes from an unverified JWT header. It
// must not be able to steer the fetch at a different daemon path.
func TestVerifier_EscapesKidInPath(t *testing.T) {
	pub, priv := mustGenKey(t)
	ks := startKeyServer(t, "k1", bareKeyDoc(pub, "k1"))
	v := newTestVerifier(t, ks, time.Hour)

	tok := mintJWT(t, priv, "../../.well-known/jwks.json", validClaims(time.Now().UTC()))
	if _, err := v.Verify(context.Background(), tok); err == nil {
		t.Fatal("expected the traversal kid to fail resolution")
	}
	raw := ks.requestedRaw()
	if len(raw) == 0 {
		t.Fatal("no request reached the key server; nothing was asserted")
	}
	for _, u := range raw {
		// path.Clean resolves the dot segments the way a normalising proxy
		// would. An escaped kid has none to resolve and stays under the base.
		if !strings.HasPrefix(path.Clean(u), testKeysPath) {
			t.Errorf("kid escaped the key endpoint: raw request URI %q resolves to %q", u, path.Clean(u))
		}
	}
}

func TestNewVerifier_RejectsMissingFields(t *testing.T) {
	_, err := NewVerifier(Config{})
	if err == nil || !strings.Contains(err.Error(), "KeysBaseURL") {
		t.Fatalf("expected KeysBaseURL required, got %v", err)
	}
	_, err = NewVerifier(Config{KeysBaseURL: "x"})
	if err == nil {
		t.Fatal("expected ExpectedIssuer required")
	}
	_, err = NewVerifier(Config{KeysBaseURL: "x", ExpectedIssuer: "y"})
	if err == nil {
		t.Fatal("expected ExpectedAudience required")
	}
	// The key document is the trust anchor, so the transport that fetches it
	// is never defaulted: a nil client is a construction error, not a bare
	// http.Client (GHSA-8m76-9r77-xvh3).
	_, err = NewVerifier(Config{KeysBaseURL: "x", ExpectedIssuer: "y", ExpectedAudience: "z"})
	if err == nil || !strings.Contains(err.Error(), "HTTPClient") {
		t.Fatalf("expected HTTPClient required, got %v", err)
	}
}

func TestEd25519FromKeyDoc_RejectsNonEd25519(t *testing.T) {
	var doc keyDoc
	if err := json.Unmarshal([]byte(`{"keys":[{"kty":"RSA","kid":"r1"}]}`), &doc); err != nil {
		t.Fatal(err)
	}
	if _, err := ed25519FromKeyDoc(doc, "r1"); err == nil {
		t.Fatal("expected rejection of a non-Ed25519 key")
	}
}
