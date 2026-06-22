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
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/zeroroot-ai/sdk/capabilitygrant"
)

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

func startJWKSServer(t *testing.T, pub ed25519.PublicKey, kid string, hits *int32) *httptest.Server {
	t.Helper()
	js := struct {
		Keys []map[string]string `json:"keys"`
	}{
		Keys: []map[string]string{{
			"kty": "OKP",
			"crv": "Ed25519",
			"x":   base64.RawURLEncoding.EncodeToString(pub),
			"kid": kid,
			"alg": "EdDSA",
			"use": "sig",
		}},
	}
	body, _ := json.Marshal(js)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(hits, 1)
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestVerifier_HappyPath(t *testing.T) {
	pub, priv := mustGenKey(t)
	var hits int32
	srv := startJWKSServer(t, pub, "k1", &hits)

	v, err := NewVerifier(Config{
		JWKSURL:          srv.URL,
		ExpectedIssuer:   "https://test.daemon/gibson",
		ExpectedAudience: "test-daemon",
		TTL:              time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	tok := mintJWT(t, priv, "k1", validClaims(time.Now().UTC()))
	claims, err := v.Verify(context.Background(), tok)
	if err != nil {
		t.Fatalf("expected ok, got %v", err)
	}
	if claims.Subject != "agent" {
		t.Errorf("subject mismatch")
	}
}

func TestVerifier_CachesKey(t *testing.T) {
	pub, priv := mustGenKey(t)
	var hits int32
	srv := startJWKSServer(t, pub, "k1", &hits)
	v, _ := NewVerifier(Config{
		JWKSURL: srv.URL, ExpectedIssuer: "https://test.daemon/gibson", ExpectedAudience: "test-daemon", TTL: time.Hour,
	})

	tok := mintJWT(t, priv, "k1", validClaims(time.Now().UTC()))
	for i := 0; i < 5; i++ {
		if _, err := v.Verify(context.Background(), tok); err != nil {
			t.Fatalf("iter %d: %v", i, err)
		}
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("expected 1 JWKS fetch, got %d", got)
	}
}

func TestVerifier_RejectsExpiredCacheTriggersRefetch(t *testing.T) {
	pub, priv := mustGenKey(t)
	var hits int32
	srv := startJWKSServer(t, pub, "k1", &hits)
	v, _ := NewVerifier(Config{
		JWKSURL: srv.URL, ExpectedIssuer: "https://test.daemon/gibson", ExpectedAudience: "test-daemon", TTL: 10 * time.Millisecond,
	})

	tok := mintJWT(t, priv, "k1", validClaims(time.Now().UTC()))
	_, _ = v.Verify(context.Background(), tok)
	time.Sleep(20 * time.Millisecond)
	_, _ = v.Verify(context.Background(), tok)
	if got := atomic.LoadInt32(&hits); got < 2 {
		t.Fatalf("expected ≥2 JWKS fetches after TTL expiry, got %d", got)
	}
}

func TestVerifier_BadSignatureFails(t *testing.T) {
	pubA, _ := mustGenKey(t)
	_, privB := mustGenKey(t)
	var hits int32
	srv := startJWKSServer(t, pubA, "k1", &hits)
	v, _ := NewVerifier(Config{
		JWKSURL: srv.URL, ExpectedIssuer: "https://test.daemon/gibson", ExpectedAudience: "test-daemon", TTL: time.Hour,
	})
	tok := mintJWT(t, privB, "k1", validClaims(time.Now().UTC()))
	_, err := v.Verify(context.Background(), tok)
	if err == nil || !errors.Is(err, capabilitygrant.ErrSignature) {
		t.Fatalf("expected ErrSignature, got %v", err)
	}
}

func TestVerifier_UnknownKidFails(t *testing.T) {
	pub, priv := mustGenKey(t)
	var hits int32
	srv := startJWKSServer(t, pub, "k1", &hits)
	v, _ := NewVerifier(Config{
		JWKSURL: srv.URL, ExpectedIssuer: "https://test.daemon/gibson", ExpectedAudience: "test-daemon", TTL: time.Hour,
	})
	tok := mintJWT(t, priv, "k2-not-in-jwks", validClaims(time.Now().UTC()))
	_, err := v.Verify(context.Background(), tok)
	if err == nil {
		t.Fatal("expected error on unknown kid")
	}
}

func TestNewVerifier_RejectsMissingFields(t *testing.T) {
	_, err := NewVerifier(Config{})
	if err == nil || !strings.Contains(err.Error(), "JWKSURL") {
		t.Fatal("expected JWKSURL required")
	}
	_, err = NewVerifier(Config{JWKSURL: "x"})
	if err == nil {
		t.Fatal("expected ExpectedIssuer required")
	}
	_, err = NewVerifier(Config{JWKSURL: "x", ExpectedIssuer: "y"})
	if err == nil {
		t.Fatal("expected ExpectedAudience required")
	}
}

func TestParseJWKS_RejectsNonEd25519(t *testing.T) {
	bad := `{"keys":[{"kty":"RSA","kid":"r1"}]}`
	_, err := parseJWKS([]byte(bad))
	if err == nil {
		t.Fatal("expected rejection")
	}
}
