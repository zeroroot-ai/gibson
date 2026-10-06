// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package zitadel

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/zeroroot-ai/gibson/internal/platform/zitadelconn"
)

// generateTestRSAKey returns a 2048-bit RSA key seeded deterministically.
// Using a fixed seed keeps the generated key identical across runs while
// remaining suitable for signing — the key never leaves the test process.
func generateTestRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	// math/rand for determinism; key never used outside tests.
	//nolint:gosec
	src := rand.NewSource(42)
	r := rand.New(src)
	key, err := rsa.GenerateKey(r, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	return key
}

// writeKeyFile serialises key as a PKCS1 PEM file under t's temp dir.
func writeKeyFile(t *testing.T, key *rsa.PrivateKey) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "rsa-*.pem")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	defer func() { _ = f.Close() }()
	if err := pem.Encode(f, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}); err != nil {
		t.Fatalf("pem.Encode: %v", err)
	}
	return f.Name()
}

// newFakeServer builds an httptest.Server that dispatches on "METHOD /path".
// Unregistered routes cause test failure.
func newFakeServer(t *testing.T, routes map[string]http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Method + " " + r.URL.Path
		if fn, ok := routes[key]; ok {
			fn(w, r)
			return
		}
		t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		http.Error(w, "unexpected route", http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// bearerFromAuth strips the "Bearer " prefix from r's Authorization header.
func bearerFromAuth(r *http.Request) string {
	const prefix = "Bearer "
	v := r.Header.Get("Authorization")
	if !strings.HasPrefix(v, prefix) {
		return ""
	}
	return strings.TrimPrefix(v, prefix)
}

// systemAPIRoute is the System API route the transport tests call.
const systemAPIRoute = "GET /admin/v1/orgs/default"

// callSystemAPI makes one authenticated System API call with the self-signed
// JWT of the client: the call that MintAdminToken makes first.
func callSystemAPI(ctx context.Context, sc SystemClient) error {
	c := sc.(*systemHTTPClient)
	tok, err := c.token(ctx)
	if err != nil {
		return err
	}
	return c.doJSON(ctx, tok, http.MethodGet, "/admin/v1/orgs/default", nil, nil)
}

// TestSystemClient_HappyPath_SelfSignedBearer verifies the JWT-mint →
// direct-bearer-on-System-API flow. Zitadel's System API authenticates
// via a self-signed JWT presented directly in `Authorization: Bearer …`
// — there is NO OIDC token-exchange round-trip.
//
// Reference: https://zitadel.com/docs/guides/integrate/zitadel-apis/access-zitadel-system-api
func TestSystemClient_HappyPath_SelfSignedBearer(t *testing.T) {
	key := generateTestRSAKey(t)
	keyPath := writeKeyFile(t, key)

	const systemUser = "gibson-system-bot"
	var capturedBearer string

	srv := newFakeServer(t, map[string]http.HandlerFunc{
		systemAPIRoute: func(w http.ResponseWriter, r *http.Request) {
			capturedBearer = bearerFromAuth(r)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		},
	})

	sc, err := NewSystemClient(srv.URL, systemUser, testDomain, keyPath)
	if err != nil {
		t.Fatalf("NewSystemClient: %v", err)
	}

	if err := callSystemAPI(context.Background(), sc); err != nil {
		t.Fatalf("System API call: %v", err)
	}

	// --- Verify Bearer is a self-signed JWT (NOT exchanged via OIDC) ---
	if capturedBearer == "" {
		t.Fatal("no Bearer token on /system/v1/* request")
	}
	parsed, err := jwt.Parse(capturedBearer, func(tok *jwt.Token) (any, error) {
		if _, ok := tok.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", tok.Header["alg"])
		}
		return &key.PublicKey, nil
	})
	if err != nil {
		t.Fatalf("verify JWT signature on Bearer: %v", err)
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("claims not MapClaims")
	}
	if got := claims["iss"]; got != systemUser {
		t.Errorf("iss = %q, want %q", got, systemUser)
	}
	if got := claims["sub"]; got != systemUser {
		t.Errorf("sub = %q, want %q", got, systemUser)
	}

	aud, err := parsed.Claims.GetAudience()
	if err != nil || len(aud) == 0 {
		t.Errorf("JWT missing aud claim: %v", err)
	}

	exp, err := parsed.Claims.GetExpirationTime()
	if err != nil || exp == nil {
		t.Fatalf("JWT missing exp: %v", err)
	}
	iat, err := parsed.Claims.GetIssuedAt()
	if err != nil || iat == nil {
		t.Fatalf("JWT missing iat: %v", err)
	}
	ttl := exp.Sub(iat.Time)
	if ttl > systemJWTTTL+time.Second {
		t.Errorf("JWT TTL = %v, want <= %v", ttl, systemJWTTTL)
	}
}

// TestSystemClient_Unauthorized verifies that a 401 from the System API
// wraps both ErrUnauthorized and ErrPermanent so the controller requeue
// loop doesn't retry indefinitely on a misconfigured key.
func TestSystemClient_Unauthorized(t *testing.T) {
	key := generateTestRSAKey(t)
	keyPath := writeKeyFile(t, key)

	srv := newFakeServer(t, map[string]http.HandlerFunc{
		systemAPIRoute: func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized","error_description":"invalid key or user"}`))
		},
	})

	sc, err := NewSystemClient(srv.URL, "gibson-system-bot", testDomain, keyPath)
	if err != nil {
		t.Fatalf("NewSystemClient: %v", err)
	}
	err = callSystemAPI(context.Background(), sc)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrUnauthorized) {
		t.Errorf("want ErrUnauthorized in chain, got: %v", err)
	}
	if !IsPermanent(err) {
		t.Errorf("want IsPermanent(err)=true (not retryable), got false; err: %v", err)
	}
}

// TestSystemClient_ServerError_5xx verifies that a 5xx from the System API surfaces as ErrUnreachable (transient — controller should requeue).
func TestSystemClient_ServerError_5xx(t *testing.T) {
	key := generateTestRSAKey(t)
	keyPath := writeKeyFile(t, key)

	srv := newFakeServer(t, map[string]http.HandlerFunc{
		systemAPIRoute: func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":"internal server error"}`))
		},
	})

	sc, err := NewSystemClient(srv.URL, "gibson-system-bot", testDomain, keyPath)
	if err != nil {
		t.Fatalf("NewSystemClient: %v", err)
	}
	err = callSystemAPI(context.Background(), sc)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrUnreachable) {
		t.Errorf("want ErrUnreachable in chain, got: %v", err)
	}
	if IsPermanent(err) {
		t.Errorf("5xx should NOT be permanent (controller should retry); got permanent err: %v", err)
	}
}

// TestSystemClient_AssertionCaching verifies that the signed JWT is reused
// across multiple calls within its TTL — we don't re-sign on every call.
func TestSystemClient_AssertionCaching(t *testing.T) {
	key := generateTestRSAKey(t)
	keyPath := writeKeyFile(t, key)

	var firstBearer, secondBearer string

	srv := newFakeServer(t, map[string]http.HandlerFunc{
		systemAPIRoute: func(w http.ResponseWriter, r *http.Request) {
			if firstBearer == "" {
				firstBearer = bearerFromAuth(r)
			} else {
				secondBearer = bearerFromAuth(r)
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		},
	})

	sc, err := NewSystemClient(srv.URL, "gibson-system-bot", testDomain, keyPath)
	if err != nil {
		t.Fatalf("NewSystemClient: %v", err)
	}

	ctx := context.Background()
	if err := callSystemAPI(ctx, sc); err != nil {
		t.Fatalf("first System API call: %v", err)
	}
	if err := callSystemAPI(ctx, sc); err != nil {
		t.Fatalf("second System API call: %v", err)
	}

	if firstBearer == "" || secondBearer == "" {
		t.Fatal("missing Bearer on one of the calls")
	}
	if firstBearer != secondBearer {
		t.Errorf("Bearer JWT was re-minted between calls (caching broken)")
	}
}

// TestLoadRSAKey_PKCS1 verifies that LoadRSAKey handles a standard PKCS1
// (RSA PRIVATE KEY) PEM file and returns a key with the correct modulus.
func TestLoadRSAKey_PKCS1(t *testing.T) {
	key := generateTestRSAKey(t)
	path := writeKeyFile(t, key)

	loaded, err := LoadRSAKey(path)
	if err != nil {
		t.Fatalf("LoadRSAKey: %v", err)
	}
	if loaded.N.Cmp(key.N) != 0 {
		t.Error("loaded key modulus does not match original key")
	}
}

// TestLoadRSAKey_NotFound verifies that a missing key file returns a
// descriptive error rather than panicking.
func TestLoadRSAKey_NotFound(t *testing.T) {
	_, err := LoadRSAKey("/nonexistent/path/private-key.pem")
	if err == nil {
		t.Fatal("expected error for missing key file, got nil")
	}
	if !strings.Contains(err.Error(), "read") {
		t.Errorf("expected 'read' in error message, got: %v", err)
	}
}

// TestSystemClient_ClaimsTheHostByHeader verifies that every System API
// request carries the claimed public host in x-zitadel-instance-host and that
// the client does not set the Host header by hand (ADR-0092, gibson#223).
func TestSystemClient_ClaimsTheHostByHeader(t *testing.T) {
	key := generateTestRSAKey(t)
	keyPath := writeKeyFile(t, key)

	var gotInstance, gotHost string

	srv := newFakeServer(t, map[string]http.HandlerFunc{
		systemAPIRoute: func(w http.ResponseWriter, r *http.Request) {
			gotInstance = r.Header.Get(zitadelconn.InstanceHostHeader)
			gotHost = r.Host
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		},
	})

	sc, err := NewSystemClient(srv.URL, "gibson-system-bot", testDomain, keyPath)
	if err != nil {
		t.Fatalf("NewSystemClient: %v", err)
	}
	if err := callSystemAPI(context.Background(), sc); err != nil {
		t.Fatalf("System API call: %v", err)
	}

	if gotInstance != testDomain {
		t.Errorf("instance header = %q, want %q", gotInstance, testDomain)
	}
	if gotHost == testDomain {
		t.Errorf("Host = %q: the client must not forge the Host header", gotHost)
	}
}

// TestSystemClient_AudienceIsThePortlessPublicOrigin pins the JWT audience.
// Zitadel requires the exact string, and a port in it made every System API
// call answer 401 (deploy#1633). The connect address must never appear in it.
func TestSystemClient_AudienceIsThePortlessPublicOrigin(t *testing.T) {
	keyPath := writeKeyFile(t, generateTestRSAKey(t))
	sc, err := NewSystemClient("http://gibson-zitadel.gibson.svc.cluster.local:8080", "gibson-system-bot", testDomain, keyPath)
	if err != nil {
		t.Fatalf("NewSystemClient: %v", err)
	}
	if got, want := sc.(*systemHTTPClient).audience, "https://"+testDomain; got != want {
		t.Errorf("audience = %q, want %q", got, want)
	}
}

// TestSystemClient_RefusesABadEndpoint: a ported or empty claimed host, or a
// connect address that is not a base URL, is refused at construction time.
func TestSystemClient_RefusesABadEndpoint(t *testing.T) {
	keyPath := writeKeyFile(t, generateTestRSAKey(t))
	for name, tc := range map[string]struct{ url, host string }{
		"ported host": {"http://gibson-zitadel:8080", "app.example.test:30443"},
		"empty host":  {"http://gibson-zitadel:8080", ""},
		"bad URL":     {"://bad", testDomain},
	} {
		if _, err := NewSystemClient(tc.url, "gibson-system-bot", tc.host, keyPath); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("%s: NewSystemClient error = %v, want ErrInvalidInput", name, err)
		}
	}
}
