// Copyright 2026 Hack the Planet LLC
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package zitadel

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
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

// testInstanceID is the canned Zitadel instance ID returned by the
// /system/v1/instances/_search fake handler that every test installs.
const testInstanceID = "372802942115250284"

// instanceSearchHandler is the shared handler for the instance-discovery
// call that runs first in every System API operation. Returns a single
// instance whose ID is testInstanceID.
func instanceSearchHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{
			"result": [
				{"id": %q, "name": "ZITADEL", "domain": "auth.zeroroot.local"}
			],
			"details": {"totalResult": "1"}
		}`, testInstanceID)
	}
}

// TestSystemClient_HappyPath_AddInstanceDomain verifies the JWT-mint →
// direct-bearer-on-System-API flow. Zitadel's System API authenticates
// via a self-signed JWT presented directly in `Authorization: Bearer …`
// — there is NO OIDC token-exchange round-trip.
//
// Reference: https://zitadel.com/docs/guides/integrate/zitadel-apis/access-zitadel-system-api
func TestSystemClient_HappyPath_AddInstanceDomain(t *testing.T) {
	key := generateTestRSAKey(t)
	keyPath := writeKeyFile(t, key)

	const systemUser = "gibson-system-bot"
	var capturedBearer string
	var capturedDomainBody []byte

	srv := newFakeServer(t, map[string]http.HandlerFunc{
		"POST /system/v1/instances/_search": instanceSearchHandler(),
		"POST /system/v1/instances/372802942115250284/domains": func(w http.ResponseWriter, r *http.Request) {
			capturedBearer = bearerFromAuth(r)
			capturedDomainBody, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		},
	})

	sc, err := NewSystemClient(srv.URL, systemUser, "", keyPath)
	if err != nil {
		t.Fatalf("NewSystemClient: %v", err)
	}

	const targetDomain = "gibson-zitadel.gibson.svc.cluster.local"
	if err := sc.AddInstanceDomain(context.Background(), targetDomain); err != nil {
		t.Fatalf("AddInstanceDomain: %v", err)
	}

	// --- Verify request body contained the domain ---
	var domainPayload struct {
		Domain string `json:"domain"`
	}
	if err := json.Unmarshal(capturedDomainBody, &domainPayload); err != nil {
		t.Fatalf("parse domain request body: %v", err)
	}
	if domainPayload.Domain != targetDomain {
		t.Errorf("domain in request = %q, want %q", domainPayload.Domain, targetDomain)
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

// TestSystemClient_Idempotent_409 verifies that a 409 Conflict response
// from AddInstanceDomain (domain already registered) returns nil.
func TestSystemClient_Idempotent_409(t *testing.T) {
	key := generateTestRSAKey(t)
	keyPath := writeKeyFile(t, key)

	srv := newFakeServer(t, map[string]http.HandlerFunc{
		"POST /system/v1/instances/_search": instanceSearchHandler(),
		"POST /system/v1/instances/372802942115250284/domains": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"code":6,"message":"domain already registered"}`))
		},
	})

	sc, err := NewSystemClient(srv.URL, "gibson-system-bot", "", keyPath)
	if err != nil {
		t.Fatalf("NewSystemClient: %v", err)
	}
	if err := sc.AddInstanceDomain(context.Background(), "already.example"); err != nil {
		t.Fatalf("AddInstanceDomain 409 returned error: %v", err)
	}
}

// TestSystemClient_Idempotent_AlreadyExistsBody verifies that a 400-level
// response whose body contains "already exists" is treated as idempotent.
// Zitadel sometimes returns a 400 with an "already exists" error code instead
// of a true 409.
func TestSystemClient_Idempotent_AlreadyExistsBody(t *testing.T) {
	key := generateTestRSAKey(t)
	keyPath := writeKeyFile(t, key)

	srv := newFakeServer(t, map[string]http.HandlerFunc{
		"POST /system/v1/instances/_search": instanceSearchHandler(),
		"POST /system/v1/instances/372802942115250284/domains": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"code":6,"message":"domain already exists","details":[]}`))
		},
	})

	sc, err := NewSystemClient(srv.URL, "gibson-system-bot", "", keyPath)
	if err != nil {
		t.Fatalf("NewSystemClient: %v", err)
	}
	if err := sc.AddInstanceDomain(context.Background(), "already.example"); err != nil {
		t.Fatalf("AddInstanceDomain on already-exists 400 returned error: %v", err)
	}
}

// TestSystemClient_Unauthorized verifies that a 401 from the System API
// wraps both ErrUnauthorized and ErrPermanent so the controller requeue
// loop doesn't retry indefinitely on a misconfigured key.
func TestSystemClient_Unauthorized(t *testing.T) {
	key := generateTestRSAKey(t)
	keyPath := writeKeyFile(t, key)

	srv := newFakeServer(t, map[string]http.HandlerFunc{
		"POST /system/v1/instances/_search": instanceSearchHandler(),
		"POST /system/v1/instances/372802942115250284/domains": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized","error_description":"invalid key or user"}`))
		},
	})

	sc, err := NewSystemClient(srv.URL, "gibson-system-bot", "", keyPath)
	if err != nil {
		t.Fatalf("NewSystemClient: %v", err)
	}
	err = sc.AddInstanceDomain(context.Background(), "any.domain")
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

// TestSystemClient_ServerError_5xx verifies that a 5xx from the domains
// endpoint surfaces as ErrUnreachable (transient — controller should requeue).
func TestSystemClient_ServerError_5xx(t *testing.T) {
	key := generateTestRSAKey(t)
	keyPath := writeKeyFile(t, key)

	srv := newFakeServer(t, map[string]http.HandlerFunc{
		"POST /system/v1/instances/_search": instanceSearchHandler(),
		"POST /system/v1/instances/372802942115250284/domains": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":"internal server error"}`))
		},
	})

	sc, err := NewSystemClient(srv.URL, "gibson-system-bot", "", keyPath)
	if err != nil {
		t.Fatalf("NewSystemClient: %v", err)
	}
	err = sc.AddInstanceDomain(context.Background(), "any.domain")
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

// TestSystemClient_ListInstanceDomains verifies that ListInstanceDomains
// parses the result array and returns just the domain strings.
func TestSystemClient_ListInstanceDomains(t *testing.T) {
	key := generateTestRSAKey(t)
	keyPath := writeKeyFile(t, key)

	const (
		domain1 = "auth.zeroroot.local"
		domain2 = "gibson-zitadel.gibson.svc.cluster.local"
	)

	srv := newFakeServer(t, map[string]http.HandlerFunc{
		"POST /system/v1/instances/_search": instanceSearchHandler(),
		"POST /system/v1/instances/372802942115250284/domains/_search": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{
				"result": [
					{"domain": %q, "isPrimary": true,  "isVerified": true},
					{"domain": %q, "isPrimary": false, "isVerified": true}
				],
				"details": {"totalResult": "2"}
			}`, domain1, domain2)
		},
	})

	sc, err := NewSystemClient(srv.URL, "gibson-system-bot", "", keyPath)
	if err != nil {
		t.Fatalf("NewSystemClient: %v", err)
	}
	domains, err := sc.ListInstanceDomains(context.Background())
	if err != nil {
		t.Fatalf("ListInstanceDomains: %v", err)
	}
	if len(domains) != 2 {
		t.Fatalf("want 2 domains, got %d: %v", len(domains), domains)
	}
	domainSet := make(map[string]bool, len(domains))
	for _, d := range domains {
		domainSet[d] = true
	}
	for _, want := range []string{domain1, domain2} {
		if !domainSet[want] {
			t.Errorf("domain %q missing from result %v", want, domains)
		}
	}
}

// TestSystemClient_AssertionCaching verifies that the signed JWT is reused
// across multiple calls within its TTL — we don't re-sign on every call.
func TestSystemClient_AssertionCaching(t *testing.T) {
	key := generateTestRSAKey(t)
	keyPath := writeKeyFile(t, key)

	var firstBearer, secondBearer string

	srv := newFakeServer(t, map[string]http.HandlerFunc{
		"POST /system/v1/instances/_search": instanceSearchHandler(),
		"POST /system/v1/instances/372802942115250284/domains": func(w http.ResponseWriter, r *http.Request) {
			if firstBearer == "" {
				firstBearer = bearerFromAuth(r)
			} else {
				secondBearer = bearerFromAuth(r)
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		},
	})

	sc, err := NewSystemClient(srv.URL, "gibson-system-bot", "", keyPath)
	if err != nil {
		t.Fatalf("NewSystemClient: %v", err)
	}

	ctx := context.Background()
	if err := sc.AddInstanceDomain(ctx, "a.example"); err != nil {
		t.Fatalf("first AddInstanceDomain: %v", err)
	}
	if err := sc.AddInstanceDomain(ctx, "b.example"); err != nil {
		t.Fatalf("second AddInstanceDomain: %v", err)
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

// TestSystemClient_ExternalDomain_HostHeader verifies that externalDomain
// is forged onto the Host header for every System API request — Zitadel
// routes by vhost, so cluster-internal Service-name dialing requires the
// Host header to match the registered ExternalDomain.
func TestSystemClient_ExternalDomain_HostHeader(t *testing.T) {
	key := generateTestRSAKey(t)
	keyPath := writeKeyFile(t, key)

	const externalDomain = "auth.zeroroot.local:30443"
	var domainHost string

	srv := newFakeServer(t, map[string]http.HandlerFunc{
		"POST /system/v1/instances/_search": instanceSearchHandler(),
		"POST /system/v1/instances/372802942115250284/domains": func(w http.ResponseWriter, r *http.Request) {
			domainHost = r.Host
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		},
	})

	sc, err := NewSystemClient(srv.URL, "gibson-system-bot", externalDomain, keyPath)
	if err != nil {
		t.Fatalf("NewSystemClient: %v", err)
	}
	if err := sc.AddInstanceDomain(context.Background(), "any.domain"); err != nil {
		t.Fatalf("AddInstanceDomain: %v", err)
	}

	if domainHost != externalDomain {
		t.Errorf("domains request Host = %q, want %q", domainHost, externalDomain)
	}
}
