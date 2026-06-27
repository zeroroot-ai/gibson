// Copyright 2026 Hack the Planet LLC
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package vault

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
)

// fakeJWTConfigVault is a minimal fake that only handles /v1/auth/jwt/config
// writes, recording the body and namespace header so the test can assert
// the request shape.
type fakeJWTConfigVault struct {
	mu     sync.Mutex
	writes []jwtConfigWrite
}

type jwtConfigWrite struct {
	Namespace string
	Body      map[string]any
}

func (f *fakeJWTConfigVault) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/jwt/config", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		f.writes = append(f.writes, jwtConfigWrite{
			Namespace: r.Header.Get("X-Vault-Namespace"),
			Body:      body,
		})
		f.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}

// TestConfigureTenantJWTAuth_WritesMirroredConfig verifies the operator
// writes the per-tenant auth/jwt/config with bound_issuer + jwks_url +
// jwks_ca_pem mirroring the root namespace's config, under the per-tenant
// namespace header tenant-<id>. tenant-operator#189.
func TestConfigureTenantJWTAuth_WritesMirroredConfig(t *testing.T) {
	t.Parallel()
	fv := &fakeJWTConfigVault{}
	srv := httptest.NewServer(fv.handler())
	defer srv.Close()

	const (
		issuer  = "https://gibson-spire-spiffe-oidc-discovery-provider"
		jwksURL = "https://gibson-spire-spiffe-oidc-discovery-provider/keys"
		caPEM   = "-----BEGIN CERTIFICATE-----\nMIIBkzCCATWgAwIBAgIJALmock=\n-----END CERTIFICATE-----\n"
	)

	c, err := New(Config{
		Address:          srv.URL,
		AdminToken:       "t",
		JWTBoundAudience: "gibson-saas",
		JWTBoundIssuer:   issuer,
		JWKSURL:          jwksURL,
		JWKSCAPEM:        caPEM,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := c.ConfigureTenantJWTAuth(context.Background(), "abcd"); err != nil {
		t.Fatalf("ConfigureTenantJWTAuth: %v", err)
	}

	fv.mu.Lock()
	defer fv.mu.Unlock()
	if len(fv.writes) != 1 {
		t.Fatalf("want 1 write, got %d", len(fv.writes))
	}
	got := fv.writes[0]
	if got.Namespace != "tenant-abcd" {
		t.Errorf("X-Vault-Namespace = %q, want %q", got.Namespace, "tenant-abcd")
	}
	if got.Body["bound_issuer"] != issuer {
		t.Errorf("bound_issuer = %v, want %v", got.Body["bound_issuer"], issuer)
	}
	if got.Body["jwks_url"] != jwksURL {
		t.Errorf("jwks_url = %v, want %v", got.Body["jwks_url"], jwksURL)
	}
	if got.Body["jwks_ca_pem"] != caPEM {
		t.Errorf("jwks_ca_pem mismatch (got %q)", got.Body["jwks_ca_pem"])
	}
}

// TestConfigureTenantJWTAuth_Idempotent verifies a second call against an
// already-configured tenant succeeds (POST overwrite is the idempotency
// shape Vault provides). The recorded byte-for-byte writes must match.
func TestConfigureTenantJWTAuth_Idempotent(t *testing.T) {
	t.Parallel()
	fv := &fakeJWTConfigVault{}
	srv := httptest.NewServer(fv.handler())
	defer srv.Close()

	c, err := New(Config{
		Address:        srv.URL,
		AdminToken:     "t",
		JWTBoundIssuer: "https://issuer.example",
		JWKSURL:        "https://issuer.example/keys",
		JWKSCAPEM:      "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	for i := range 3 {
		if err := c.ConfigureTenantJWTAuth(ctx, "tenantx"); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	fv.mu.Lock()
	defer fv.mu.Unlock()
	if len(fv.writes) != 3 {
		t.Fatalf("want 3 writes, got %d", len(fv.writes))
	}
	first := fv.writes[0]
	for i := 1; i < 3; i++ {
		if fv.writes[i].Namespace != first.Namespace {
			t.Errorf("call %d namespace drift: %q vs %q", i, fv.writes[i].Namespace, first.Namespace)
		}
		if fv.writes[i].Body["bound_issuer"] != first.Body["bound_issuer"] {
			t.Errorf("call %d bound_issuer drift", i)
		}
	}
}

// TestConfigureTenantJWTAuth_RequiresBoundIssuer verifies the operator
// fails LOUDLY rather than writing a degraded config when JWTBoundIssuer
// is unset. Tracks feedback_no_skippable_steps_for_required_artifacts.
func TestConfigureTenantJWTAuth_RequiresBoundIssuer(t *testing.T) {
	t.Parallel()
	fv := &fakeJWTConfigVault{}
	srv := httptest.NewServer(fv.handler())
	defer srv.Close()

	c, err := New(Config{Address: srv.URL, AdminToken: "t"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	err = c.ConfigureTenantJWTAuth(context.Background(), "abcd")
	if err == nil {
		t.Fatal("expected error when JWTBoundIssuer is empty, got nil")
	}
	if !errors.Is(err, clients.ErrInvalidInput) {
		t.Errorf("expected ErrInvalidInput, got %v", err)
	}
	if !strings.Contains(err.Error(), "JWTBoundIssuer") {
		t.Errorf("expected error mentioning JWTBoundIssuer, got %q", err.Error())
	}
}

// TestConfigureTenantJWTAuth_DefaultsJWKSURL verifies that when JWKSURL is
// empty, the operator derives it as <issuer>/keys to match the chart Job's
// default. Saves operators from setting both env vars in lock-step.
func TestConfigureTenantJWTAuth_DefaultsJWKSURL(t *testing.T) {
	t.Parallel()
	fv := &fakeJWTConfigVault{}
	srv := httptest.NewServer(fv.handler())
	defer srv.Close()

	c, err := New(Config{
		Address:        srv.URL,
		AdminToken:     "t",
		JWTBoundIssuer: "https://issuer.example",
		// JWKSURL intentionally empty.
		JWKSCAPEM: "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := c.ConfigureTenantJWTAuth(context.Background(), "abcd"); err != nil {
		t.Fatalf("ConfigureTenantJWTAuth: %v", err)
	}
	fv.mu.Lock()
	defer fv.mu.Unlock()
	got := fv.writes[0].Body["jwks_url"]
	if got != "https://issuer.example/keys" {
		t.Errorf("jwks_url default = %v, want https://issuer.example/keys", got)
	}
}

// TestConfigureTenantJWTAuth_RequiresCAPEMForHTTPSJWKS verifies the
// operator refuses to write an HTTPS JWKS URL without a CA PEM — Vault
// would fall back to the system trust store, which in-cluster doesn't
// have the SPIRE-issued cert, and the breakage shows up only at the
// daemon's first login attempt minutes later. tenant-operator#189.
func TestConfigureTenantJWTAuth_RequiresCAPEMForHTTPSJWKS(t *testing.T) {
	t.Parallel()
	fv := &fakeJWTConfigVault{}
	srv := httptest.NewServer(fv.handler())
	defer srv.Close()

	c, err := New(Config{
		Address:        srv.URL,
		AdminToken:     "t",
		JWTBoundIssuer: "https://issuer.example",
		JWKSURL:        "https://issuer.example/keys",
		// JWKSCAPEM intentionally empty.
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	err = c.ConfigureTenantJWTAuth(context.Background(), "abcd")
	if err == nil {
		t.Fatal("expected error when CA PEM missing for HTTPS JWKS, got nil")
	}
	if !errors.Is(err, clients.ErrInvalidInput) {
		t.Errorf("expected ErrInvalidInput, got %v", err)
	}
}
