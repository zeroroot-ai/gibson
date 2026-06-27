// Copyright 2026 Hack the Planet LLC
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package vault

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
)

func TestVerifyJWTAuthMounted_OK(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/sys/auth/jwt" {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	c, err := New(Config{Address: srv.URL, AdminToken: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.VerifyJWTAuthMounted(context.Background()); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

func TestVerifyJWTAuthMounted_NotFound(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/sys/auth/jwt" {
			// Vault returns 400 "path is not a mount" when the backend is absent.
			http.Error(w, `{"errors":["path is not a mount or is not accessible"]}`, http.StatusBadRequest)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	c, err := New(Config{Address: srv.URL, AdminToken: "t"})
	if err != nil {
		t.Fatal(err)
	}
	err = c.VerifyJWTAuthMounted(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, clients.ErrNotFound) {
		t.Errorf("want ErrNotFound in chain, got %v", err)
	}
	if errors.Is(err, clients.ErrUnauthorized) {
		t.Errorf("must NOT be ErrUnauthorized for absent-backend case")
	}
}

// TestVerifyJWTAuthMounted_Forbidden validates that a 403 is surfaced as
// ErrUnauthorized so cmd/main.go can warn-and-continue instead of exiting.
// tenant-operator#212.
func TestVerifyJWTAuthMounted_Forbidden(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/sys/auth/jwt" {
			http.Error(w, `{"errors":["1 error occurred: permission denied"]}`, http.StatusForbidden)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	c, err := New(Config{Address: srv.URL, AdminToken: "t"})
	if err != nil {
		t.Fatal(err)
	}
	err = c.VerifyJWTAuthMounted(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, clients.ErrUnauthorized) {
		t.Errorf("want ErrUnauthorized in chain for 403, got %v", err)
	}
	if errors.Is(err, clients.ErrNotFound) {
		t.Errorf("must NOT be ErrNotFound for 403 case")
	}
	// A bare "permission denied" (no expiry/lease/ttl vocabulary) is a genuine
	// capability/credential problem — it must stay permanent, i.e. NOT carry
	// ErrTokenExpired (tenant-operator#273).
	if errors.Is(err, ErrTokenExpired) {
		t.Errorf("bare permission-denied must NOT be classified ErrTokenExpired, got %v", err)
	}
}

// TestForbidden_TokenExpiry_IsTransient validates that a 403 whose body carries
// token-expiry vocabulary is additionally tagged ErrTokenExpired (while still
// matching ErrUnauthorized) so the provisioning saga keeps retrying rather than
// blocking the tenant. tenant-operator#273.
func TestForbidden_TokenExpiry_IsTransient(t *testing.T) {
	t.Parallel()

	// Bodies Vault/OpenBao emit when the *token itself* is expired/invalid,
	// as opposed to a valid token lacking a capability.
	expiryBodies := []string{
		`{"errors":["permission denied: token is expired"]}`,
		`{"errors":["token is not renewable"]}`,
		`{"errors":["invalid token"]}`,
		`{"errors":["1 error occurred: lease is expired"]}`,
		`{"errors":["token not found"]}`,
		`{"errors":["failed to find accessor entry for token"]}`,
	}

	for _, body := range expiryBodies {
		t.Run(body, func(t *testing.T) {
			t.Parallel()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/sys/auth/jwt" {
					http.Error(w, body, http.StatusForbidden)
					return
				}
				http.NotFound(w, r)
			}))
			defer srv.Close()

			c, err := New(Config{Address: srv.URL, AdminToken: "t"})
			if err != nil {
				t.Fatal(err)
			}
			err = c.VerifyJWTAuthMounted(context.Background())
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			// Still classified as ErrUnauthorized for back-compat with callers
			// that only test that sentinel.
			if !errors.Is(err, clients.ErrUnauthorized) {
				t.Errorf("want ErrUnauthorized in chain, got %v", err)
			}
			// AND additionally tagged transient.
			if !errors.Is(err, ErrTokenExpired) {
				t.Errorf("want ErrTokenExpired for token-expiry body %q, got %v", body, err)
			}
		})
	}
}

func TestLooksLikeTokenExpiry(t *testing.T) {
	t.Parallel()
	cases := []struct {
		msg  string
		want bool
	}{
		{"permission denied", false},
		{"1 error occurred: permission denied", false},
		{"403 Forbidden", false},
		{"token is expired", true},
		{"Token Expired", true}, // case-insensitive
		{"token is not renewable", true},
		{"invalid token", true},
		{"lease is expired", true},
		{"ttl expired", true},
		{"token not found", true},
		{"failed to find accessor", true},
	}
	for _, tc := range cases {
		if got := looksLikeTokenExpiry(tc.msg); got != tc.want {
			t.Errorf("looksLikeTokenExpiry(%q) = %v, want %v", tc.msg, got, tc.want)
		}
	}
}
