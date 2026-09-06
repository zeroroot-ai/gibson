// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package vault

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestEnsureTransitMounted_SkipsWhenPresent proves the check-before-enable: no
// enable POST when sys/mounts already lists transit/, one when it is absent.
func TestEnsureTransitMounted_SkipsWhenPresent(t *testing.T) {
	for _, tc := range []struct {
		name      string
		present   bool
		wantPosts int
	}{
		{"already mounted → no enable POST", true, 0},
		{"absent → one enable POST", false, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var posts int
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == http.MethodGet && r.URL.Path == "/v1/sys/mounts":
					w.Header().Set("Content-Type", "application/json")
					if tc.present {
						_, _ = w.Write([]byte(`{"data":{"transit/":{"type":"transit"}}}`))
					} else {
						_, _ = w.Write([]byte(`{"data":{}}`))
					}
				case r.Method == http.MethodPost && r.URL.Path == "/v1/sys/mounts/transit":
					posts++
					w.WriteHeader(http.StatusNoContent)
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer srv.Close()

			c, err := New(srv.URL, func() (string, error) { return "x", nil })
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if err := c.EnsureTransitMounted(context.Background()); err != nil {
				t.Fatalf("EnsureTransitMounted: %v", err)
			}
			if posts != tc.wantPosts {
				t.Errorf("enable POSTs = %d, want %d", posts, tc.wantPosts)
			}
		})
	}
}
