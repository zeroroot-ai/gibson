// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package authz

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func probeServer(t *testing.T, statusCode int, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		_, _ = w.Write([]byte(body))
	}))
}

// TestProbe_FailsOnAnyError proves that a bad token and a wrong store ID fail the
// probe. Before, only an outage did, so a broken daemon started and was Ready.
func TestProbe_FailsOnAnyError(t *testing.T) {
	cases := map[string]struct {
		status int
		body   string
	}{
		"bad token":      {http.StatusUnauthorized, `{"code":"auth_failed","message":"bad token"}`},
		"forbidden":      {http.StatusForbidden, `{"code":"forbidden","message":"no"}`},
		"wrong store id": {http.StatusNotFound, `{"code":"store_id_not_found","message":"no store"}`},
		"outage":         {http.StatusServiceUnavailable, `{"code":"unavailable","message":"down"}`},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			srv := probeServer(t, tc.status, tc.body)
			defer srv.Close()
			if err := Probe(context.Background(), newTestFgaAuthorizer(t, srv.URL)); err == nil {
				t.Fatalf("status %d: the probe must fail", tc.status)
			}
		})
	}
}

// A deny is an answer, so it passes the probe.
func TestProbe_PassesOnADeny(t *testing.T) {
	srv := probeServer(t, http.StatusOK, `{"allowed":false}`)
	defer srv.Close()
	if err := Probe(context.Background(), newTestFgaAuthorizer(t, srv.URL)); err != nil {
		t.Fatalf("a deny must pass the probe: %v", err)
	}
}
