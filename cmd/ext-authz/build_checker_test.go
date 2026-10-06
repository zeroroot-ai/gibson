// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/server/extauthz/fga"
)

const buildCheckerRegistryYAML = `entries:
  "/test.v1.S/Public":
    unauthenticated: true
`

// No start text names the platform-clients module. That module does not
// exist. Its code is internal/infra (ADR-0056, gibson#997).
const removedModuleName = "platform-clients"

func buildCheckerRegistry(t *testing.T) *fga.Registry {
	t.Helper()
	reg, err := fga.LoadRegistry([]byte(buildCheckerRegistryYAML))
	if err != nil {
		t.Fatalf("load registry: %v", err)
	}
	return reg
}

// TestBuildChecker_RefusesAMissingSetting: each missing FGA setting stops the
// start with an error that names the setting.
func TestBuildChecker_RefusesAMissingSetting(t *testing.T) {
	cases := []struct {
		name, addr, store, model, want string
	}{
		{"no address", "", "store", "model", "EXT_AUTHZ_FGA_ADDR"},
		{"no store", "openfga:8080", "", "model", "EXT_AUTHZ_FGA_STORE_ID"},
		{"no model", "openfga:8080", "store", "", "EXT_AUTHZ_FGA_MODEL_ID"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("EXT_AUTHZ_FGA_ADDR", tc.addr)
			t.Setenv("EXT_AUTHZ_FGA_STORE_ID", tc.store)
			t.Setenv("EXT_AUTHZ_FGA_MODEL_ID", tc.model)
			_, _, err := buildChecker(context.Background(), slog.New(slog.DiscardHandler), buildCheckerRegistry(t))
			if err == nil {
				t.Fatal("buildChecker returned no error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not name %s", err, tc.want)
			}
			if strings.Contains(err.Error(), removedModuleName) {
				t.Fatalf("error %q names the removed module", err)
			}
		})
	}
}

// TestBuildChecker_RefusesABadTimeout: a per-call timeout at or above the
// Envoy budget makes the client constructor fail, and the start stops.
func TestBuildChecker_RefusesABadTimeout(t *testing.T) {
	t.Setenv("EXT_AUTHZ_FGA_ADDR", "openfga:8080")
	t.Setenv("EXT_AUTHZ_FGA_STORE_ID", "01ARZ3NDEKTSV4RRFFQ69G5FAV")
	t.Setenv("EXT_AUTHZ_FGA_MODEL_ID", "01ARZ3NDEKTSV4RRFFQ69G5FAW")
	t.Setenv("EXT_AUTHZ_FGA_PER_CALL_TIMEOUT", "10s")
	_, _, err := buildChecker(context.Background(), slog.New(slog.DiscardHandler), buildCheckerRegistry(t))
	if err == nil {
		t.Fatal("buildChecker accepted a timeout above the Envoy budget")
	}
	if !strings.Contains(err.Error(), "internal/infra/authz") || strings.Contains(err.Error(), removedModuleName) {
		t.Fatalf("error %q must name internal/infra/authz and not the removed module", err)
	}
}

// TestBuildChecker_SelfCheck: the self-check reaches a fake OpenFGA. When it
// answers, the start logs success. When it fails, the start stops.
func TestBuildChecker_SelfCheck(t *testing.T) {
	t.Run("passes", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !strings.HasSuffix(r.URL.Path, "/check") {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"allowed":false}`))
		}))
		t.Cleanup(srv.Close)

		t.Setenv("EXT_AUTHZ_FGA_ADDR", srv.URL)
		t.Setenv("EXT_AUTHZ_FGA_STORE_ID", "01ARZ3NDEKTSV4RRFFQ69G5FAV")
		t.Setenv("EXT_AUTHZ_FGA_MODEL_ID", "01ARZ3NDEKTSV4RRFFQ69G5FAW")
		t.Setenv("EXT_AUTHZ_FGA_PER_CALL_TIMEOUT", "")

		var logs bytes.Buffer
		log := slog.New(slog.NewTextHandler(&logs, nil))
		checker, client, err := buildChecker(context.Background(), log, buildCheckerRegistry(t))
		if err != nil {
			t.Fatalf("buildChecker: %v", err)
		}
		if checker == nil || client == nil {
			t.Fatal("buildChecker returned a nil checker or client")
		}
		out := logs.String()
		if !strings.Contains(out, "OpenFGA client (internal/infra/authz) connected and self-check passed") {
			t.Fatalf("no success log in %q", out)
		}
		if strings.Contains(out, removedModuleName) {
			t.Fatalf("log %q names the removed module", out)
		}
	})

	t.Run("fails", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, `{"code":"store_id_not_found"}`, http.StatusNotFound)
		}))
		t.Cleanup(srv.Close)

		t.Setenv("EXT_AUTHZ_FGA_ADDR", srv.URL)
		t.Setenv("EXT_AUTHZ_FGA_STORE_ID", "01ARZ3NDEKTSV4RRFFQ69G5FAV")
		t.Setenv("EXT_AUTHZ_FGA_MODEL_ID", "01ARZ3NDEKTSV4RRFFQ69G5FAW")
		t.Setenv("EXT_AUTHZ_FGA_PER_CALL_TIMEOUT", "")

		_, _, err := buildChecker(context.Background(), slog.New(slog.DiscardHandler), buildCheckerRegistry(t))
		if err == nil {
			t.Fatal("buildChecker accepted a failed self-check")
		}
		if !strings.Contains(err.Error(), "self-check") {
			t.Fatalf("error %q does not name the self-check", err)
		}
	})
}
