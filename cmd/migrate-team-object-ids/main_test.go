// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"log/slog"
	"strings"
	"testing"
)

// TestFGAConfigFromEnv_RequiresEveryField pins the fail-closed read of the FGA
// configuration. A missing store or model id must stop the binary, not produce
// a client pointed at a default: this tool deletes tuples, and running it
// against the wrong store is not recoverable.
func TestFGAConfigFromEnv_RequiresEveryField(t *testing.T) {
	all := map[string]string{
		"EXT_AUTHZ_FGA_ADDR":     "http://fga:8080",
		"EXT_AUTHZ_FGA_STORE_ID": "store-1",
		"EXT_AUTHZ_FGA_MODEL_ID": "model-1",
	}

	for missing := range all {
		t.Run("missing "+missing, func(t *testing.T) {
			for k, v := range all {
				if k == missing {
					t.Setenv(k, "")
					continue
				}
				t.Setenv(k, v)
			}
			_, err := fgaConfigFromEnv(slog.Default())
			if err == nil {
				t.Fatalf("fgaConfigFromEnv succeeded with %s unset", missing)
			}
			if !strings.Contains(err.Error(), missing) {
				t.Errorf("error %q does not name the missing variable %s", err, missing)
			}
		})
	}
}

// TestFGAConfigFromEnv_PassesTheEnvironmentThrough is the positive control: a
// validator that rejected everything would make the cases above pass for the
// wrong reason.
func TestFGAConfigFromEnv_PassesTheEnvironmentThrough(t *testing.T) {
	t.Setenv("EXT_AUTHZ_FGA_ADDR", "http://fga:8080")
	t.Setenv("EXT_AUTHZ_FGA_STORE_ID", "store-1")
	t.Setenv("EXT_AUTHZ_FGA_MODEL_ID", "model-1")

	cfg, err := fgaConfigFromEnv(slog.Default())
	if err != nil {
		t.Fatalf("fgaConfigFromEnv: %v", err)
	}
	if cfg.Endpoint != "http://fga:8080" || cfg.StoreID != "store-1" || cfg.ModelID != "model-1" {
		t.Errorf("cfg = %+v, want the three environment values verbatim", cfg)
	}
	if cfg.TimeoutMs <= 0 {
		t.Errorf("TimeoutMs = %d, want a positive per-call timeout", cfg.TimeoutMs)
	}
}
