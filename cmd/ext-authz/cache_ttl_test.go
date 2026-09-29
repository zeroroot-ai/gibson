// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/server/extauthz/fga"
)

// TestFGACacheSettings: with no override the live TTL IS the package default,
// so a change of fga.DefaultCacheTTL changes what runs (hosted#204). The env
// overrides work, and a non-positive one falls back to the default.
func TestFGACacheSettings(t *testing.T) {
	t.Setenv("EXT_AUTHZ_FGA_CACHE_TTL", "")
	t.Setenv("EXT_AUTHZ_FGA_CACHE_MAX_SIZE", "")
	ttl, maxSize := fgaCacheSettings()
	if ttl != fga.DefaultCacheTTL {
		t.Fatalf("ttl = %s, want the package default %s", ttl, fga.DefaultCacheTTL)
	}
	if fga.DefaultCacheTTL != 5*time.Second {
		t.Fatalf("fga.DefaultCacheTTL = %s, want 5s, the bound the identity exit test measures", fga.DefaultCacheTTL)
	}
	if maxSize != defaultFGACacheMaxSize {
		t.Fatalf("maxSize = %d, want %d", maxSize, defaultFGACacheMaxSize)
	}

	t.Setenv("EXT_AUTHZ_FGA_CACHE_TTL", "7s")
	t.Setenv("EXT_AUTHZ_FGA_CACHE_MAX_SIZE", "42")
	ttl, maxSize = fgaCacheSettings()
	if ttl != 7*time.Second || maxSize != 42 {
		t.Fatalf("overrides = %s/%d, want 7s/42", ttl, maxSize)
	}

	t.Setenv("EXT_AUTHZ_FGA_CACHE_TTL", "0s")
	t.Setenv("EXT_AUTHZ_FGA_CACHE_MAX_SIZE", "0")
	ttl, maxSize = fgaCacheSettings()
	if ttl != fga.DefaultCacheTTL || maxSize != defaultFGACacheMaxSize {
		t.Fatalf("non-positive overrides = %s/%d, want the defaults", ttl, maxSize)
	}
}
