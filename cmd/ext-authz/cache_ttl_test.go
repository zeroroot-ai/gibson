// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/server/extauthz/fga"
)

// TestFGACacheTTL: with no override the live TTL IS the package default,
// so a change of fga.DefaultCacheTTL changes what runs (hosted#204). The env
// override still works.
func TestFGACacheTTL(t *testing.T) {
	t.Setenv("EXT_AUTHZ_FGA_CACHE_TTL", "")
	if got := fgaCacheTTL(); got != fga.DefaultCacheTTL {
		t.Fatalf("fgaCacheTTL() = %s, want the package default %s", got, fga.DefaultCacheTTL)
	}
	if fga.DefaultCacheTTL != 5*time.Second {
		t.Fatalf("fga.DefaultCacheTTL = %s, want 5s, the bound the identity exit test measures", fga.DefaultCacheTTL)
	}
	t.Setenv("EXT_AUTHZ_FGA_CACHE_TTL", "7s")
	if got := fgaCacheTTL(); got != 7*time.Second {
		t.Fatalf("fgaCacheTTL() with an override = %s, want 7s", got)
	}
}
