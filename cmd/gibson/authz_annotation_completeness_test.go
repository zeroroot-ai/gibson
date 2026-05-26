/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package main

import (
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/authz/registry"
)

// TestAuthzAnnotationCompleteness asserts that every Entry in the
// generated authz registry has a non-empty Relation + ObjectType. This
// catches the failure mode where a proto's `option (gibson.auth.v1.authz)`
// annotation is missing or incompletely filled in — the generator emits
// an Entry with empty strings, and the daemon's authz Check at runtime
// would dispatch against an empty relation (FGA returns deny-all, every
// request fails with cryptic permission_denied).
//
// Cross-checking against `internal/authz/model.fga` (the OpenFGA model)
// would catch a related but deeper drift: a Relation referenced by an
// annotation but not declared in the FGA model. That cross-check is the
// next-iteration version of this test (deferred — the FGA model parser
// needs `go-fga` or a hand-rolled parser; out of scope for v1).
//
// Slice 3.7 of the production-readiness epic (gibson#182 → gibson#173).
//
// What this test catches today:
//   - Missing Relation on an authenticated RPC entry
//   - Missing ObjectType on an FGA-relation entry
//   - Missing ObjectDeriver when Self=false (Self=true skips FGA Check
//     entirely so the deriver isn't required)
//   - Empty Method (registry-gen bug; should never happen but cheap to check)
//
// What this test does NOT catch (deferred to v2):
//   - Relation referenced but not defined in model.fga
//   - ObjectType referenced but not defined in model.fga
//   - Identity class set wrong (e.g. requires Service but route is dashboard-only)
func TestAuthzAnnotationCompleteness(t *testing.T) {
	_, thisFile, _, _ := runtime.Caller(0)
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..")
	// Verify the registry source file exists (sanity)
	if _, err := os.Stat(filepath.Join(repoRoot, "internal", "authz", "registry", "registry.go")); err != nil {
		t.Fatalf("registry.go not found: %v", err)
	}

	var missing []string
	keys := make([]string, 0, len(registry.Registry))
	for k := range registry.Registry {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, method := range keys {
		entry := registry.Registry[method]

		// Method must be non-empty (registry-gen invariant)
		if entry.Method == "" {
			missing = append(missing, method+": empty Method")
		}

		// Unauthenticated entries are exempt — they're public RPCs with
		// no authz dispatch.
		if entry.Unauthenticated {
			continue
		}

		// Self-mode entries skip FGA Check by design — they're the
		// user-reading-own-data shape. The auth context (the authenticated
		// user identity) IS the filter; no Relation / ObjectType / Deriver
		// applies. The registry generator emits empty strings for these
		// fields on Self=true entries.
		if entry.Self {
			continue
		}

		if entry.Relation == "" {
			missing = append(missing, method+": Relation empty (authenticated non-Self RPC must declare a relation)")
		}
		if entry.ObjectType == "" {
			missing = append(missing, method+": ObjectType empty (authenticated non-Self RPC must declare an object_type)")
		}
		if entry.ObjectDeriver == "" {
			missing = append(missing, method+": ObjectDeriver empty (non-Self RPC needs object_deriver)")
		}

		// AllowedIdentities must be non-zero — an RPC that allows no
		// identity class is a deploy mistake.
		if entry.AllowedIdentities == 0 {
			missing = append(missing, method+": AllowedIdentities = 0 (no identity allowed; certainly a misconfig)")
		}
	}

	if len(missing) > 0 {
		t.Errorf("authz annotation completeness failures (%d):\n  %s\n\n"+
			"Each row is a registry entry with an empty required field. The fix:\n"+
			"  (1) Find the proto RPC at internal/daemon/api/gibson/*/v1/*.proto\n"+
			"      whose name appears in the failure list.\n"+
			"  (2) Edit the `option (gibson.auth.v1.authz) = {...};` block to fill\n"+
			"      the missing field (typically relation, object_type, or object_deriver).\n"+
			"  (3) Run `make authz-registry && make proto` to regenerate.\n"+
			"  (4) Commit the proto edit + the regenerated registry artifacts together.\n",
			len(missing),
			strings.Join(missing, "\n  "),
		)
	}
}
