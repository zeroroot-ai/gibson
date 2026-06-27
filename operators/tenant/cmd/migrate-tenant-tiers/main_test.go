// Copyright 2026 Hack the Planet LLC
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package main

import (
	"testing"

	tiermigrate "github.com/zeroroot-ai/gibson/operators/tenant/internal/backfill/tiermigrate"
)

// As of Phase 5.3 of deploy-architecture-refactor the legacy tier map
// lives in internal/backfill/tiermigrate (exported as LegacyTierMap)
// and is consumed by both the standalone CLI and the operator's
// startup runnable. Tests target the exported map.

func TestLegacyTierMap_Coverage(t *testing.T) {
	wantTargets := map[string]string{
		"solo":              "team",
		"squad":             "team",
		"platform":          "enterprise",
		"enterprise-cloud":  "enterprise",
		"enterprise-onprem": "enterprise-deploy",
		"public-sector":     "enterprise-deploy",
		"free":              "team",
		"pro":               "enterprise",
	}
	for from, want := range wantTargets {
		got, ok := tiermigrate.LegacyTierMap[from]
		if !ok {
			t.Errorf("LegacyTierMap missing entry for %q", from)
			continue
		}
		if got != want {
			t.Errorf("LegacyTierMap[%q]: got %q, want %q", from, got, want)
		}
	}
}

func TestLegacyTierMap_NewIdsAreNoOps(t *testing.T) {
	canonical := []string{"team", "org", "enterprise", "enterprise-deploy"}
	for _, id := range canonical {
		if _, ok := tiermigrate.LegacyTierMap[id]; ok {
			t.Errorf("LegacyTierMap should not contain canonical id %q", id)
		}
	}
}

func TestLegacyTierMap_NoCycles(t *testing.T) {
	canonical := map[string]struct{}{
		"team":              {},
		"org":               {},
		"enterprise":        {},
		"enterprise-deploy": {},
	}
	for from, to := range tiermigrate.LegacyTierMap {
		if _, ok := canonical[to]; !ok {
			t.Errorf("LegacyTierMap[%q] = %q is not a canonical id", from, to)
		}
	}
}
