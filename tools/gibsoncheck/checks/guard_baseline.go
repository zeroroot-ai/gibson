// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package checks

import (
	_ "embed"
	"fmt"
	"os"
	"strings"
	"sync"
)

// guardBaselineRaw is the committed inventory of security-guard
// findings that predate the guards themselves. It is a SHRINK-ONLY
// ratchet — see the file header for the contract, and
// scripts/check-guard-baselines.sh for the stale-entry half of it.
//
//go:embed guard_baseline.txt
var guardBaselineRaw string

// guardBaselineKey identifies a finding independently of its position
// in the file, so reformatting or unrelated edits above it do not churn
// the baseline, and so MOVING a violation does not silently un-baseline
// it. Format: <rule>|<package path>|<symbol>.
func guardBaselineKey(rule, pkgPath, symbol string) string {
	return fmt.Sprintf("%s|%s|%s", rule, pkgPath, symbol)
}

var (
	guardBaselineOnce sync.Once
	guardBaselineSet  map[string]struct{}
)

func guardBaseline() map[string]struct{} {
	guardBaselineOnce.Do(func() {
		guardBaselineSet = make(map[string]struct{})
		for _, line := range strings.Split(guardBaselineRaw, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			guardBaselineSet[line] = struct{}{}
		}
	})
	return guardBaselineSet
}

// guardBaselineDisabled reports whether baseline suppression is off.
// scripts/check-guard-baselines.sh sets GIBSON_GUARD_BASELINE=off to
// get the unsuppressed finding set, which is how STALE entries — ones
// whose site is fixed or gone — are detected and hard-failed. Without
// that half, a baseline silently retains dead entries and stops
// shrinking.
func guardBaselineDisabled() bool {
	return strings.EqualFold(os.Getenv("GIBSON_GUARD_BASELINE"), "off")
}

// baselined reports whether this finding is a known, tracked violation
// that predates the guard. New findings are never baselined, so they
// fail the build from the moment the guard lands.
func baselined(rule, pkgPath, symbol string) bool {
	if guardBaselineDisabled() {
		return false
	}
	_, ok := guardBaseline()[guardBaselineKey(rule, pkgPath, symbol)]
	return ok
}
