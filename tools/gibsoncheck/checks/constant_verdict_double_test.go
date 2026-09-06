// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package checks_test

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"github.com/zeroroot-ai/gibson/tools/gibsoncheck/checks"
)

// TestConstantVerdictDouble_Asymmetry is as much a test of what the
// guard does NOT report as of what it does. The denyAll and
// denyAllUnnamed fixtures discard every decision argument, exactly like
// the positives, and differ only in verdict polarity — they must stay
// silent. That asymmetry is what turns a ~50-site candidate population
// into a handful of real findings; without it the guard reports
// fail-closed doubles across the operator and FGA packages and gets
// muted.
//
// This fixture lives in a _test.go file on purpose: the analyzer
// inverts the convention every other check in this binary follows, and
// the package must actually be loaded in its test variant or the guard
// is silently inert.
func TestConstantVerdictDouble_Asymmetry(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), checks.ConstantVerdictDoubleAnalyzer,
		"github.com/zeroroot-ai/gibson/internal/server/admin/constverdict")
}
