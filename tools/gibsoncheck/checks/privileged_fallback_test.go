// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package checks_test

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"github.com/zeroroot-ai/gibson/tools/gibsoncheck/checks"
)

const privFallbackBase = "github.com/zeroroot-ai/gibson/internal/server/daemon/"

// TestPrivilegedFallback_Shapes covers G1 and G3 plus the two evasions
// the rule must not be defeated by (literal concatenation of the
// sentinel slug; an innocuous helper name with an inverted condition),
// and the FAIL-CLOSED CANARY — a failure branch that mentions a
// sentinel only inside its denial message must stay silent.
func TestPrivilegedFallback_Shapes(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), checks.PrivilegedFallbackAnalyzer,
		privFallbackBase+"privfallback")
}

// TestPrivilegedFallback_FactPropagation is the G2 arm. The caller
// package contains no G1 shape of its own, so the diagnostic there can
// only come from the exported analysis.Fact. If this test goes silent,
// FactTypes is not wired and the guard has degraded to catching
// definitions but not the call sites that consume them.
func TestPrivilegedFallback_FactPropagation(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), checks.PrivilegedFallbackAnalyzer,
		privFallbackBase+"privfallbackcaller")
}

// TestPrivilegedFallback_SuppressionIntegrity proves a bare marker and
// an unresolvable guard symbol each produce their own diagnostic ON TOP
// of the finding they tried to silence.
func TestPrivilegedFallback_SuppressionIntegrity(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), checks.PrivilegedFallbackAnalyzer,
		privFallbackBase+"privfallbacksuppress")
}
