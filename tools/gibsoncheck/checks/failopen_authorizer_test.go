// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package checks_test

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"github.com/zeroroot-ai/gibson/tools/gibsoncheck/checks"
)

// TestFailOpenAuthorizer_Shapes covers both AST shapes and — as much as
// it covers the shapes — the NEAR-MISS NEGATIVES that a naive version
// of this rule reports as defects: a (bool, error) helper that denies
// with `false, nil`, an empty response literal, a `!= nil` block whose
// only error return is inside a closure, and a plain value nil-guard on
// a non-security type.
//
// Those negatives are the guard's real contract. If someone later
// relaxes the TYPE gate or the RETURN-POLARITY model "to catch more",
// this test goes red instead of the repository filling with reports of
// fail-CLOSED code.
func TestFailOpenAuthorizer_Shapes(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), checks.FailOpenAuthorizerAnalyzer, "github.com/zeroroot-ai/gibson/internal/server/daemon/api/failopen")
}

// TestFailOpenAuthorizer_SuppressionIntegrity proves the escape hatch
// is not an escape hatch. A bare directive, a guard symbol that does
// not resolve, a guard that is named but never runs before the
// permissive branch, a missing/expired/over-horizon expiry — each is
// its own diagnostic, and none of them silences the finding.
func TestFailOpenAuthorizer_SuppressionIntegrity(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), checks.FailOpenAuthorizerAnalyzer, "github.com/zeroroot-ai/gibson/internal/server/daemon/api/failopensuppress")
}
