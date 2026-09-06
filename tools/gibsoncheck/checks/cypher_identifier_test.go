// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package checks_test

import (
	"strings"
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"github.com/zeroroot-ai/gibson/tools/gibsoncheck/checks"
)

// TestCypherIdentifier_Violations is the mutation case: three new call
// sites — a raw fmt.Sprintf, a raw string concatenation, and a naked
// cypherFrag(...) conversion — each reach for Cypher-shaped text without
// going through sanitizeIdentifier/cypherf, and MUST be flagged. The same
// fixture package also carries the trusted constructors (trusted.go) and
// legitimate call sites (safe.go), both without `want` comments, so a rule
// that flagged indiscriminately would fail here too.
func TestCypherIdentifier_Violations(t *testing.T) {
	testdata := analysistest.TestData()
	analysistest.Run(t, testdata, checks.CypherIdentifierAnalyzer,
		"github.com/zeroroot-ai/gibson/internal/engine/graphrag")
}

// TestCypherIdentifier_OutOfScopeUnaffected proves the analyzer is scoped to
// exactly the graphrag package: a sibling package with the identical
// fmt.Sprintf violation shape and no `want` comment must produce zero
// diagnostics.
func TestCypherIdentifier_OutOfScopeUnaffected(t *testing.T) {
	testdata := analysistest.TestData()
	analysistest.Run(t, testdata, checks.CypherIdentifierAnalyzer,
		"github.com/zeroroot-ai/gibson/internal/engine/graphrag/other")
}

// TestCypherIdentifier_NoBaseline guards the decision that this analyzer
// ships with no baseline, matching GraphWriteAnalyzer (gibson#1440): the
// local_provider.go refactor that introduced cypherFrag left zero
// violations, and a baseline would only ever accumulate new ones.
func TestCypherIdentifier_NoBaseline(t *testing.T) {
	if checks.CypherIdentifierAnalyzer.Flags.Lookup("baseline") != nil {
		t.Fatal("cypheridentifier must not grow a baseline flag: the tree has zero " +
			"violations, and a baseline would only ever accumulate new ones")
	}
	if !strings.Contains(checks.CypherIdentifierAnalyzer.Doc, "gibson#1440") {
		t.Errorf("cypheridentifier doc must cite the issue it enforces, got %q",
			checks.CypherIdentifierAnalyzer.Doc)
	}
}
