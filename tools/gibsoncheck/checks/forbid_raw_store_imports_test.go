package checks_test

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"github.com/zero-day-ai/gibson/tools/gibsoncheck/checks"
)

// TestForbidRawStoreImports_Violation verifies that a handler package outside
// the data-plane allowlist that imports pgx or go-redis triggers diagnostics.
func TestForbidRawStoreImports_Violation(t *testing.T) {
	testdata := analysistest.TestData()
	analysistest.Run(t, testdata, checks.ForbidRawStoreImportsAnalyzer,
		"github.com/zero-day-ai/gibson/internal/rawstoreviolation")
}

// TestForbidRawStoreImports_TestFileMiniredis verifies that a _test.go file
// importing miniredis (a legitimate fixture server) does NOT trigger a
// diagnostic even when the package is outside the allowlist.
func TestForbidRawStoreImports_TestFileMiniredis(t *testing.T) {
	testdata := analysistest.TestData()
	// analysistest.Run returns the diagnostics; passing the allowed package
	// should produce zero diagnostics (no // want comments in the fixture).
	analysistest.Run(t, testdata, checks.ForbidRawStoreImportsAnalyzer,
		"github.com/zero-day-ai/gibson/internal/rawstoreallowed")
}
