package checks_test

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"github.com/zero-day-ai/gibson/tools/gibsoncheck/checks"
)

// TestForbidRedisClientConstruction_Violation verifies that a package outside the
// allowlist that calls redis.NewClient directly triggers a diagnostic.
func TestForbidRedisClientConstruction_Violation(t *testing.T) {
	testdata := analysistest.TestData()
	analysistest.Run(t, testdata, checks.ForbidRedisClientConstructionAnalyzer,
		"github.com/zero-day-ai/gibson/internal/redisclientviolation")
}

// TestForbidRedisClientConstruction_TestFileExempt verifies that a _test.go file
// calling redis.NewClient (e.g. against miniredis) does NOT trigger a diagnostic.
func TestForbidRedisClientConstruction_TestFileExempt(t *testing.T) {
	testdata := analysistest.TestData()
	// The fixture has no // want comments, so zero diagnostics are expected.
	analysistest.Run(t, testdata, checks.ForbidRedisClientConstructionAnalyzer,
		"github.com/zero-day-ai/gibson/internal/redisclientallowed")
}
