package checks_test

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"github.com/zeroroot-ai/gibson/tools/gibsoncheck/checks"
)

// TestForbidRedisKeyPrefix_Violation verifies that a package outside the
// allowlist that uses tenant-prefix patterns in Redis calls triggers
// diagnostics.
func TestForbidRedisKeyPrefix_Violation(t *testing.T) {
	testdata := analysistest.TestData()
	analysistest.Run(t, testdata, checks.ForbidRedisKeyPrefixAnalyzer,
		"github.com/zeroroot-ai/gibson/internal/redisprefixviolation")
}

// TestForbidRedisKeyPrefix_PlainKeys verifies that a package using plain
// (non-tenant-prefixed) Redis keys produces no diagnostics.
func TestForbidRedisKeyPrefix_PlainKeys(t *testing.T) {
	testdata := analysistest.TestData()
	analysistest.Run(t, testdata, checks.ForbidRedisKeyPrefixAnalyzer,
		"github.com/zeroroot-ai/gibson/internal/redisprefixallowed")
}
