package checks_test

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"github.com/zeroroot-ai/gibson/tools/gibsoncheck/checks"
)

// TestSecretsNoLog_Violation verifies that a secrets-package function that
// passes a Get/Resolve return value directly to a logging sink is flagged.
func TestSecretsNoLog_Violation(t *testing.T) {
	testdata := analysistest.TestData()
	analysistest.Run(t, testdata, checks.SecretsNoLogAnalyzer,
		"github.com/zeroroot-ai/gibson/internal/infra/secrets/secretslogviolation")
}

// TestSecretsNoLog_Clean verifies that a secrets-package function that uses
// the Get/Resolve return value for legitimate purposes (e.g. HMAC) without
// logging does NOT trigger any diagnostic.
func TestSecretsNoLog_Clean(t *testing.T) {
	testdata := analysistest.TestData()
	// No // want comments in the clean fixture — zero diagnostics expected.
	analysistest.Run(t, testdata, checks.SecretsNoLogAnalyzer,
		"github.com/zeroroot-ai/gibson/internal/infra/secrets/secretslogclean")
}
