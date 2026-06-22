package checks_test

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"github.com/zeroroot-ai/gibson/tools/gibsoncheck/checks"
)

// TestTenantFromContext_Violation verifies that functions reading
// req.TenantId / request.TenantId without the gibsoncheck:allow
// tenant-from-request opt-out trigger a diagnostic at each read site.
func TestTenantFromContext_Violation(t *testing.T) {
	testdata := analysistest.TestData()
	analysistest.Run(t, testdata, checks.TenantFromContextAnalyzer,
		"github.com/zeroroot-ai/gibson/internal/server/daemon/api/tenantfromctxviolation")
}

// TestTenantFromContext_AllowDirective verifies that functions carrying
// the gibsoncheck:allow tenant-from-request directive in their doc
// comment are exempted from the check — admin RPCs that legitimately
// take a target tenant in the request body, where authorization is
// enforced by FGA at ext-authz before the handler runs.
func TestTenantFromContext_AllowDirective(t *testing.T) {
	testdata := analysistest.TestData()
	// No // want comments in the clean fixture — zero diagnostics expected.
	analysistest.Run(t, testdata, checks.TenantFromContextAnalyzer,
		"github.com/zeroroot-ai/gibson/internal/server/daemon/api/tenantfromctxclean")
}
