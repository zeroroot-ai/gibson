package checks_test

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"github.com/zeroroot-ai/gibson/tools/gibsoncheck/checks"
)

// TestAdminPoolAcquire_Violation verifies that a package outside the allowed
// list that imports internal/infra/datapool/admin triggers a diagnostic.
//
// The fixture is placed inside the gibson module namespace (internal/handlers)
// to satisfy Go's internal package visibility rules within the testdata GOPATH.
func TestAdminPoolAcquire_Violation(t *testing.T) {
	testdata := analysistest.TestData()
	analysistest.Run(t, testdata, checks.AdminPoolAcquireAnalyzer,
		"github.com/zeroroot-ai/gibson/internal/handlers")
}
