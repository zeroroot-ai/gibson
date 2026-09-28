// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package checks_test

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"github.com/zeroroot-ai/gibson/tools/gibsoncheck/checks"
)

// TestTenantRoleWrite_ViolationsOutsideTheSyncer is the mutation case: four
// shapes of a tenant-role tuple written outside tenantrole.Syncer, and
// three shapes that must stay silent (a non-role relation, a role relation
// on a non-tenant object, and a CheckRequest read). If this test passed
// with the guard deleted from the registered analyzer list, the fixture
// itself would fail to compile with unexpected `want` comments unmatched —
// so this can only pass by the guard actually firing.
func TestTenantRoleWrite_ViolationsOutsideTheSyncer(t *testing.T) {
	testdata := analysistest.TestData()
	analysistest.Run(t, testdata, checks.TenantRoleWriteAnalyzer,
		"github.com/zeroroot-ai/gibson/internal/tenantroleviolation")
}

// TestTenantRoleWrite_TheSyncerPackageIsExempt loads a testdata package
// declared at the real internal/platform/tenantrole import path,
// containing the exact tuple shape the violation fixture flags. It must
// NOT be flagged here — this package IS the one writer ADR-0093 names.
func TestTenantRoleWrite_TheSyncerPackageIsExempt(t *testing.T) {
	testdata := analysistest.TestData()
	analysistest.Run(t, testdata, checks.TenantRoleWriteAnalyzer,
		"github.com/zeroroot-ai/gibson/internal/platform/tenantrole")
}

// TestTenantRoleWrite_TheOperatorAdapterFileIsExempt loads a testdata
// package declared at the real
// operators/tenant/internal/clients/fga import path, whose only file is
// named tenantrole.go — the guard's one file-level exemption outside the
// Syncer's own package. It constructs the exact flagged shape and must
// stay silent.
func TestTenantRoleWrite_TheOperatorAdapterFileIsExempt(t *testing.T) {
	testdata := analysistest.TestData()
	analysistest.Run(t, testdata, checks.TenantRoleWriteAnalyzer,
		"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients/fga")
}
