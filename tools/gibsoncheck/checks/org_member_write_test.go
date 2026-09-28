// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package checks_test

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"github.com/zeroroot-ai/gibson/tools/gibsoncheck/checks"
)

// TestOrgMemberWrite_ViolationsOutsideTheAllowlist is the mutation case: a
// call to AddOrgMember or RemoveOrgMember from a file the guard does not
// allowlist must be flagged, and a same-named method on an unrelated type
// must stay silent. If this test passed with the guard deleted from the
// registered analyzer list, the fixture itself would fail to compile with
// unexpected `want` comments unmatched — so this can only pass by the guard
// actually firing.
func TestOrgMemberWrite_ViolationsOutsideTheAllowlist(t *testing.T) {
	testdata := analysistest.TestData()
	analysistest.Run(t, testdata, checks.OrgMemberWriteAnalyzer,
		"github.com/zeroroot-ai/gibson/operators/platform/orgmemberviolation")
}

// TestOrgMemberWrite_MachineUserAdministratorRoleReconcilerIsExempt loads a
// testdata package declared at the real
// operators/platform/internal/controller import path, whose only file is
// named oidcclient_controller.go — the guard's one file-level exemption. It
// constructs the exact flagged call shape (AddOrgMember/RemoveOrgMember) and
// must stay silent: no `want` comments here means the guard must report
// zero findings.
func TestOrgMemberWrite_MachineUserAdministratorRoleReconcilerIsExempt(t *testing.T) {
	testdata := analysistest.TestData()
	analysistest.Run(t, testdata, checks.OrgMemberWriteAnalyzer,
		"github.com/zeroroot-ai/gibson/operators/platform/internal/controller")
}
