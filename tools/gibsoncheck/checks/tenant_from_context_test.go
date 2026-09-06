// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package checks_test

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"github.com/zeroroot-ai/gibson/tools/gibsoncheck/checks"
)

// TestTenantFromContext_Violation verifies that functions reading a tenant off
// the request without the gibsoncheck:allow tenant-from-request opt-out trigger
// a diagnostic at each read site — through the struct field (req.TenantId) and
// through the generated accessor (req.GetTenantId()), and regardless of what
// the request parameter is named. It also pins the receiver filter: a Get*
// selector on a server receiver is not a request-body read.
func TestTenantFromContext_Violation(t *testing.T) {
	testdata := analysistest.TestData()
	analysistest.Run(t, testdata, checks.TenantFromContextAnalyzer,
		"github.com/zeroroot-ai/gibson/internal/server/daemon/api/tenantfromctxviolation")
}

// TestTenantFromContext_CoversAdminPackage verifies the analyzer inspects
// internal/server/admin. That tree carries the MembershipService and
// TenantAdminService handlers and was previously outside the analyzer's
// package list, so the whole surface went unchecked.
func TestTenantFromContext_CoversAdminPackage(t *testing.T) {
	testdata := analysistest.TestData()
	analysistest.Run(t, testdata, checks.TenantFromContextAnalyzer,
		"github.com/zeroroot-ai/gibson/internal/server/admin/tenantfromctxadmin")
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
