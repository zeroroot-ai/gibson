// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package checks

import (
	"go/ast"
	"go/types"
	"strings"

	"golang.org/x/tools/go/analysis"
)

// OrgMemberWriteAnalyzer enforces hosted#203: a tenant role IS the
// membership (ADR-0093), so nothing writes a human tenant user onto Zitadel's
// org-member API (`/orgs/me/members`, and the v2 AddOrgMember /
// RemoveOrgMember calls it maps to). The one legitimate caller left in this
// tree is the platform-operator's machine-user administrator-role
// reconciliation (IAM_/ORG_-prefixed roles on a machine user's own
// service-account org membership, unrelated to any tenant) — allowlisted
// below by file, the same convention TenantRoleWriteAnalyzer uses.
//
// # What is flagged
//
// A call to AddOrgMember or RemoveOrgMember on
// operators/platform/internal/clients/zitadel.Client, from any file not in
// orgMemberAllowedFiles.
//
// # What is NOT flagged
//
//   - The interface declaration and the httpClient / errClient
//     implementations themselves (client.go): they define the methods, they
//     do not call them on a tenant-user path.
//   - oidcclient_controller.go: reconciles a machine user's OWN IAM_/ORG_
//     administrator roles, never a tenant user's membership.
//   - Test files and this analyzer's own testdata fixtures.
//
// Spec: ADR-0093, hosted#203.
var OrgMemberWriteAnalyzer = &analysis.Analyzer{
	Name: "orgmemberwrite",
	Doc:  "fail on any call to Zitadel's org-member API outside machine-user administrator-role reconciliation (hosted#203)",
	Run:  runOrgMemberWrite,
}

// orgMemberMethods are the org-member API methods this analyzer watches.
var orgMemberMethods = map[string]bool{
	"AddOrgMember":    true,
	"RemoveOrgMember": true,
}

// orgMemberOwningType is the interface these methods must belong to for a
// call to be in scope. A same-named method on an unrelated type (there is
// none today) would not match.
const orgMemberOwningType = "github.com/zeroroot-ai/gibson/operators/platform/internal/clients/zitadel.Client"

// orgMemberAllowedFiles are file paths (matched by suffix) allowed to call
// an org-member method: the one machine-user administrator-role
// reconciler. Do not add an entry without the same review this list already
// got — see the package doc comment above.
var orgMemberAllowedFiles = []string{
	"operators/platform/internal/controller/oidcclient_controller.go",
}

func runOrgMemberWrite(pass *analysis.Pass) (any, error) {
	for _, file := range pass.Files {
		fname := pass.Fset.Position(file.Pos()).Filename
		if strings.HasSuffix(fname, "_test.go") {
			continue
		}
		if isOrgMemberAllowedFile(fname) {
			continue
		}

		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if !orgMemberMethods[sel.Sel.Name] {
				return true
			}
			fn, ok := pass.TypesInfo.Uses[sel.Sel].(*types.Func)
			if !ok {
				return true
			}
			if qualifiedFuncName(fn) != orgMemberOwningType+"."+sel.Sel.Name {
				return true
			}
			pass.Reportf(call.Pos(),
				"%s calls Zitadel's org-member API outside machine-user administrator-role "+
					"reconciliation: a tenant role IS the membership (ADR-0093, hosted#203) — "+
					"there is no separate org-membership write for a tenant user. Use "+
					"tenantrole.Syncer.Assign/Revoke, or idp.AdminClient.EnsureHumanUser, instead.",
				sel.Sel.Name)
			return true
		})
	}
	return nil, nil
}

func isOrgMemberAllowedFile(fname string) bool {
	fname = filepathToSlash(fname)
	for _, allowed := range orgMemberAllowedFiles {
		if strings.HasSuffix(fname, allowed) {
			return true
		}
	}
	return false
}
