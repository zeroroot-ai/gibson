// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// TestTenantIDSource asserts that no handler in internal/server/daemon/api/
// reads `req.TenantId` directly from a request body. The canonical
// tenant-ID source is the x-gibson-identity-tenant header (forwarded
// by ext-authz with HMAC signature, parsed by internal/identity).
//
// Slice 3.5 of the production-readiness epic (gibson#180 → gibson#173).
//
// Detection: any `<ident>.TenantId` access pattern in code under
// internal/server/daemon/api/ that doesn't have a comment marker
// // tenant-id-source: header-auth-context (the explicit opt-out for
// audit-record types that legitimately carry tenant-id in payload).
//
// Allowlist below: legitimate payload-carriers (events, audit log
// entries, response shapes) that have TenantId for non-authz purposes.
//
// CONTENT-KEYED (gibson#1384): each allowlist key is "<relpath> :: <line
// text>" — the full trimmed source line the match sits on — not a line
// number. A line number shifts on any unrelated edit above it (an added
// comment, an import, a license-header change); the guarded line's own
// text does not, so this walker survives exactly the class of edit that
// repeatedly reddened it (the #1310/#1234/#1382 pattern, same root cause
// as the astchecks-based walkers' migration in this same slice). Unlike
// those walkers' ForbiddenCallsite matcher — whose snippet is the bare
// call text and therefore coarsens to one entry per file — using the
// full line here keeps site-level precision: two `req.TenantId` reads on
// different lines of the same file get different keys as long as their
// surrounding code differs (which it does for every site below).
//
// Migrated from the prior 14 line-keyed entries: the five entries for
// platform_operator_impersonate.go were dropped — that file no longer
// exists — rather than carried forward stale.
func TestTenantIDSource(t *testing.T) {
	_, thisFile, _, _ := runtime.Caller(0)
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..")
	scope := filepath.Join(repoRoot, "internal", "server", "daemon", "api")

	allowlist := map[string]string{
		// Legacy sites — req.TenantId is the OBJECT identifier (the
		// tenant being acted upon), not the authz SUBJECT. The authz
		// subject comes from the x-gibson-identity-tenant header on the
		// caller's identity (typically platform-operator for these).
		`internal/server/daemon/api/server_model_access.go :: TenantId:      r.TenantID,`: "response event shape; TenantId echoes the stored audit row, and is never read as the authz subject",

		`internal/server/daemon/api/tenant_admin_onboarding_get.go :: if req.TenantId == "" {`:                                                                                    "platform-operator action; req.TenantId is the object being acted upon, not the authz subject",
		`internal/server/daemon/api/tenant_admin_onboarding_get.go :: if auth.TenantStringFromContext(ctx) != req.TenantId {`:                                                     "platform-operator action; req.TenantId is the object being acted upon, not the authz subject",
		`internal/server/daemon/api/tenant_admin_onboarding_get.go :: currentStep, completedSteps, setupTasks, completedAt, err := s.onboardingStore.GetState(ctx, req.TenantId)`: "platform-operator action; req.TenantId is the object being acted upon, not the authz subject",
		`internal/server/daemon/api/tenant_admin_onboarding_get.go :: s.logger.Error("failed to get onboarding state", "tenant_id", req.TenantId, "error", err)`:                  "platform-operator action; req.TenantId is the object being acted upon, not the authz subject",

		`internal/server/daemon/api/tenant_admin_onboarding_update.go :: if req.TenantId == "" {`:                                                                                                       "platform-operator action; req.TenantId is the object being acted upon, not the authz subject",
		`internal/server/daemon/api/tenant_admin_onboarding_update.go :: if auth.TenantStringFromContext(ctx) != req.TenantId {`:                                                                        "platform-operator action; req.TenantId is the object being acted upon, not the authz subject",
		`internal/server/daemon/api/tenant_admin_onboarding_update.go :: if err := s.onboardingStore.UpdateState(ctx, req.TenantId, req.CurrentStep, req.CompletedSteps, req.SetupTasks); err != nil {`: "platform-operator action; req.TenantId is the object being acted upon, not the authz subject",
		`internal/server/daemon/api/tenant_admin_onboarding_update.go :: s.logger.Error("failed to update onboarding state", "tenant_id", req.TenantId, "error", err)`:                                  "platform-operator action; req.TenantId is the object being acted upon, not the authz subject",
		`internal/server/daemon/api/tenant_admin_onboarding_update.go :: s.logger.Info("onboarding state updated via RPC", "tenant_id", req.TenantId)`:                                                  "platform-operator action; req.TenantId is the object being acted upon, not the authz subject",
	}

	var findings []string
	liveKeys := make(map[string]bool)
	err := filepath.Walk(scope, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			if info != nil && info.IsDir() && info.Name() == "testdata" {
				return filepath.SkipDir
			}
			return err
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		if strings.HasSuffix(path, ".pb.go") || strings.HasSuffix(path, "_grpc.pb.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, src, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		lines := strings.Split(string(src), "\n")
		rel, _ := filepath.Rel(repoRoot, path)
		// Narrow: only flag `<req-like>.TenantId` where ident is req/request/r.
		// Other selectors are legitimate payload carriers.
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if sel.Sel.Name != "TenantId" && sel.Sel.Name != "TenantID" {
				return true
			}
			id, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			switch id.Name {
			case "req", "request", "r":
			default:
				return true
			}
			pos := fset.Position(sel.Pos())
			key := rel + " :: " + sourceLineSnippet(lines, pos.Line)
			liveKeys[key] = true
			if _, ok := allowlist[key]; ok {
				return true
			}
			findings = append(findings, rel+":"+sprintInt(pos.Line)+" :: "+key)
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	sort.Strings(findings)
	if len(findings) > 0 {
		t.Errorf("tenant-id-from-payload found in internal/server/daemon/api (%d sites):\n  %s\n\n"+
			"Handlers must source tenant ID from the x-gibson-identity-tenant header (extracted by\n"+
			"internal/identity from the ext-authz-signed headers), NOT from request body fields.\n"+
			"If a TenantId field on a payload struct is legitimately needed (audit-record types,\n"+
			"event shapes, response payloads), add the content key to this test's allowlist with a\n"+
			"per-site reason. New handlers reading req.TenantId for authz purposes are a security bug.\n",
			len(findings), strings.Join(findings, "\n  "),
		)
	}

	// Orphaned-entry check: every allowlist key must still match a
	// currently-discovered site. An entry that matches nothing means its
	// guarded line was deleted, renamed, or reworded — leaving it to
	// silently exempt whatever unrelated code happens to produce the same
	// key later is exactly the failure mode gibson#1384 forbids. Fail loud
	// instead so the stale entry gets removed deliberately.
	var orphaned []string
	for key := range allowlist {
		if !liveKeys[key] {
			orphaned = append(orphaned, key)
		}
	}
	if len(orphaned) > 0 {
		sort.Strings(orphaned)
		t.Errorf("%d orphaned allowlist entries — no current site matches their content key:\n  %s",
			len(orphaned), strings.Join(orphaned, "\n  "))
	}

	// Keep allowlist visible in test output.
	if len(allowlist) > 0 {
		keys := make([]string, 0, len(allowlist))
		for k := range allowlist {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			t.Logf("allowlisted: %s — %s", k, allowlist[k])
		}
	}
}

// sourceLineSnippet returns the trimmed text of the given 1-indexed source
// line. Used to build a content key that identifies a guard by its own
// text rather than its position, so line shifts elsewhere in the file
// don't change the key.
func sourceLineSnippet(lines []string, line int) string {
	if line < 1 || line > len(lines) {
		return ""
	}
	return strings.TrimSpace(lines[line-1])
}

func sprintInt(n int) string {
	if n == 0 {
		return "0"
	}
	digits := ""
	for n > 0 {
		digits = string(rune('0'+(n%10))) + digits
		n /= 10
	}
	return digits
}
