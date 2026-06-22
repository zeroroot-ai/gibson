/*
Copyright 2026 Zero Day AI.
Licensed under the Apache License, Version 2.0 (the "License").
*/

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

// TestTenantIDSource asserts that no handler in internal/daemon/api/
// reads `req.TenantId` directly from a request body. The canonical
// tenant-ID source is the x-gibson-identity-tenant header (forwarded
// by ext-authz with HMAC signature, parsed by internal/identity).
//
// Slice 3.5 of the production-readiness epic (gibson#180 → gibson#173).
//
// Detection: any `<ident>.TenantId` access pattern in code under
// internal/daemon/api/ that doesn't have a comment marker
// // tenant-id-source: header-auth-context (the explicit opt-out for
// audit-record types that legitimately carry tenant-id in payload).
//
// Allowlist below: legitimate payload-carriers (events, audit log
// entries, response shapes) that have TenantId for non-authz purposes.
func TestTenantIDSource(t *testing.T) {
	_, thisFile, _, _ := runtime.Caller(0)
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..")
	scope := filepath.Join(repoRoot, "internal", "daemon", "api")

	// file:line coords where TenantId-from-payload is a known-legitimate
	// pattern. Tagged + reasoned, same shape as the graceful-nil allowlist.
	allowlist := map[string]string{
		// Legacy sites — req.TenantId is the OBJECT identifier (the
		// tenant being acted upon), not the authz SUBJECT. The authz
		// subject comes from the x-gibson-identity-tenant header on the
		// caller's identity (typically platform-operator for these).
		"internal/daemon/api/platform_operator_impersonate.go:31":  "platform-operator action; req.TenantId is the object being acted upon, not the authz subject",
		"internal/daemon/api/platform_operator_impersonate.go:43":  "platform-operator action; req.TenantId is the object being acted upon, not the authz subject",
		"internal/daemon/api/platform_operator_impersonate.go:48":  "platform-operator action; req.TenantId is the object being acted upon, not the authz subject",
		"internal/daemon/api/platform_operator_impersonate.go:58":  "platform-operator action; req.TenantId is the object being acted upon, not the authz subject",
		"internal/daemon/api/platform_operator_impersonate.go:61":  "platform-operator action; req.TenantId is the object being acted upon, not the authz subject",
		"internal/daemon/api/server_model_access.go:257":           "platform-operator action; req.TenantId is the object being acted upon, not the authz subject",
		"internal/daemon/api/tenant_admin_onboarding_get.go:29":    "platform-operator action; req.TenantId is the object being acted upon, not the authz subject",
		"internal/daemon/api/tenant_admin_onboarding_get.go:34":    "platform-operator action; req.TenantId is the object being acted upon, not the authz subject",
		"internal/daemon/api/tenant_admin_onboarding_get.go:42":    "platform-operator action; req.TenantId is the object being acted upon, not the authz subject",
		"internal/daemon/api/tenant_admin_onboarding_get.go:44":    "platform-operator action; req.TenantId is the object being acted upon, not the authz subject",
		"internal/daemon/api/tenant_admin_onboarding_update.go:29": "platform-operator action; req.TenantId is the object being acted upon, not the authz subject",
		"internal/daemon/api/tenant_admin_onboarding_update.go:34": "platform-operator action; req.TenantId is the object being acted upon, not the authz subject",
		"internal/daemon/api/tenant_admin_onboarding_update.go:42": "platform-operator action; req.TenantId is the object being acted upon, not the authz subject",
		"internal/daemon/api/tenant_admin_onboarding_update.go:43": "platform-operator action; req.TenantId is the object being acted upon, not the authz subject",
		"internal/daemon/api/tenant_admin_onboarding_update.go:47": "platform-operator action; req.TenantId is the object being acted upon, not the authz subject",
	}

	var findings []string
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
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
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
			rel, _ := filepath.Rel(repoRoot, pos.Filename)
			coord := rel + ":" + sprintInt(pos.Line)
			if _, ok := allowlist[coord]; ok {
				return true
			}
			findings = append(findings, coord)
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	sort.Strings(findings)
	if len(findings) > 0 {
		t.Errorf("tenant-id-from-payload found in internal/daemon/api (%d sites):\n  %s\n\n"+
			"Handlers must source tenant ID from the x-gibson-identity-tenant header (extracted by\n"+
			"internal/identity from the ext-authz-signed headers), NOT from request body fields.\n"+
			"If a TenantId field on a payload struct is legitimately needed (audit-record types,\n"+
			"event shapes, response payloads), add the coord to this test's allowlist with a per-site\n"+
			"reason. New handlers reading req.TenantId for authz purposes are a security bug.\n",
			len(findings), strings.Join(findings, "\n  "),
		)
	}

	// Keep allowlist visible in test output.
	if len(allowlist) > 0 {
		for c, r := range allowlist {
			t.Logf("allowlisted: %s — %s", c, r)
		}
	}
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
