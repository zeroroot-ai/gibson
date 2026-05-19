/*
Copyright 2026 Zero Day AI.
Licensed under the Apache License, Version 2.0 (the "License").
*/

package main

import (
	"path/filepath"
	"runtime"
	"testing"

	astchecks "github.com/zero-day-ai/ast-checks"
)

// TestTenantClientOnly asserts that no handler in internal/daemon/api/
// calls pgxpool.Pool.QueryContext / .Exec / .Query directly. Per-tenant
// isolation requires routing every DB operation through the per-tenant
// client wrapper (which scopes the connection to the tenant's schema).
//
// Slice 3.5 of the production-readiness epic (gibson#180 → gibson#173).
func TestTenantClientOnly(t *testing.T) {
	_, thisFile, _, _ := runtime.Caller(0)
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..")

	matchers := []astchecks.Matcher{
		astchecks.NewForbiddenCallsite(
			"direct pgxpool.Pool access in handlers; must go through per-tenant client",
			"pgxpool.New",
			"pgxpool.Connect",
			"pgxpool.ParseConfig",
		),
	}

	opts := astchecks.WalkOpts{
		ScopeDirs:     []string{filepath.Join(repoRoot, "internal", "daemon", "api")},
		RepoRoot:      repoRoot,
		Matchers:      matchers,
		SkipTestFiles: true,
		SkipGenerated: true,
	}

	findings, err := astchecks.Walk(opts)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}

	if len(findings) > 0 {
		t.Errorf("direct pgxpool access in internal/daemon/api (%d sites):\n%s\n\n"+
			"Handlers must use the per-tenant client wrapper (state.NewTenantClient or similar)\n"+
			"to scope DB operations to the inbound tenant. Direct pgxpool calls bypass that scoping.\n",
			len(findings), astchecks.RenderFindings(findings))
	}
}
