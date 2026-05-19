/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package main

import (
	"path/filepath"
	"runtime"
	"testing"

	astchecks "github.com/zero-day-ai/ast-checks"
)

// TestNoContextBackgroundInRPCHandlers asserts that RPC handler code in
// `internal/daemon/api/` does not call `context.Background()`. The
// graceful-nil tests guard dependency wiring; this test guards context
// propagation. A handler that creates a fresh background context drops
// cancellation from the calling RPC — clients that hang up, timeouts
// from Envoy, and parent-span cancellation are all silently lost.
//
// Legitimate sites (rollback contexts after the main RPC context is
// done, shutdown cleanup paths) are explicitly allowlisted with a
// per-site reason. New violations fail the test.
//
// Implements one of three walkers in slice 3.6 of the production-readiness
// epic (zero-day-ai/gibson#181 → gibson#173 → board #16). The third
// walker in that slice (audit_emit_on_mutation) is deferred — gibson's
// audit happens at the middleware layer (ext-authz + harness middleware),
// not per-handler, so "every handler must call Emit" would be the wrong
// invariant.
//
// Scope: only `internal/daemon/api/`. Widening to other dirs lands when
// each subsystem adopts ctx-propagation discipline.
func TestNoContextBackgroundInRPCHandlers(t *testing.T) {
	_, thisFile, _, _ := runtime.Caller(0)
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..")

	matchers := []astchecks.Matcher{
		astchecks.NewForbiddenCallsite(
			"context.Background() in RPC handlers drops cancellation propagation; use the inbound ctx",
			"context.Background",
		),
	}

	// Existing-debt allowlist for legitimate sites that must not be
	// removed without thought.
	allowlist := astchecks.Allowlist{
		"internal/daemon/api/platform_operator_shutdown.go:46": astchecks.Entry{
			Category: astchecks.CategoryDefensiveGuard,
			Reason:   "shutdown cleanup must outlive the inbound RPC ctx; bounded by WithTimeout",
		},
		"internal/daemon/api/tenant_admin_create.go:211": astchecks.Entry{
			Category: astchecks.CategoryDefensiveGuard,
			Reason:   "saga rollback context must outlive the failed-RPC ctx; bounded by WithTimeout(10s)",
		},
	}

	opts := astchecks.WalkOpts{
		ScopeDirs:     []string{filepath.Join(repoRoot, "internal", "daemon", "api")},
		RepoRoot:      repoRoot,
		Matchers:      matchers,
		Allowlist:     allowlist,
		SkipTestFiles: true,
		SkipGenerated: true,
	}

	findings, err := astchecks.Walk(opts)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}

	if len(findings) > 0 {
		t.Errorf("NEW context.Background() in internal/daemon/api/:\n%s\n\n"+
			"Use the inbound RPC ctx — `func (s *Server) Method(ctx context.Context, ...)` —\n"+
			"so client cancellation + parent-span cancellation propagate to downstream calls.\n"+
			"If you genuinely need a context that outlives the inbound ctx (saga rollback,\n"+
			"shutdown cleanup), bound it with WithTimeout and add it to this allowlist with\n"+
			"a per-site reason.\n",
			astchecks.RenderFindings(findings))
	}

	t.Log(astchecks.FormatAllowlistLog(allowlist))
}
