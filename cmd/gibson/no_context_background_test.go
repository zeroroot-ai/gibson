// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"path/filepath"
	"runtime"
	"testing"

	astchecks "github.com/zeroroot-ai/ast-checks"
)

// TestNoContextBackgroundInRPCHandlers asserts that RPC handler code in
// `internal/server/daemon/api/` does not call `context.Background()`. The
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
// epic (zeroroot-ai/gibson#181 → gibson#173 → board #16). The third
// walker in that slice (audit_emit_on_mutation) is deferred — gibson's
// audit happens at the middleware layer (ext-authz + harness middleware),
// not per-handler, so "every handler must call Emit" would be the wrong
// invariant.
//
// Scope: only `internal/server/daemon/api/`. Widening to other dirs lands when
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

	// CONTENT-KEYED (ast-checks v0.2.0, AllowlistByContent below; gibson#1384).
	// Each key is "<relpath> :: <snippet>" — the guard text, NOT a line
	// number — so an unrelated edit shifting a line can never red this gate.
	// See no_time_now_test.go's allowlist comment for the file-level
	// coarsening trade-off this implies for ForbiddenCallsite matchers, and
	// assertNoOrphanedContentKeys for the deletion-safety check that
	// partially offsets it.
	//
	// Migrated from the prior 3 line-keyed entries: platform_operator_shutdown.go:43
	// no longer matched anything (the file no longer exists) and was dropped
	// rather than carried forward stale.
	allowlist := astchecks.Allowlist{
		"internal/server/daemon/api/tenant_admin_create.go :: context.Background()": astchecks.Entry{
			Category: astchecks.CategoryDefensiveGuard,
			Reason:   "saga rollback context must outlive the failed-RPC ctx; bounded by WithTimeout(10s)",
		},
		"internal/server/daemon/api/server_reembed_trigger.go :: context.Background()": astchecks.Entry{
			Category: astchecks.CategoryDefensiveGuard,
			Reason:   "detached async re-embed goroutine must outlive the inbound RPC ctx; bounded by WithTimeout(t.timeout)",
		},
	}

	opts := astchecks.WalkOpts{
		ScopeDirs:          []string{filepath.Join(repoRoot, "internal", "server", "daemon", "api")},
		RepoRoot:           repoRoot,
		Matchers:           matchers,
		Allowlist:          allowlist,
		SkipTestFiles:      true,
		SkipGenerated:      true,
		AllowlistByContent: true,
	}

	findings, err := astchecks.Walk(opts)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	assertNoOrphanedContentKeys(t, opts)

	if len(findings) > 0 {
		t.Errorf("NEW context.Background() in internal/server/daemon/api/:\n%s\n\n"+
			"Use the inbound RPC ctx — `func (s *Server) Method(ctx context.Context, ...)` —\n"+
			"so client cancellation + parent-span cancellation propagate to downstream calls.\n"+
			"If you genuinely need a context that outlives the inbound ctx (saga rollback,\n"+
			"shutdown cleanup), bound it with WithTimeout and add it to this allowlist with\n"+
			"a per-site reason.\n",
			astchecks.RenderFindings(findings))
	}

	t.Log(astchecks.FormatAllowlistLog(allowlist))
}
