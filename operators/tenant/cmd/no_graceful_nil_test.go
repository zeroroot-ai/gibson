// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	astchecks "github.com/zeroroot-ai/ast-checks"
)

// TestNoGracefulNilInRequestPaths walks every request-path Go file in the
// operator and flags each `if X == nil { return ... }` pattern where the body
// silently returns success (return nil / return true, nil / return false,
// nil / return nil, nil) without recording an error.
//
// Why: the "one-code-path" PRD (deploy#186) forbids degraded-mode branches in
// request paths. Every dependency must be validated at startup (in
// cmd/main.go). Once the binary runs, each call site assumes its dependencies
// are non-nil. A silent skip on a missing dependency produces a user-visible
// "Failed to load" with no log trail. Real incident: tenant-operator#76
// (broker config skipped, so every dashboard panel returned 412).
//
// The walker and the matcher are the shared ast-checks harness, the same one
// that cmd/gibson/no_graceful_nil_test.go uses, so the two gates cannot
// disagree about what a nil guard is (gibson#754). The operator keeps its own
// scope and its own allowlist. It uses the broad matcher: a selector at any
// depth (`e.cfg.RedisClient`) or a bare identifier (`out`), because the
// operator's dependencies sit deeper than one receiver field.
//
// Scope: only files under `internal/` are walked. `cmd/` (startup wiring),
// test files and generated files are out of scope.
func TestNoGracefulNilInRequestPaths(t *testing.T) {
	_, thisFile, _, _ := runtime.Caller(0)
	operatorRoot := filepath.Join(filepath.Dir(thisFile), "..")
	matchers := []astchecks.Matcher{astchecks.NewNilGuard(false)}

	// Fixture subtest: the walker flags the two illegal guards under
	// testdata/scope/internal and nothing under testdata/scope/cmd.
	t.Run("fixtures", func(t *testing.T) {
		fixturesRoot := filepath.Join(filepath.Dir(thisFile), "testdata", "scope")
		findings, err := astchecks.Walk(astchecks.WalkOpts{
			ScopeDirs:     []string{filepath.Join(fixturesRoot, "internal")},
			RepoRoot:      fixturesRoot,
			Matchers:      matchers,
			SkipTestFiles: true,
			SkipGenerated: true,
		})
		if err != nil {
			t.Fatalf("Walk fixtures: %v", err)
		}
		if want := 2; len(findings) != want {
			t.Errorf("fixture scan: got %d findings, want %d:\n%s",
				len(findings), want, astchecks.RenderFindings(findings))
		}
		for _, f := range findings {
			if !strings.Contains(f.Coord, "illegal_silent_skip") {
				t.Errorf("fixture scan: unexpected finding (should only flag illegal_*): %s", f)
			}
		}
	})

	// Existing-debt allowlist, keyed by content ("<relpath> :: <guard>"),
	// never by line number, so an unrelated line shift cannot red this gate.
	// Removing an entry is the goal. Adding one needs a reason.
	const (
		httpDiscard = "HTTP helper: out=nil means discard the body (a caller convention, not a dependency)"
		ctorGuard   = "client constructor guard; reassert with the constructor-inversion slice"
		k8sShape    = "the Kubernetes API may return a nil map or slice; a shape guard, not a dependency"
		applyShim   = "the ApplyOpts helper accepts a nil dst as a no-op"
		recorderOpt = "SetupWithManager always sets the event recorder; nil only in unit tests (best-effort observability)"
	)
	entry := func(c astchecks.Category, reason string) astchecks.Entry {
		return astchecks.Entry{Category: c, Reason: reason}
	}
	allowlist := astchecks.Allowlist{
		// internal/clients/*: HTTP unmarshal helpers (the caller passes out=nil to discard the body).
		"internal/clients/fga/http.go :: if out == nil || len(raw) == 0 { ... }":       entry(astchecks.CategoryDefensiveGuard, httpDiscard),
		"internal/clients/zitadel/client.go :: if out == nil || len(raw) == 0 { ... }": entry(astchecks.CategoryDefensiveGuard, httpDiscard),
		"internal/clients/vault/client.go :: if out == nil { ... }":                    entry(astchecks.CategoryDefensiveGuard, httpDiscard),
		"internal/clients/vault/transit.go :: if out == nil { ... }":                   entry(astchecks.CategoryDefensiveGuard, httpDiscard),

		"internal/clients/signupprogress/redis.go :: if c == nil || c.rdb == nil { ... }":             entry(astchecks.CategoryReceiverNilGuard, ctorGuard),
		"internal/provision/entitlements_grpc_client.go :: if c == nil || c.transport == nil { ... }": entry(astchecks.CategoryReceiverNilGuard, ctorGuard),

		// Controller-runtime patterns.
		"internal/controller/tenant_namespace.go :: if dst == nil { ... }": entry(astchecks.CategoryDefensiveGuard, applyShim),

		// E8 declarative reconcilers: each emit/event helper guards
		// `if r.Recorder == nil { return }`.
		"internal/controller/tenantdataplane_controller.go :: if r.Recorder == nil { ... }":      entry(astchecks.CategoryLegacyOptional, recorderOpt),
		"internal/controller/tenantsecretsbackend_controller.go :: if r.Recorder == nil { ... }": entry(astchecks.CategoryLegacyOptional, recorderOpt),
		"internal/controller/tenantidentity_controller.go :: if r.Recorder == nil { ... }":       entry(astchecks.CategoryLegacyOptional, recorderOpt),
		"internal/controller/tenantgrants_controller.go :: if r.Recorder == nil { ... }":         entry(astchecks.CategoryLegacyOptional, recorderOpt),
		"internal/controller/tenantrolesync_controller.go :: if r.Recorder == nil { ... }":       entry(astchecks.CategoryLegacyOptional, recorderOpt),

		// Saga runner: the Kubernetes API may return nil maps or conditions
		// from a new object.
		"internal/saga/runner.go :: if conditions == nil { ... }":  entry(astchecks.CategoryDefensiveGuard, k8sShape),
		"internal/saga/runner.go :: if annotations == nil { ... }": entry(astchecks.CategoryDefensiveGuard, k8sShape),
	}

	// Real-code subtest: walk internal/ and fail on each new finding.
	t.Run("real_code", func(t *testing.T) {
		report, err := astchecks.WalkReport(astchecks.WalkOpts{
			ScopeDirs:     []string{filepath.Join(operatorRoot, "internal")},
			RepoRoot:      operatorRoot,
			Matchers:      matchers,
			Allowlist:     allowlist,
			SkipTestFiles: true,
			SkipGenerated: true,
		})
		if err != nil {
			t.Fatalf("Walk: %v", err)
		}
		// An entry that allows nothing is a decision about a guard that is
		// gone. It must be deleted, or it would silently allow the next guard
		// with the same text in the same file.
		astchecks.AssertNoStaleAllowlist(t, report)

		if len(report.Findings) > 0 {
			t.Errorf("NEW graceful-nil branches in request paths (forbidden by one-code-path PRD deploy#186):\n%s\n\n"+
				"Each is a `if X == nil { return [...] nil }` pattern in a request-path file. The fix is one of:\n"+
				"  (1) Validate the dep at startup (cmd/main.go) so it can never be nil at request time.\n"+
				"  (2) If the skip is tenant-spec-aware, use the saga Step.Skip() predicate (which inspects only Tenant.Spec).\n"+
				"  (3) If this is a legitimate exception, add it to the allowlist with a category and a reason.\n",
				astchecks.RenderFindings(report.Findings))
		}
		t.Log(astchecks.FormatAllowlistLog(allowlist))
	})
}
