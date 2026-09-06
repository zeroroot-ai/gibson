// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"path/filepath"
	"runtime"
	"testing"

	astchecks "github.com/zeroroot-ai/ast-checks"
)

// TestNoTimeNowInRPCHandlers asserts that RPC handler code in
// `internal/server/daemon/api/` does not call `time.Now()` for behavior that
// benefits from a testable clock. The slice 3.6 intent: handlers that
// depend on "the current time" for logic (cache expiry, token TTL,
// retry windows) should take an injected `Clock` interface so tests can
// move time deterministically.
//
// Existing sites are exhaustively allowlisted as DEFENSIVE-GUARD: every
// current `time.Now()` in `internal/server/daemon/api/` is a wall-clock
// timestamp for an audit log, a response field, or a latency-measurement
// start. None of them is logic-dependent on time advancing — so injecting
// Clock would be overkill.
//
// The walker is still load-bearing: any NEW `time.Now()` call on a PR
// surfaces the question at review time. The reviewer decides whether
// the new site needs Clock injection or whether it joins the allowlist
// with a per-site rationale.
//
// Implements one of three walkers in slice 3.6 of the production-readiness
// epic (zeroroot-ai/gibson#181 → gibson#173 → board #16). The third
// walker (audit_emit_on_mutation) is deferred — gibson's audit happens
// at the middleware layer, not per-handler.
//
// Scope: only `internal/server/daemon/api/`. Widening to other dirs is a
// follow-up when other subsystems adopt Clock-injection.
func TestNoTimeNowInRPCHandlers(t *testing.T) {
	_, thisFile, _, _ := runtime.Caller(0)
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..")

	matchers := []astchecks.Matcher{
		astchecks.NewForbiddenCallsite(
			"time.Now() in RPC handlers; prefer an injected Clock interface for testability",
			"time.Now",
		),
	}

	// CONTENT-KEYED (ast-checks v0.2.0, AllowlistByContent below; gibson#1384).
	// Each key is "<relpath> :: <snippet>" — the guard text, NOT a line
	// number — so an unrelated edit shifting a line can never red this gate
	// (the brittleness that hit #1382/#1329, the recurring #1310/#1234
	// class). ForbiddenCallsite's snippet is the bare call text
	// ("time.Now()"), identical for every call in a file, so this
	// necessarily coarsens to one entry per file — every prior per-site
	// reason for a file is preserved by concatenation rather than dropped.
	// This is the same trade-off no_graceful_nil_test.go's ContentKey
	// entries already accept ("identical guards in one file share one
	// key"); assertNoOrphanedContentKeys below closes the deletion-safety
	// gap that trade-off would otherwise leave open (see its doc comment).
	//
	// Migrated from the prior 34 line-keyed entries (dedupes to 15; one
	// entry, "findings_export.go:103", no longer matched anything — the
	// file had been renamed to export_findings.go — and was dropped
	// rather than carried forward stale).
	allowlist := astchecks.Allowlist{
		"internal/server/daemon/api/credentials.go :: time.Now()":               astchecks.Entry{Category: astchecks.CategoryDefensiveGuard, Reason: "credential creation timestamp; credential rotation timestamp; credential timestamp"},
		"internal/server/daemon/api/export_findings.go :: time.Now()":           astchecks.Entry{Category: astchecks.CategoryDefensiveGuard, Reason: "export-filename date stamp; wall-clock UTC; export-payload `exportedAt` field; wall-clock UTC"},
		"internal/server/daemon/api/llm_config.go :: time.Now()":                astchecks.Entry{Category: astchecks.CategoryDefensiveGuard, Reason: "LLM config metadata timestamp; LLM config `UpdatedAt` field; latency-measurement start for LLM probe; LLM `LastCheck` field; wall-clock"},
		"internal/server/daemon/api/server.go :: time.Now()":                    astchecks.Entry{Category: astchecks.CategoryDefensiveGuard, Reason: "session ID generation uses wall-clock Unix epoch; Ping response `Timestamp` field; wall-clock Unix; latency-measurement start (QueryPlugin)"},
		"internal/server/daemon/api/server_budget.go :: time.Now()":             astchecks.Entry{Category: astchecks.CategoryDefensiveGuard, Reason: "AppliedAtUnix wall-clock for budget operations"},
		"internal/server/daemon/api/server_chat.go :: time.Now()":               astchecks.Entry{Category: astchecks.CategoryDefensiveGuard, Reason: "conversation save `createdAt`/`updatedAt` Redis hash fields; wall-clock Unix; conversation save `updatedAt` refresh; wall-clock Unix"},
		"internal/server/daemon/api/server_entitlements.go :: time.Now()":       astchecks.Entry{Category: astchecks.CategoryDefensiveGuard, Reason: "audit-log timestamp; RFC3339Nano"},
		"internal/server/daemon/api/server_entitlements_audit.go :: time.Now()": astchecks.Entry{Category: astchecks.CategoryDefensiveGuard, Reason: "audit-log timestamp; RFC3339Nano"},
		"internal/server/daemon/api/server_model_access.go :: time.Now()":       astchecks.Entry{Category: astchecks.CategoryDefensiveGuard, Reason: "named helper wrapping wall-clock Unix timestamp"},
		"internal/server/daemon/api/server_provider_config.go :: time.Now()":    astchecks.Entry{Category: astchecks.CategoryDefensiveGuard, Reason: "latency-measurement start for TestProvider; `checkedAt` field on GetProviderHealth response; latency-measurement start for ProbeProvider; latency-measurement start for ListProviderModels"},
		"internal/server/daemon/api/server_tenant_status.go :: time.Now()":      astchecks.Entry{Category: astchecks.CategoryDefensiveGuard, Reason: "real-clock call site for authorizeBillingWebhook's injected `now` parameter"},
		"internal/server/daemon/api/server_usage.go :: time.Now()":              astchecks.Entry{Category: astchecks.CategoryDefensiveGuard, Reason: "`StaleAsOfUnix` response field; wall-clock"},
		"internal/server/daemon/api/signup_verification_store.go :: time.Now()": astchecks.Entry{Category: astchecks.CategoryDefensiveGuard, Reason: "clock() wall-clock default when no test clock (s.now) is injected"},
		"internal/server/daemon/api/signup_wiring.go :: time.Now()":             astchecks.Entry{Category: astchecks.CategoryDefensiveGuard, Reason: "signupNow() wall-clock default when no test clock (s.signupClock) is injected"},
		"internal/server/daemon/api/user_state.go :: time.Now()":                astchecks.Entry{Category: astchecks.CategoryDefensiveGuard, Reason: "onboarding default-state `startedAt`/`updatedAt` fields; wall-clock RFC3339; onboarding `updatedAt` field on Update; wall-clock RFC3339; user-activity `lastActiveAt` Unix-ms wall-clock marker; UUID fallback using wall-clock nonce when crypto/rand fails (unreachable in prod)"},
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
		t.Errorf("NEW time.Now() in internal/server/daemon/api/:\n%s\n\n"+
			"For NEW handler logic that depends on the current time (cache expiry, token TTL,\n"+
			"retry windows, anything a test would want to move forward), accept an injected\n"+
			"Clock interface instead of calling time.Now() directly. For wall-clock timestamps\n"+
			"on audit logs / response fields / latency-measurement starts, the allowlist accepts\n"+
			"new entries with a per-site reason — but PRs should justify the inability to test.\n",
			astchecks.RenderFindings(findings))
	}

	t.Log(astchecks.FormatAllowlistLog(allowlist))
}
