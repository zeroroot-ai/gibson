/*
Copyright 2026 Hack the Planet LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

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

	// Existing sites — all wall-clock timestamps / latency-measurement
	// starts. No test-relevance for Clock injection at any of them.
	// Each new entry should carry a per-site reason; if multiple sites
	// in a file share a rationale, repeat the reason verbatim for
	// grep-friendliness.
	allowlist := astchecks.Allowlist{
		// export_findings.go — date stamps for export-file naming
		"internal/server/daemon/api/export_findings.go:119": astchecks.Entry{Category: astchecks.CategoryDefensiveGuard, Reason: "export-filename date stamp; wall-clock UTC"},
		"internal/server/daemon/api/export_findings.go:273": astchecks.Entry{Category: astchecks.CategoryDefensiveGuard, Reason: "export-payload `exportedAt` field; wall-clock UTC"},

		// findings_export.go — file timestamp
		"internal/server/daemon/api/findings_export.go:103": astchecks.Entry{Category: astchecks.CategoryDefensiveGuard, Reason: "export-filename timestamp; wall-clock UTC"},

		// server_provider_config.go — latency-measurement + check timestamps
		"internal/server/daemon/api/server_provider_config.go:450":  astchecks.Entry{Category: astchecks.CategoryDefensiveGuard, Reason: "latency-measurement start for TestProvider"},
		"internal/server/daemon/api/server_provider_config.go:691":  astchecks.Entry{Category: astchecks.CategoryDefensiveGuard, Reason: "`checkedAt` field on GetProviderHealth response"},
		"internal/server/daemon/api/server_provider_config.go:838":  astchecks.Entry{Category: astchecks.CategoryDefensiveGuard, Reason: "latency-measurement start for ProbeProvider"},
		"internal/server/daemon/api/server_provider_config.go:1045": astchecks.Entry{Category: astchecks.CategoryDefensiveGuard, Reason: "latency-measurement start for ListProviderModels"},

		// credentials.go — credential metadata timestamps
		"internal/server/daemon/api/credentials.go:88":  astchecks.Entry{Category: astchecks.CategoryDefensiveGuard, Reason: "credential creation timestamp"},
		"internal/server/daemon/api/credentials.go:123": astchecks.Entry{Category: astchecks.CategoryDefensiveGuard, Reason: "credential rotation timestamp"},
		"internal/server/daemon/api/credentials.go:167": astchecks.Entry{Category: astchecks.CategoryDefensiveGuard, Reason: "credential timestamp"},
		"internal/server/daemon/api/credentials.go:206": astchecks.Entry{Category: astchecks.CategoryDefensiveGuard, Reason: "credential timestamp"},

		// server_entitlements_audit.go — audit-log timestamps (per RFC3339Nano)
		"internal/server/daemon/api/server_entitlements_audit.go:135": astchecks.Entry{Category: astchecks.CategoryDefensiveGuard, Reason: "audit-log timestamp; RFC3339Nano"},
		"internal/server/daemon/api/server_entitlements_audit.go:171": astchecks.Entry{Category: astchecks.CategoryDefensiveGuard, Reason: "audit-log timestamp; RFC3339Nano"},
		"internal/server/daemon/api/server_entitlements.go:212":       astchecks.Entry{Category: astchecks.CategoryDefensiveGuard, Reason: "audit-log timestamp; RFC3339Nano"},

		// server_budget.go — budget applied-at timestamp
		"internal/server/daemon/api/server_budget.go:352": astchecks.Entry{Category: astchecks.CategoryDefensiveGuard, Reason: "AppliedAtUnix wall-clock for budget operations"},

		// server_model_access.go — timeNowUnix wrapper helper
		"internal/server/daemon/api/server_model_access.go:291": astchecks.Entry{Category: astchecks.CategoryDefensiveGuard, Reason: "named helper wrapping wall-clock Unix timestamp"},

		// server.go — session IDs + response timestamps + latency
		"internal/server/daemon/api/server.go:1166": astchecks.Entry{Category: astchecks.CategoryDefensiveGuard, Reason: "session ID generation uses wall-clock Unix epoch"},
		"internal/server/daemon/api/server.go:1185": astchecks.Entry{Category: astchecks.CategoryDefensiveGuard, Reason: "Ping response `Timestamp` field; wall-clock Unix"},
		"internal/server/daemon/api/server.go:1531": astchecks.Entry{Category: astchecks.CategoryDefensiveGuard, Reason: "latency-measurement start (QueryPlugin)"},

		// server_usage.go — staleness markers on usage responses
		"internal/server/daemon/api/server_usage.go:77":  astchecks.Entry{Category: astchecks.CategoryDefensiveGuard, Reason: "`StaleAsOfUnix` response field; wall-clock"},
		"internal/server/daemon/api/server_usage.go:113": astchecks.Entry{Category: astchecks.CategoryDefensiveGuard, Reason: "`StaleAsOfUnix` response field; wall-clock"},

		// llm_config.go — config metadata timestamps + latency
		"internal/server/daemon/api/llm_config.go:190": astchecks.Entry{Category: astchecks.CategoryDefensiveGuard, Reason: "LLM config metadata timestamp"},
		"internal/server/daemon/api/llm_config.go:259": astchecks.Entry{Category: astchecks.CategoryDefensiveGuard, Reason: "LLM config `UpdatedAt` field"},
		"internal/server/daemon/api/llm_config.go:364": astchecks.Entry{Category: astchecks.CategoryDefensiveGuard, Reason: "latency-measurement start for LLM probe"},
		"internal/server/daemon/api/llm_config.go:403": astchecks.Entry{Category: astchecks.CategoryDefensiveGuard, Reason: "LLM `LastCheck` field; wall-clock"},

		// server_chat.go — conversation store save timestamps
		"internal/server/daemon/api/server_chat.go:191": astchecks.Entry{Category: astchecks.CategoryDefensiveGuard, Reason: "conversation save `createdAt`/`updatedAt` Redis hash fields; wall-clock Unix"},
		"internal/server/daemon/api/server_chat.go:619": astchecks.Entry{Category: astchecks.CategoryDefensiveGuard, Reason: "conversation save `updatedAt` refresh; wall-clock Unix"},

		// user_state.go — per-user state record timestamps + activity last-active marker
		// (Module 2: Redis-read RPCs, dashboard-no-backing-store-clients).
		"internal/server/daemon/api/user_state.go:138": astchecks.Entry{Category: astchecks.CategoryDefensiveGuard, Reason: "onboarding default-state `startedAt`/`updatedAt` fields; wall-clock RFC3339"},
		"internal/server/daemon/api/user_state.go:217": astchecks.Entry{Category: astchecks.CategoryDefensiveGuard, Reason: "onboarding `updatedAt` field on Update; wall-clock RFC3339"},
		"internal/server/daemon/api/user_state.go:420": astchecks.Entry{Category: astchecks.CategoryDefensiveGuard, Reason: "user-activity `lastActiveAt` Unix-ms wall-clock marker"},
		"internal/server/daemon/api/user_state.go:651": astchecks.Entry{Category: astchecks.CategoryDefensiveGuard, Reason: "UUID fallback using wall-clock nonce when crypto/rand fails (unreachable in prod)"},
	}

	opts := astchecks.WalkOpts{
		ScopeDirs:     []string{filepath.Join(repoRoot, "internal", "server", "daemon", "api")},
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
