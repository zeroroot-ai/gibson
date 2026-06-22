// Copyright 2026 Zero Day AI, Inc.

package main

import (
	"path/filepath"
	"runtime"
	"testing"

	astchecks "github.com/zeroroot-ai/ast-checks"
)

// TestNoGibsonImport asserts that the ext-authz subtree — now folded into the
// gibson monorepo (ADR-0056) — never links the gibson DAEMON.
//
// The historical boundary ("ext-authz must not import
// github.com/zeroroot-ai/gibson") inverted when ext-authz moved inside the
// module: it now legitimately shares internal/infra. The invariant we keep is
// that ext-authz remains an independent authorization service that never
// depends on the daemon, so it must not import internal/daemon. This is the
// intra-module replacement for the old separate-repo no-gibson gate
// (gibson#782).
func TestNoGibsonImport(t *testing.T) {
	_, thisFile, _, _ := runtime.Caller(0)
	cmdDir := filepath.Dir(thisFile)              // cmd/ext-authz
	repoRoot := filepath.Join(cmdDir, "..", "..") // gibson module root
	extauthzPkgs := filepath.Join(repoRoot, "internal", "extauthz")

	matchers := []astchecks.Matcher{
		astchecks.NewImportBoundary(
			"ext-authz must not import the gibson daemon (internal/daemon) — it is an independent authorization service (ADR-0056, gibson#782)",
			"github.com/zeroroot-ai/gibson/internal/server/daemon",
		),
	}

	// Walk only the ext-authz subtree (cmd/ext-authz + internal/extauthz).
	// ast-checks recurses; vendor/, testdata/, .worktrees/ are skipped;
	// generated bindings excluded via SkipGenerated.
	opts := astchecks.WalkOpts{
		ScopeDirs:     []string{cmdDir, extauthzPkgs},
		RepoRoot:      repoRoot,
		Matchers:      matchers,
		SkipTestFiles: false, // boundary applies to test files too
		SkipGenerated: true,
	}

	findings, err := astchecks.Walk(opts)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}

	if len(findings) > 0 {
		t.Errorf("ext-authz imports the gibson daemon (forbidden — keep ext-authz daemon-independent):\n%s\n\n"+
			"ext-authz is the standalone authorization-decision point. It may share\n"+
			"internal/infra primitives, but it must NOT link internal/daemon. Required\n"+
			"types belong in the SDK; the authz registry is fetched from the daemon at\n"+
			"runtime over mTLS, never imported at link-time.\n",
			astchecks.RenderFindings(findings))
	}
}
