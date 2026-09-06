// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"sort"
	"testing"

	astchecks "github.com/zeroroot-ai/ast-checks"
)

// assertNoOrphanedContentKeys re-runs opts with an empty allowlist and
// asserts every key in opts.Allowlist still matches a currently-discovered
// ContentKey.
//
// Content-keying (ast-checks v0.2.0, gibson#1384) fixes the false-positive
// side of line-keyed allowlists: an unrelated edit shifting a line no
// longer reds the gate. It does not, by itself, guarantee the other
// direction the issue also asks for — "deleting an exempted site ...
// must not silently exempt whatever replaces it" — because
// ForbiddenCallsite's snippet is the bare call text (e.g. "time.Now()"),
// identical for every call in a file, so distinct sites in the same file
// share one key. This helper closes that gap for the case that matters:
// if every call a key used to cover is removed, the key stops matching
// anything and goes silently inert — the entry rots forever instead of
// failing loud. Run this after every content-keyed Walk to turn "rots
// forever" into "fails the build," matching the two accepted outcomes
// the issue names.
//
// It cannot detect the narrower case of a *new*, different violation
// added to a file that already has an allowlisted call of the same kind
// (the coarsening is inherent to file+bare-call-text keying); that
// trade-off is accepted explicitly, matching the ast-checks-documented
// "identical guards in one file share one key" design and the existing
// precedent in no_graceful_nil_test.go.
func assertNoOrphanedContentKeys(t *testing.T, opts astchecks.WalkOpts) {
	t.Helper()
	if len(opts.Allowlist) == 0 {
		return
	}
	unfiltered := opts
	unfiltered.Allowlist = nil
	findings, err := astchecks.Walk(unfiltered)
	if err != nil {
		t.Fatalf("assertNoOrphanedContentKeys: unfiltered Walk: %v", err)
	}
	live := make(map[string]bool, len(findings))
	for _, f := range findings {
		live[f.ContentKey()] = true
	}
	var orphaned []string
	for key := range opts.Allowlist {
		if !live[key] {
			orphaned = append(orphaned, key)
		}
	}
	if len(orphaned) == 0 {
		return
	}
	sort.Strings(orphaned)
	t.Errorf("%d orphaned allowlist entries — no current finding matches their content key "+
		"(the guarded call was removed, renamed, or its file moved). Remove the stale entry "+
		"rather than leaving it to silently cover whatever new code lands at the same key:\n  %s",
		len(orphaned), joinStrings(orphaned, "\n  "))
}

func joinStrings(xs []string, sep string) string {
	out := ""
	for i, x := range xs {
		if i > 0 {
			out += sep
		}
		out += x
	}
	return out
}
