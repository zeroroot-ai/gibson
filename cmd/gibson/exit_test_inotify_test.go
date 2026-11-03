// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// raiseInotifyAction is the shared action of zeroroot-ai/.github. A `uses:` line
// that names it counts as the raise.
const raiseInotifyAction = "zeroroot-ai/.github/.github/actions/raise-inotify-limits@"

// kindStarts are the commands that start a kind cluster in an exit-test
// workflow. The raise must come before the first of them. `make substrate`
// already starts the cluster, so it counts (gibson#1331).
var kindStarts = []string{"make substrate", "make recreate"}

// workflowMissingInotify reports whether a workflow stands up a kind cluster
// and does not raise the inotify limits before it (gibson#1331). A kind
// cluster of the whole platform needs more inotify instances than the runner
// gives. Without them the kubelet cannot follow a pod log, a streamed log loses
// its lines, and an exit test reads its verdict from a log that is not whole.
func workflowMissingInotify(text string) bool {
	standUp, raise, pos := -1, -1, 0
	for _, line := range strings.SplitAfter(text, "\n") {
		code := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(code, "#"):
		case strings.Contains(code, raiseInotifyAction) && raise < 0:
			raise = pos
		case containsAny(code, kindStarts) && standUp < 0:
			standUp = pos
		}
		pos += len(line)
	}
	return standUp >= 0 && (raise < 0 || raise > standUp)
}

// TestWorkflowMissingInotify is the failing fixture of the guard below.
func TestWorkflowMissingInotify(t *testing.T) {
	for name, tc := range map[string]struct {
		text string
		want bool
	}{
		"no kind cluster":                    {"steps:\n  - run: echo hi\n", false},
		"kind with no raise":                 {"  - run: make recreate ENV=kind\n", true},
		"raise after the kind":               {"  - run: make recreate ENV=kind\n  - uses: " + raiseInotifyAction + "abc\n", true},
		"raise before the kind":              {"  - uses: " + raiseInotifyAction + "abc\n  - run: make recreate ENV=kind\n", false},
		"substrate after the raise is clean": {"  - uses: " + raiseInotifyAction + "abc\n  - run: make substrate ENV=kind\n", false},
		"raise after the substrate":          {"  - run: make substrate ENV=kind\n  - uses: " + raiseInotifyAction + "abc\n", true},
		"substrate with no raise":            {"  - run: make substrate ENV=kind\n", true},
		"another action is none":             {"  - uses: ./gibson/.github/actions/open-kvm\n  - run: make recreate ENV=kind\n", true},
	} {
		if got := workflowMissingInotify(tc.text); got != tc.want {
			t.Errorf("%s: got %v, want %v", name, got, tc.want)
		}
	}
}

// TestExitTestWorkflowsRaiseInotifyLimits fails when an exit-test workflow
// stands up kind and does not raise the inotify limits first.
func TestExitTestWorkflowsRaiseInotifyLimits(t *testing.T) {
	_, thisFile, _, _ := runtime.Caller(0)
	dir := filepath.Join(filepath.Dir(thisFile), "..", "..", ".github", "workflows")
	fsys := os.DirFS(dir)
	files, err := fs.Glob(fsys, "exit-test-*.yml")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no exit-test workflow found: the guard looked in the wrong place")
	}
	for _, f := range files {
		b, err := fs.ReadFile(fsys, f)
		if err != nil {
			t.Fatal(err)
		}
		if workflowMissingInotify(string(b)) {
			t.Errorf("%s stands up kind and does not use %s before it", f, raiseInotifyAction)
		}
	}
}

func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
