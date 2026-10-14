// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"testing"
)

// notRunIn returns each analyzer name that the workflow text never invokes
// as `gibsoncheck -<name>`.
func notRunIn(names []string, workflow string) []string {
	var missing []string
	for _, n := range names {
		if !regexp.MustCompile(`gibsoncheck\s+-` + regexp.QuoteMeta(n) + `\s`).MatchString(workflow) {
			missing = append(missing, n)
		}
	}
	return missing
}

// TestEveryAnalyzerRunsInCI fails when an analyzer is registered but no CI
// step runs it. Five analyzers were in that state: their analysistest
// fixtures passed, and the guard itself never ran (gibson#807 condition 7).
func TestEveryAnalyzerRunsInCI(t *testing.T) {
	wf, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "gibsoncheck.yml"))
	if err != nil {
		t.Fatalf("read the workflow: %v", err)
	}
	names := make([]string, 0, len(analyzers))
	for _, a := range analyzers {
		names = append(names, a.Name)
	}
	if len(names) < 15 {
		t.Fatalf("found %d analyzers, want at least 15: the list did not load", len(names))
	}
	if missing := notRunIn(names, string(wf)); len(missing) > 0 {
		t.Fatalf("gibsoncheck.yml never runs %v. Add `./bin/gibsoncheck -<name> <packages>` to a gate step.", missing)
	}
}

// TestNotRunIn_FlagsAnAnalyzerTheWorkflowSkips is the failing fixture.
func TestNotRunIn_FlagsAnAnalyzerTheWorkflowSkips(t *testing.T) {
	wf := "run: |\n  ./bin/gibsoncheck -alpha ./internal/...\n  ./bin/gibsoncheck -alphabet ./cmd/...\n"
	got := notRunIn([]string{"alpha", "beta", "alphab"}, wf)
	if want := []string{"beta", "alphab"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("notRunIn = %v, want %v", got, want)
	}
}
