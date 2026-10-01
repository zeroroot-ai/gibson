// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package missioncatalog

import (
	"context"
	"strings"
	"testing"
)

// completeParams builds a full parameter set for one mission from its own
// declaration, so a parameter added to the mission shows up here as a value
// rather than as a test that quietly stops covering it.
func completeParams(t *testing.T, mission string) map[string]string {
	t.Helper()
	names, err := ParamNames(mission)
	if err != nil {
		t.Fatalf("ParamNames(%s): %v", mission, err)
	}
	out := make(map[string]string, len(names))
	for _, n := range names {
		out[n] = "v-" + n
	}
	return out
}

// ParamNames reads the mission's own CUE. It used to read a Go struct shared by
// every mission in the catalog, which is why Render demanded a pipeline id of a
// mission that has no pipeline (gibson#499).
func TestParamNames_ComesFromTheMissionsOwnDeclaration(t *testing.T) {
	t.Parallel()

	names, err := ParamNames("scan")
	if err != nil {
		t.Fatal(err)
	}
	if len(names) == 0 {
		t.Fatal("scan declares no parameters")
	}
	seen := map[string]bool{}
	for _, n := range names {
		if n == "" {
			t.Error("a parameter has no name")
		}
		if seen[n] {
			t.Errorf("parameter %q is declared twice", n)
		}
		seen[n] = true
	}
	// The names must be the ones the mission source actually writes, not a list
	// from somewhere else that happens to be the same length.
	src, err := Source("scan")
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		if !strings.Contains(src, n+":") {
			t.Errorf("ParamNames reported %q, which scan.cue does not declare", n)
		}
	}
}

func TestParamNames_UnknownMissionIsAnError(t *testing.T) {
	t.Parallel()
	if _, err := ParamNames("no-such-mission"); err == nil {
		t.Fatal("an unknown mission must be an error, not an empty parameter list")
	}
}

// Every name the mission declares must render, which is what proves the reading
// and the writing halves agree.
func TestRender_AParameterSetBuiltFromTheDeclarationRenders(t *testing.T) {
	t.Parallel()
	if _, err := Render(context.Background(), "scan", completeParams(t, "scan")); err != nil {
		t.Fatalf("a map built from ParamNames must render: %v", err)
	}
}

// The unknown-key refusal is the whole smuggling defence: no mission declares a
// target or a host, so a dropped key would leave a caller believing it had
// redirected the scan.
func TestRender_UnknownKeyIsRefusedNotDropped(t *testing.T) {
	t.Parallel()
	in := completeParams(t, "scan")
	in["host"] = "evil.example.com"

	_, err := Render(context.Background(), "scan", in)
	if err == nil {
		t.Fatal("an unknown parameter must be refused, not dropped")
	}
	if !strings.Contains(err.Error(), "host") {
		t.Errorf("the error does not name the offending key: %v", err)
	}
	// And it names what the mission does take, so the caller can correct it.
	names, _ := ParamNames("scan")
	if !strings.Contains(err.Error(), names[0]) {
		t.Errorf("the error does not name what the mission takes: %v", err)
	}
}

func TestRender_UnknownKeysReportedTogetherAndSorted(t *testing.T) {
	t.Parallel()
	in := completeParams(t, "scan")
	in["zeta"] = "1"
	in["alpha"] = "2"

	_, err := Render(context.Background(), "scan", in)
	if err == nil {
		t.Fatal("want a refusal")
	}
	msg := err.Error()
	ia, iz := strings.Index(msg, "alpha"), strings.Index(msg, "zeta")
	if ia < 0 || iz < 0 {
		t.Fatalf("both unknown keys must be reported: %v", err)
	}
	if ia > iz {
		t.Errorf("unknown keys must be sorted: %v", err)
	}
}

// Missing keys are reported together too. A caller wiring this up for the first
// time should see every field it forgot in one error.
func TestRender_MissingKeysReportedTogether(t *testing.T) {
	t.Parallel()
	names, err := ParamNames("scan")
	if err != nil {
		t.Fatal(err)
	}
	in := completeParams(t, "scan")
	delete(in, names[0])
	in[names[1]] = "   " // whitespace is as absent as absent

	_, err = Render(context.Background(), "scan", in)
	if err == nil {
		t.Fatal("a missing parameter must be refused rather than rendered empty")
	}
	for _, want := range names[:2] {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not name the missing %q: %v", want, err)
		}
	}
}

func TestRender_NoParametersAtAllIsRefusedForAMissionThatTakesSome(t *testing.T) {
	t.Parallel()
	if _, err := Render(context.Background(), "scan", nil); err == nil {
		t.Fatal("a mission that declares parameters must refuse an empty map")
	}
}

// A value carrying a quote or a backslash must not terminate the CUE string and
// inject a field. %q is what stops it; this asserts it still does.
func TestRender_AQuoteInAValueCannotInjectCUE(t *testing.T) {
	t.Parallel()
	in := completeParams(t, "scan")
	names, _ := ParamNames("scan")
	in[names[0]] = `x" , injected: "yes`

	if _, err := Render(context.Background(), "scan", in); err != nil {
		t.Fatalf("a quoted value must render, not fail: %v", err)
	}
}
