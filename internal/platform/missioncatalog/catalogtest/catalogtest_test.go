// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package catalogtest

import (
	"fmt"
	"strings"
	"testing"
)

func TestExampleParams_ReadsTheDeclaration(t *testing.T) {
	t.Parallel()

	src := `
_params: {
	application: string
	connector?:  "a" | "b" @example("b")
	timeout?:    string @example("40m")
}
`
	got, err := ExampleParams(src)
	if err != nil {
		t.Fatalf("ExampleParams: %v", err)
	}
	want := map[string]string{"application": "v-application", "connector": "b", "timeout": "40m"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
}

func TestExampleParams_NoParamsIsNotAnError(t *testing.T) {
	t.Parallel()

	got, err := ExampleParams(`mission: name: "x"`)
	if err != nil || len(got) != 0 {
		t.Fatalf("got %v, %v, want an empty map", got, err)
	}
}

// The failing fixtures. A typed parameter with no example value must fail, and
// the error must name every such parameter.
func TestExampleParams_TypedParameterWithoutExampleFails(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"an enum":    `_params: {kind: "a" | "b"}`,
		"a pattern":  `_params: {id: =~"^[0-9]+$"}`,
		"a number":   `_params: {count?: int}`,
		"a blank":    `_params: {kind: "a" | "b" @example("  ")}`,
		"unquoted":   `_params: {kind: "a" | "b" @example(a)}`,
		"two typed":  `_params: {zeta: "a" | "b", alpha: int}`,
		"broken CUE": `_params: {`,
	}
	for name, src := range cases {
		if _, err := ExampleParams(src); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}

	_, err := ExampleParams(cases["two typed"])
	if err == nil || !strings.Contains(err.Error(), "alpha, zeta") {
		t.Errorf("the error must name both parameters, sorted: %v", err)
	}
}

// stopTB records a Fatal call and stops the helper, as a real test does.
type stopTB struct {
	testing.TB
	fatal string
}

func (s *stopTB) Helper() {}

func (s *stopTB) Fatal(args ...any) {
	s.fatal = fmt.Sprint(args...)
	panic(s)
}

func TestParams_ReturnsTheExamplesAndStopsTheTestOnAnError(t *testing.T) {
	t.Parallel()

	got := Params(t, `_params: {a: string}`)
	if got["a"] != "v-a" {
		t.Errorf("a = %q, want v-a", got["a"])
	}

	stop := &stopTB{TB: t}
	func() {
		defer func() { _ = recover() }()
		Params(stop, `_params: {kind: "a" | "b"}`)
	}()
	if !strings.Contains(stop.fatal, "kind") {
		t.Errorf("the test was not stopped with an error that names the parameter: %q", stop.fatal)
	}
}

func TestExampleParams_SkipsWhatIsNotANamedParameter(t *testing.T) {
	t.Parallel()

	src := `
_params: {
	// a comment is not a parameter
	[string]: string
	named: string @other("x") @example("n")
}
other: {x: 1}
`
	got, err := ExampleParams(src)
	if err != nil {
		t.Fatalf("ExampleParams: %v", err)
	}
	if len(got) != 1 || got["named"] != "n" {
		t.Errorf("got %v, want only named=n", got)
	}
}

func TestExampleParams_ParamsThatIsNotAStructFails(t *testing.T) {
	t.Parallel()

	if _, err := ExampleParams(`_params: "x"`); err == nil {
		t.Fatal("want an error")
	}
}
