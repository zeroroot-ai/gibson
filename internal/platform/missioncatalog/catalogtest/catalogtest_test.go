// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package catalogtest

import (
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
