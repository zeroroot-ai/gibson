// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package missioncatalog

import (
	"strings"
	"testing"
)

// ParamNames is the one declaration every other use reads. If it ever returned
// a short list, validation would stop checking a field, rendering would emit it
// empty, and decoding would refuse it as unknown — three different symptoms of
// one cause.
func TestParamNames_MatchesTheStructItDescribes(t *testing.T) {
	t.Parallel()

	names := ParamNames()
	if len(names) == 0 {
		t.Fatal("ParamNames is empty")
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
	// Every declared name must round-trip through the decoder, which is what
	// proves the two halves of the declaration agree.
	in := map[string]string{}
	for _, n := range names {
		in[n] = "v-" + n
	}
	if _, err := ParamsFromMap(in); err != nil {
		t.Fatalf("a map built from ParamNames must decode: %v", err)
	}
}

// The smuggling defence, tested where it lives. Params has no target or host
// field, so the runtime target can only come from the mission's target. A
// decoder that dropped unrecognised keys would let a caller send
// `host: evil.example.com`, receive no error, and reasonably believe it bound.
func TestParamsFromMap_UnknownKeyIsRefusedNotDropped(t *testing.T) {
	t.Parallel()

	in := map[string]string{}
	for _, n := range ParamNames() {
		in[n] = "v"
	}
	in["host"] = "evil.example.com"

	_, err := ParamsFromMap(in)
	if err == nil {
		t.Fatal("an unknown parameter must be refused")
	}
	if !strings.Contains(err.Error(), "host") {
		t.Errorf("error %q does not name the refused key", err.Error())
	}
	// The known set is listed, so a caller with a typo can see what was meant
	// without opening the source.
	if !strings.Contains(err.Error(), ParamNames()[0]) {
		t.Errorf("error %q does not list the known parameters", err.Error())
	}
}

// Several typos are reported together and in a stable order, so a caller fixes
// them in one pass rather than one attempt each.
func TestParamsFromMap_UnknownKeysReportedTogetherAndSorted(t *testing.T) {
	t.Parallel()

	_, err := ParamsFromMap(map[string]string{"zeta": "1", "alpha": "2"})
	if err == nil {
		t.Fatal("unknown parameters must be refused")
	}
	msg := err.Error()
	ai, zi := strings.Index(msg, "alpha"), strings.Index(msg, "zeta")
	if ai < 0 || zi < 0 {
		t.Fatalf("error %q does not name both unknown keys", msg)
	}
	if ai > zi {
		t.Errorf("unknown keys are not sorted in %q", msg)
	}
}

// A partial map decodes what it was given; the emptiness of the rest is
// Render's business, reported all at once. Splitting that here would report a
// missing parameter twice with different wording.
func TestParamsFromMap_PartialMapDecodesWithoutError(t *testing.T) {
	t.Parallel()

	p, err := ParamsFromMap(map[string]string{"application": "portal"})
	if err != nil {
		t.Fatalf("a partial map is not a decoding error: %v", err)
	}
	if p.Application != "portal" {
		t.Errorf("Application = %q; want portal", p.Application)
	}
	if missing := p.missing(); len(missing) == 0 {
		t.Error("the unset parameters must still be reported as missing")
	}
}

// An empty map is not an error either, and reports every parameter as missing —
// the answer a caller wiring this up for the first time needs.
func TestParamsFromMap_EmptyMapReportsEveryParameterMissing(t *testing.T) {
	t.Parallel()

	p, err := ParamsFromMap(nil)
	if err != nil {
		t.Fatalf("an empty map is not a decoding error: %v", err)
	}
	if got, want := len(p.missing()), len(ParamNames()); got != want {
		t.Errorf("missing = %d parameters; want all %d", got, want)
	}
}
