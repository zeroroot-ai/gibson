// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package beliefvi

import (
	"encoding/json"
	"os"
	"sort"
	"testing"
)

// parityFixtureEnv names the JSON fixture gen_parity_fixture.py writes
// (sidecar/belief/gen_parity_fixture.py) — a list of {cpds, query_var,
// evidence, expected} cases computed by infer.query (numpy), itself
// parity-tested against pgmpy to 1e-12 in test_parity.py. This is ADR-0134's
// CI parity gate: pgmpy never links into this Go binary or any
// runtime image, but the belief-sidecar CI workflow generates this fixture
// (with the numpy reference it already holds to pgmpy) and points this test
// at it, so a Go answer that drifts from the reference fails the build.
//
// Unset locally (the common case — nobody is expected to have Python/numpy
// wired up just to run `go test`), this test skips, exactly the same
// import-guarded-skip shape test_parity.py itself uses for pgmpy.
const parityFixtureEnv = "GIBSON_BELIEF_PARITY_FIXTURE"

// parityTolerance is ADR-0134's own stated bound: "parity-tested
// against pgmpy the same way infer.py is (agreement to 1e-12 in CI)".
const parityTolerance = 1e-12

type parityCase struct {
	CPDs     map[string]CPDSpec `json:"cpds"`
	QueryVar string             `json:"query_var"`
	Evidence map[string]string  `json:"evidence"`
	Expected map[string]float64 `json:"expected"`
}

func TestPgmpyParity(t *testing.T) {
	path := os.Getenv(parityFixtureEnv)
	if path == "" {
		t.Skipf("%s not set; generate it with `python sidecar/belief/gen_parity_fixture.py > <path>` "+
			"(needs numpy, not pgmpy) and re-run with %s=<path>. CI sets this on every PR (belief-sidecar.yml).",
			parityFixtureEnv, parityFixtureEnv)
	}

	// #nosec G304 -- path comes from GIBSON_BELIEF_PARITY_FIXTURE, a CI/dev
	// environment variable, never end-user input.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	var cases []parityCase
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatalf("parse fixture %s: %v", path, err)
	}
	if len(cases) == 0 {
		t.Fatalf("fixture %s carries no cases", path)
	}

	for i, c := range cases {
		names := make([]string, 0, len(c.CPDs))
		for name := range c.CPDs {
			names = append(names, name)
		}
		sort.Strings(names)

		factors := make([]Factor, 0, len(names))
		for _, name := range names {
			spec := c.CPDs[name]
			f, err := CPDToFactor(name, spec.Values, spec.Evidence, spec.EvidenceCard)
			if err != nil {
				t.Fatalf("case %d: cpd_to_factor(%q): %v", i, name, err)
			}
			factors = append(factors, f)
		}

		got, err := Query(factors, c.QueryVar, c.Evidence)
		if err != nil {
			t.Fatalf("case %d: query(%q, %v): %v", i, c.QueryVar, c.Evidence, err)
		}
		for _, state := range States {
			want, ok := c.Expected[state]
			if !ok {
				continue
			}
			diff := got[state] - want
			if diff < 0 {
				diff = -diff
			}
			if diff > parityTolerance {
				t.Errorf("case %d: query(%q, %v)[%q] = %v, pgmpy/numpy reference = %v (diff %v > %v)",
					i, c.QueryVar, c.Evidence, state, got[state], want, diff, parityTolerance)
			}
		}
	}
	t.Logf("parity: %d cases agreed with the pgmpy/numpy reference to %v", len(cases), parityTolerance)
}
