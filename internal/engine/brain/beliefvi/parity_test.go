// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package beliefvi

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// parityFixturePath is the checked-in fixture that
// sidecar/belief/gen_parity_fixture.py writes: the networks, and for each case
// {network, query_var, evidence, expected}, computed by infer.query (numpy),
// itself parity-tested against pgmpy to 1e-12 in test_parity.py. This is
// ADR-0134's parity gate: pgmpy never links into this Go binary or any runtime
// image, and a Go answer that drifts from the reference fails `go test ./...`.
//
// The fixture is in the repo, so the test needs no Python and never skips
// (gibson#714). TestParityFixtureIsCurrent fails when the reference changed
// and the fixture did not.
const parityFixturePath = "testdata/parity.json.gz"

// parityReferenceDir is the Python reference, from this package directory.
const parityReferenceDir = "../../../../sidecar/belief"

// parityReferenceFiles are the files that decide what the fixture holds. The
// generator hashes the same list in the same order (REFERENCE_FILES).
var parityReferenceFiles = []string{
	"gen_parity_fixture.py",
	"infer.py",
	"model.py",
	"models/base-v1.json",
}

// parityTolerance is ADR-0134's own stated bound: "parity-tested
// against pgmpy the same way infer.py is (agreement to 1e-12 in CI)".
const parityTolerance = 1e-12

type parityFixture struct {
	ReferenceDigest string                        `json:"reference_digest"`
	Networks        map[string]map[string]CPDSpec `json:"networks"`
	Cases           []parityCase                  `json:"cases"`
}

type parityCase struct {
	Network  string             `json:"network"`
	QueryVar string             `json:"query_var"`
	Evidence map[string]string  `json:"evidence"`
	Expected map[string]float64 `json:"expected"`
}

// loadParityFixture reads the checked-in fixture. A fixture that is absent,
// unreadable or empty fails the test. It never skips.
func loadParityFixture(t *testing.T) parityFixture {
	t.Helper()
	f, err := os.Open(parityFixturePath)
	if err != nil {
		t.Fatalf("open the parity fixture: %v", err)
	}
	defer func() { _ = f.Close() }()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("the parity fixture %s is not gzip: %v", parityFixturePath, err)
	}
	var fixture parityFixture
	if err := json.NewDecoder(gz).Decode(&fixture); err != nil {
		t.Fatalf("parse the parity fixture %s: %v", parityFixturePath, err)
	}
	if len(fixture.Cases) == 0 || len(fixture.Networks) == 0 {
		t.Fatalf("the parity fixture %s holds %d networks and %d cases", parityFixturePath, len(fixture.Networks), len(fixture.Cases))
	}
	return fixture
}

// parityReferenceDigest is the SHA-256 over each reference file in dir: its
// name, a NUL, its bytes, a NUL. The generator computes the same value
// (reference_digest in gen_parity_fixture.py).
func parityReferenceDigest(dir string) (string, error) {
	h := sha256.New()
	for _, name := range parityReferenceFiles {
		body, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(name))) // #nosec G304 -- a fixed list of repo files
		if err != nil {
			return "", fmt.Errorf("read the reference file %s: %w", name, err)
		}
		h.Write([]byte(name))
		h.Write([]byte{0})
		h.Write(body)
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

var errParityFixtureStale = errors.New("the parity fixture is older than the reference")

// checkParityFixtureCurrent fails when the fixture was made from a different
// reference than the one in dir.
func checkParityFixtureCurrent(fixtureDigest, dir string) error {
	current, err := parityReferenceDigest(dir)
	if err != nil {
		return err
	}
	if fixtureDigest != current {
		return fmt.Errorf("%w: the fixture holds digest %q and the reference in %s has digest %q. "+
			"Make a new fixture: python sidecar/belief/gen_parity_fixture.py internal/engine/brain/beliefvi/%s",
			errParityFixtureStale, fixtureDigest, dir, current, parityFixturePath)
	}
	return nil
}

// TestParityFixtureIsCurrent fails when a reference file changed and the
// fixture did not: the parity test would then compare the Go runtime with an
// old reference.
func TestParityFixtureIsCurrent(t *testing.T) {
	fixture := loadParityFixture(t)
	if err := checkParityFixtureCurrent(fixture.ReferenceDigest, parityReferenceDir); err != nil {
		t.Fatal(err)
	}
}

// TestCheckParityFixtureCurrent_FailsOnAChangedReference is the failing
// fixture of the guard above. It copies the reference, proves that the copy
// passes, changes one byte of each file in turn, and proves that the guard
// fails each time.
func TestCheckParityFixtureCurrent_FailsOnAChangedReference(t *testing.T) {
	fixture := loadParityFixture(t)

	for _, changed := range parityReferenceFiles {
		t.Run(changed, func(t *testing.T) {
			dir := t.TempDir()
			for _, name := range parityReferenceFiles {
				body, err := os.ReadFile(filepath.Join(parityReferenceDir, filepath.FromSlash(name))) // #nosec G304 -- a fixed list of repo files
				if err != nil {
					t.Fatal(err)
				}
				dst := filepath.Join(dir, filepath.FromSlash(name))
				if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(dst, body, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := checkParityFixtureCurrent(fixture.ReferenceDigest, dir); err != nil {
				t.Fatalf("an exact copy of the reference must pass: %v", err)
			}

			path := filepath.Join(dir, filepath.FromSlash(changed))
			body, err := os.ReadFile(path) // #nosec G304 -- a file this test wrote
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, append(body, '\n'), 0o600); err != nil {
				t.Fatal(err)
			}
			err = checkParityFixtureCurrent(fixture.ReferenceDigest, dir)
			if !errors.Is(err, errParityFixtureStale) {
				t.Fatalf("a change to %s must make the fixture stale, got %v", changed, err)
			}
		})
	}

	if err := checkParityFixtureCurrent(fixture.ReferenceDigest, t.TempDir()); err == nil {
		t.Fatal("a reference directory with no file must fail")
	}
}

func TestPgmpyParity(t *testing.T) {
	fixture := loadParityFixture(t)
	cases := fixture.Cases

	for i, c := range cases {
		cpds, ok := fixture.Networks[c.Network]
		if !ok {
			t.Fatalf("case %d names the network %q, which the fixture does not hold", i, c.Network)
		}
		names := make([]string, 0, len(cpds))
		for name := range cpds {
			names = append(names, name)
		}
		sort.Strings(names)

		factors := make([]Factor, 0, len(names))
		for _, name := range names {
			spec := cpds[name]
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
