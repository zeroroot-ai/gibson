// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package beliefvi

import (
	"os"
	"testing"
)

// canonicalBaseV1Path is sidecar/belief's own copy, four directories up from
// this package (internal/engine/brain/beliefvi -> internal/engine/brain ->
// internal/engine -> internal -> repo root).
const canonicalBaseV1Path = "../../../../sidecar/belief/models/base-v1.json"

// TestDefaultArtifact_MatchesTheCanonicalPythonSource guards embed.go's
// duplicated copy: sidecar/belief/models/base-v1.json is canonical (the
// braintrain/pgmpy tooling reads it there), and models/base-v1.json here is
// a go:embed-reachable copy. If the two ever drift apart, this fails the
// build rather than letting the Go runtime silently score against a stale
// model.
func TestDefaultArtifact_MatchesTheCanonicalPythonSource(t *testing.T) {
	canonical, err := os.ReadFile(canonicalBaseV1Path)
	if err != nil {
		t.Fatalf("read canonical source %s: %v", canonicalBaseV1Path, err)
	}
	if string(canonical) != string(embeddedBaseV1JSON) {
		t.Fatalf("embedded models/base-v1.json has drifted from the canonical %s; "+
			"copy the canonical file over the embedded one", canonicalBaseV1Path)
	}
}

func TestDefaultArtifact_LoadsAndValidates(t *testing.T) {
	art, err := DefaultArtifact()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewBeliefModel(art); err != nil {
		t.Fatalf("the embedded default artifact does not build a valid BeliefModel: %v", err)
	}
}
