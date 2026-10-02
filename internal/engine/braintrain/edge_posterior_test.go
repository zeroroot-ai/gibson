// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package braintrain

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
)

// fittedArtifact is what the trainer wrote for a known fixture: RESOLVES_TO
// saw 7 successes and 3 failures on a Beta(1,1) prior, AFFECTS saw 1 success.
func fittedArtifact() *EdgePosteriorArtifact {
	return &EdgePosteriorArtifact{
		Version: "test-v1",
		Posteriors: map[string]edgePosteriorJSON{
			"RESOLVES_TO": {Alpha: 8, Beta: 4},
			"AFFECTS":     {Alpha: 2, Beta: 1},
		},
	}
}

func TestLoadEdgePosteriorArtifact_RejectsAMissingVersion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte(`{"posteriors":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadEdgePosteriorArtifact(path); err == nil {
		t.Fatal("expected an error for an artifact with no version")
	}
}

func TestLoadEdgePosteriorArtifact_RejectsANonPositiveBetaShape(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	const raw = `{"version":"v1","posteriors":{"RESOLVES_TO":{"alpha":0,"beta":4}}}`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadEdgePosteriorArtifact(path); err == nil {
		t.Fatal("expected an error for a non-positive alpha")
	}
}

func TestEdgePosteriorArtifact_Provider_MeanMatchesFittedAlphaBeta(t *testing.T) {
	p := fittedArtifact().Provider()
	if got, want := p.Version(), "test-v1"; got != want {
		t.Fatalf("Provider().Version() = %q, want %q", got, want)
	}
	got := p.Posterior("RESOLVES_TO")
	if got.Alpha != 8 || got.Beta != 4 {
		t.Fatalf("Provider().Posterior(RESOLVES_TO) = Beta(%v,%v), want Beta(8,4)", got.Alpha, got.Beta)
	}
}

func TestEdgePosteriorArtifact_Provider_FallsBackToUninformativeForAnUnfittedEdgeType(t *testing.T) {
	got := fittedArtifact().Provider().Posterior("NEVER_OBSERVED")
	want := brain.UninformativeEdgePosteriors{}.Posterior("NEVER_OBSERVED")
	if got != want {
		t.Fatalf("fallback posterior = %+v, want %+v (uninformative)", got, want)
	}
}

func TestLoadEdgePosteriorArtifact_MissingFileErrors(t *testing.T) {
	if _, err := LoadEdgePosteriorArtifact(filepath.Join(t.TempDir(), "does-not-exist.json")); err == nil {
		t.Fatal("expected an error for a missing artifact file")
	}
}

func TestLoadEdgePosteriorArtifact_InvalidJSONErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadEdgePosteriorArtifact(path); err == nil {
		t.Fatal("expected an error for invalid JSON")
	}
}
