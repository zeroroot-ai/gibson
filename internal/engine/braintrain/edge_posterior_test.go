// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package braintrain

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
)

// syntheticOutcomes is a known, hand-countable recorded-outcomes fixture
// (gibson#395's "production may have no recorded outcomes yet" caveat: this
// is exactly the fixture/synthetic dataset the issue asks braintrain to be
// tested against). RESOLVES_TO: 7 successes, 3 failures. AFFECTS: 1 success,
// 0 failures. NEVER_OBSERVED never appears.
func syntheticOutcomes() []EdgeOutcome {
	var out []EdgeOutcome
	for i := 0; i < 7; i++ {
		out = append(out, EdgeOutcome{EdgeType: "RESOLVES_TO", Success: true})
	}
	for i := 0; i < 3; i++ {
		out = append(out, EdgeOutcome{EdgeType: "RESOLVES_TO", Success: false})
	}
	out = append(out, EdgeOutcome{EdgeType: "AFFECTS", Success: true})
	return out
}

func TestFitEdgePosteriors_KnownSyntheticDatasetProducesTheExactBetaParams(t *testing.T) {
	a, err := FitEdgePosteriors(syntheticOutcomes(), "test-v1")
	if err != nil {
		t.Fatalf("FitEdgePosteriors: %v", err)
	}

	// Prior is Beta(1,1) (brain.UninformativeEdgePosteriors), so the posterior
	// is exactly prior + counts: RESOLVES_TO -> Beta(1+7, 1+3) = Beta(8,4).
	got, ok := a.Posteriors["RESOLVES_TO"]
	if !ok {
		t.Fatal("RESOLVES_TO missing from fitted posteriors")
	}
	if got.Alpha != 8 || got.Beta != 4 {
		t.Fatalf("RESOLVES_TO posterior = Beta(%v,%v), want Beta(8,4)", got.Alpha, got.Beta)
	}
	wantMean := 8.0 / (8.0 + 4.0)
	gotMean := brain.EdgeStrengthPosterior{Alpha: got.Alpha, Beta: got.Beta}.Mean()
	if gotMean != wantMean {
		t.Fatalf("RESOLVES_TO mean = %v, want %v", gotMean, wantMean)
	}

	// AFFECTS -> Beta(1+1, 1+0) = Beta(2,1).
	affects, ok := a.Posteriors["AFFECTS"]
	if !ok {
		t.Fatal("AFFECTS missing from fitted posteriors")
	}
	if affects.Alpha != 2 || affects.Beta != 1 {
		t.Fatalf("AFFECTS posterior = Beta(%v,%v), want Beta(2,1)", affects.Alpha, affects.Beta)
	}

	// An edge type with zero recorded outcomes gets no row at all.
	if _, ok := a.Posteriors["NEVER_OBSERVED"]; ok {
		t.Fatal("NEVER_OBSERVED should have no fitted row (zero recorded outcomes)")
	}

	if a.Version != "test-v1" {
		t.Fatalf("Version = %q, want test-v1", a.Version)
	}
}

func TestFitEdgePosteriors_EmptyOutcomesProducesAnEmptyButValidArtifact(t *testing.T) {
	a, err := FitEdgePosteriors(nil, "test-v1")
	if err != nil {
		t.Fatalf("FitEdgePosteriors: %v", err)
	}
	if len(a.Posteriors) != 0 {
		t.Fatalf("expected no fitted rows, got %d", len(a.Posteriors))
	}
}

func TestFitEdgePosteriors_EmptyVersionErrors(t *testing.T) {
	if _, err := FitEdgePosteriors(syntheticOutcomes(), ""); err == nil {
		t.Fatal("expected an error for an empty version")
	}
}

func TestEdgePosteriorArtifact_WriteLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	a, err := FitEdgePosteriors(syntheticOutcomes(), "test-v1")
	if err != nil {
		t.Fatalf("FitEdgePosteriors: %v", err)
	}
	path := filepath.Join(dir, "test-v1.json")
	if err := a.Write(path); err != nil {
		t.Fatalf("Write: %v", err)
	}

	reloaded, err := LoadEdgePosteriorArtifact(path)
	if err != nil {
		t.Fatalf("LoadEdgePosteriorArtifact: %v", err)
	}
	if reloaded.Version != "test-v1" {
		t.Fatalf("reloaded version = %q, want test-v1", reloaded.Version)
	}
	got := reloaded.Posteriors["RESOLVES_TO"]
	if got.Alpha != 8 || got.Beta != 4 {
		t.Fatalf("reloaded RESOLVES_TO = Beta(%v,%v), want Beta(8,4)", got.Alpha, got.Beta)
	}
}

func TestLoadEdgePosteriorArtifact_RejectsAMissingVersion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte(`{"posteriors":{}}`), 0o644); err != nil {
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
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadEdgePosteriorArtifact(path); err == nil {
		t.Fatal("expected an error for a non-positive alpha")
	}
}

func TestEdgePosteriorArtifact_Provider_MeanMatchesFittedAlphaBeta(t *testing.T) {
	a, err := FitEdgePosteriors(syntheticOutcomes(), "test-v1")
	if err != nil {
		t.Fatalf("FitEdgePosteriors: %v", err)
	}
	p := a.Provider()
	if got, want := p.Version(), "test-v1"; got != want {
		t.Fatalf("Provider().Version() = %q, want %q", got, want)
	}
	got := p.Posterior("RESOLVES_TO")
	if got.Alpha != 8 || got.Beta != 4 {
		t.Fatalf("Provider().Posterior(RESOLVES_TO) = Beta(%v,%v), want Beta(8,4)", got.Alpha, got.Beta)
	}
}

func TestEdgePosteriorArtifact_Provider_FallsBackToUninformativeForAnUnfittedEdgeType(t *testing.T) {
	a, err := FitEdgePosteriors(syntheticOutcomes(), "test-v1")
	if err != nil {
		t.Fatalf("FitEdgePosteriors: %v", err)
	}
	got := a.Provider().Posterior("NEVER_OBSERVED")
	want := brain.UninformativeEdgePosteriors{}.Posterior("NEVER_OBSERVED")
	if got != want {
		t.Fatalf("fallback posterior = %+v, want %+v (uninformative)", got, want)
	}
}

func TestNextEdgePosteriorVersion_BumpsPastExistingAndIsIndependentOfTheCPTModelVersion(t *testing.T) {
	dir := t.TempDir()
	if v := NextEdgePosteriorVersion(dir, "acme"); v != "tenant-acme-edges-v1" {
		t.Errorf("empty dir should start at v1, got %q", v)
	}
	if err := os.WriteFile(filepath.Join(dir, "tenant-acme-edges-v1.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if v := NextEdgePosteriorVersion(dir, "acme"); v != "tenant-acme-edges-v2" {
		t.Errorf("should bump to v2, got %q", v)
	}

	// The belief-CPT model's own version sequence (NextVersion,
	// "tenant-<id>-v<n>") is a DIFFERENT prefix and must not be perturbed by,
	// or interfere with, the edge-posterior sequence in the same modelsDir.
	if v := NextVersion(dir, "acme"); v != "tenant-acme-v1" {
		t.Errorf("CPT model version sequence should be independent, got %q", v)
	}
}

func TestTrainTenantEdgePosteriors_EndToEnd(t *testing.T) {
	dir := t.TempDir()
	modelsDir := filepath.Join(dir, "models")

	res, err := TrainTenantEdgePosteriors("acme", syntheticOutcomes(), modelsDir)
	if err != nil {
		t.Fatalf("TrainTenantEdgePosteriors: %v", err)
	}
	if res.Version != "tenant-acme-edges-v1" {
		t.Errorf("first run should be v1, got %q", res.Version)
	}
	if res.Outcomes != len(syntheticOutcomes()) {
		t.Errorf("Outcomes = %d, want %d", res.Outcomes, len(syntheticOutcomes()))
	}

	reloaded, err := LoadEdgePosteriorArtifact(res.Path)
	if err != nil {
		t.Fatalf("reload trained artifact: %v", err)
	}
	if reloaded.Version != "tenant-acme-edges-v1" {
		t.Errorf("reloaded version mismatch: %q", reloaded.Version)
	}

	// A second run bumps the version and never overwrites v1 (ADR-0005 §5's
	// "never reuse a version a mission may have pinned", applied here to the
	// edge-posterior artifact kind).
	res2, err := TrainTenantEdgePosteriors("acme", syntheticOutcomes(), modelsDir)
	if err != nil {
		t.Fatal(err)
	}
	if res2.Version != "tenant-acme-edges-v2" {
		t.Errorf("second run should be v2, got %q", res2.Version)
	}
	if _, err := os.Stat(res.Path); err != nil {
		t.Errorf("v1 artifact must survive a re-train: %v", err)
	}
}

func TestTrainTenantEdgePosteriors_EmptyTenantErrors(t *testing.T) {
	if _, err := TrainTenantEdgePosteriors("  ", syntheticOutcomes(), t.TempDir()); err == nil {
		t.Fatal("expected an error for a blank tenant")
	}
}
