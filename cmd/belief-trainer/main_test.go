// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"os"
	"path/filepath"
	"testing"
)

const testBaseArtifact = `{
  "version": "base-v1",
  "variables": ["reachable", "exploitable", "juicy"],
  "edges": [["reachable","exploitable"],["exploitable","juicy"]],
  "cpds": {
    "reachable": {"values": [[0.5],[0.5]]},
    "exploitable": {"evidence":["reachable"],"evidence_card":[2],"values":[[0.9,0.2],[0.1,0.8]]},
    "juicy": {"evidence":["exploitable"],"evidence_card":[2],"values":[[0.9,0.3],[0.1,0.7]]}
  }
}`

const testRows = `[{"reachable":true,"exploitable":true,"juicy":true},{"reachable":false,"exploitable":false,"juicy":false}]`

const testEdgeOutcomes = `[{"edge_type":"RESOLVES_TO","success":true},{"edge_type":"RESOLVES_TO","success":false}]`

func writeTestFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRun_RequiresTenant(t *testing.T) {
	if err := run([]string{}); err == nil {
		t.Fatal("expected an error when -tenant is missing")
	}
}

func TestRun_BaseAndRowsMustBeGivenTogether(t *testing.T) {
	dir := t.TempDir()
	base := writeTestFile(t, dir, "base.json", testBaseArtifact)

	if err := run([]string{"-tenant", "acme", "-base", base}); err == nil {
		t.Fatal("expected an error when -base is given without -rows")
	}
	rows := writeTestFile(t, dir, "rows.json", testRows)
	if err := run([]string{"-tenant", "acme", "-rows", rows}); err == nil {
		t.Fatal("expected an error when -rows is given without -base")
	}
}

func TestRun_RequiresAtLeastOneTrainingInput(t *testing.T) {
	if err := run([]string{"-tenant", "acme"}); err == nil {
		t.Fatal("expected an error when neither -base/-rows nor -edge-outcomes is given")
	}
}

func TestRun_InvalidFlagReturnsAnError(t *testing.T) {
	if err := run([]string{"-not-a-real-flag"}); err == nil {
		t.Fatal("expected an error for an unknown flag")
	}
}

func TestRun_TrainsTheCPTModelOnly(t *testing.T) {
	dir := t.TempDir()
	base := writeTestFile(t, dir, "base.json", testBaseArtifact)
	rows := writeTestFile(t, dir, "rows.json", testRows)
	out := filepath.Join(dir, "models")

	if err := run([]string{"-tenant", "acme", "-base", base, "-rows", rows, "-out", out}); err != nil {
		t.Fatalf("run: %v", err)
	}
	if _, err := os.Stat(filepath.Join(out, "tenant-acme-v1.json")); err != nil {
		t.Fatalf("expected CPT model artifact: %v", err)
	}
	if _, err := os.Stat(filepath.Join(out, "tenant-acme-edges-v1.json")); err == nil {
		t.Fatal("did not expect an edge-posterior artifact when -edge-outcomes was not given")
	}
}

func TestRun_TrainsTheEdgePosteriorOnly(t *testing.T) {
	dir := t.TempDir()
	edgeOutcomes := writeTestFile(t, dir, "edge-outcomes.json", testEdgeOutcomes)
	out := filepath.Join(dir, "models")

	if err := run([]string{"-tenant", "acme", "-edge-outcomes", edgeOutcomes, "-out", out}); err != nil {
		t.Fatalf("run: %v", err)
	}
	if _, err := os.Stat(filepath.Join(out, "tenant-acme-edges-v1.json")); err != nil {
		t.Fatalf("expected edge-posterior artifact: %v", err)
	}
	if _, err := os.Stat(filepath.Join(out, "tenant-acme-v1.json")); err == nil {
		t.Fatal("did not expect a CPT model artifact when -base/-rows were not given")
	}
}

func TestRun_TrainsBothArtifactsInOneRun(t *testing.T) {
	dir := t.TempDir()
	base := writeTestFile(t, dir, "base.json", testBaseArtifact)
	rows := writeTestFile(t, dir, "rows.json", testRows)
	edgeOutcomes := writeTestFile(t, dir, "edge-outcomes.json", testEdgeOutcomes)
	out := filepath.Join(dir, "models")

	if err := run([]string{
		"-tenant", "acme",
		"-base", base, "-rows", rows,
		"-edge-outcomes", edgeOutcomes,
		"-out", out,
	}); err != nil {
		t.Fatalf("run: %v", err)
	}
	if _, err := os.Stat(filepath.Join(out, "tenant-acme-v1.json")); err != nil {
		t.Fatalf("expected CPT model artifact: %v", err)
	}
	if _, err := os.Stat(filepath.Join(out, "tenant-acme-edges-v1.json")); err != nil {
		t.Fatalf("expected edge-posterior artifact: %v", err)
	}
}

func TestRun_PropagatesACPTTrainingError(t *testing.T) {
	dir := t.TempDir()
	// -base names a file that does not exist -> runCPTTraining fails.
	if err := run([]string{
		"-tenant", "acme",
		"-base", filepath.Join(dir, "does-not-exist.json"),
		"-rows", writeTestFile(t, dir, "rows.json", testRows),
	}); err == nil {
		t.Fatal("expected an error for a missing base artifact")
	}
}

func TestRun_PropagatesAnEdgePosteriorTrainingError(t *testing.T) {
	dir := t.TempDir()
	// -edge-outcomes names a file that does not exist -> runEdgePosteriorTraining fails.
	if err := run([]string{
		"-tenant", "acme",
		"-edge-outcomes", filepath.Join(dir, "does-not-exist.json"),
	}); err == nil {
		t.Fatal("expected an error for a missing edge-outcomes file")
	}
}

func TestLoadRows_DecodesAndFiltersToKnownVariables(t *testing.T) {
	dir := t.TempDir()
	path := writeTestFile(t, dir, "rows.json", `[{"reachable":true,"unknown_var":true}]`)
	rows, err := loadRows(path, map[string]bool{"reachable": true})
	if err != nil {
		t.Fatalf("loadRows: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	if _, ok := rows[0]["unknown_var"]; ok {
		t.Fatal("expected unknown_var to be filtered out")
	}
	if v, ok := rows[0]["reachable"]; !ok || !v {
		t.Fatal("expected reachable=true to survive filtering")
	}
}

func TestLoadRows_MissingFileErrors(t *testing.T) {
	if _, err := loadRows(filepath.Join(t.TempDir(), "nope.json"), nil); err == nil {
		t.Fatal("expected an error for a missing rows file")
	}
}

func TestLoadRows_InvalidJSONErrors(t *testing.T) {
	dir := t.TempDir()
	path := writeTestFile(t, dir, "rows.json", `not json`)
	if _, err := loadRows(path, nil); err == nil {
		t.Fatal("expected an error for invalid rows JSON")
	}
}

func TestLoadEdgeOutcomes_Decodes(t *testing.T) {
	dir := t.TempDir()
	path := writeTestFile(t, dir, "edge-outcomes.json", testEdgeOutcomes)
	outcomes, err := loadEdgeOutcomes(path)
	if err != nil {
		t.Fatalf("loadEdgeOutcomes: %v", err)
	}
	if len(outcomes) != 2 {
		t.Fatalf("expected 2 outcomes, got %d", len(outcomes))
	}
	if outcomes[0].EdgeType != "RESOLVES_TO" || !outcomes[0].Success {
		t.Fatalf("unexpected first outcome: %+v", outcomes[0])
	}
}

func TestLoadEdgeOutcomes_MissingFileErrors(t *testing.T) {
	if _, err := loadEdgeOutcomes(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Fatal("expected an error for a missing edge-outcomes file")
	}
}

func TestLoadEdgeOutcomes_InvalidJSONErrors(t *testing.T) {
	dir := t.TempDir()
	path := writeTestFile(t, dir, "edge-outcomes.json", `not json`)
	if _, err := loadEdgeOutcomes(path); err == nil {
		t.Fatal("expected an error for invalid edge-outcomes JSON")
	}
}
