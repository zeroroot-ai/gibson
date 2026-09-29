// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package beliefvi

import (
	"math"
	"reflect"
	"testing"
)

// basePath reads the canonical Python-side copy directly (the same path
// embed_test.go's TestDefaultArtifact_MatchesTheCanonicalPythonSource
// guards), so this exercises LoadModelArtifact's actual file-reading code
// path without needing a third duplicate of base-v1.json in this package.
const basePath = canonicalBaseV1Path

func TestEvidenceToObservations_MapsKnownAndFlagsNovel(t *testing.T) {
	known := map[string]struct{}{"reachable": {}, "port_22": {}, "svc_ssh": {}}
	ev := Evidence{OpenPorts: []int{22, 9999}, Services: []string{"22/ssh", "9999/weirdsvc"}, Reachable: true}
	obs, novel := EvidenceToObservations(ev, known)

	want := map[string]string{"reachable": "true", "port_22": "true", "svc_ssh": "true"}
	if len(obs) != len(want) {
		t.Fatalf("obs = %v, want %v", obs, want)
	}
	for k, v := range want {
		if obs[k] != v {
			t.Errorf("obs[%q] = %q, want %q", k, obs[k], v)
		}
	}
	if !contains(novel, "port_9999") || !contains(novel, "svc_weirdsvc") {
		t.Errorf("novel = %v, want port_9999 and svc_weirdsvc", novel)
	}
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func TestEvidenceToObservations_IsDeterministicAndOrderStable(t *testing.T) {
	known := map[string]struct{}{"reachable": {}, "port_22": {}, "port_443": {}}
	a, _ := EvidenceToObservations(Evidence{OpenPorts: []int{443, 22}, Reachable: true}, known)
	b, _ := EvidenceToObservations(Evidence{OpenPorts: []int{22, 443}, Reachable: true}, known)
	if len(a) != len(b) {
		t.Fatalf("a=%v b=%v", a, b)
	}
	for k, v := range a {
		if b[k] != v {
			t.Errorf("a[%q]=%q b[%q]=%q", k, v, k, b[k])
		}
	}
}

func TestEvidenceToObservations_UnreachableSetsFalse(t *testing.T) {
	known := map[string]struct{}{"reachable": {}}
	obs, _ := EvidenceToObservations(Evidence{Reachable: false}, known)
	if obs["reachable"] != "false" || len(obs) != 1 {
		t.Fatalf("obs = %v, want {reachable: false}", obs)
	}
}

func TestPosteriorsFromMarginals_DefaultsMissingToZero(t *testing.T) {
	out := PosteriorsFromMarginals(map[string]float64{"juicy": 0.6})
	if out["juicy"] != 0.6 || out["exploitable"] != 0.0 || out["reachable"] != 0.0 {
		t.Fatalf("out = %v", out)
	}
}

func TestModelArtifact_LoadsAndHasQueryVars(t *testing.T) {
	art, err := LoadModelArtifact(basePath)
	if err != nil {
		t.Fatal(err)
	}
	if art.Version != "base-v1" {
		t.Fatalf("version = %q, want base-v1", art.Version)
	}
	known := art.KnownVars()
	for _, q := range QueryVars {
		if _, ok := known[q]; !ok {
			t.Errorf("missing query var %q", q)
		}
	}
}

func TestModelArtifact_RejectsMissingQueryVar(t *testing.T) {
	raw := []byte(`{"version":"bad","variables":["reachable","exploitable"],"cpds":{}}`)
	if _, err := ParseModelArtifact(raw); err == nil {
		t.Fatal("expected an error for a missing query var")
	}
}

var simpleArtifactJSON = []byte(`{
  "version": "t",
  "variables": ["reachable", "exploitable", "juicy"],
  "edges": [["reachable", "exploitable"], ["exploitable", "juicy"]],
  "cpds": {
    "reachable": {"values": [[0.7], [0.3]]},
    "exploitable": {"evidence": ["reachable"], "evidence_card": [2], "values": [[0.9, 0.2], [0.1, 0.8]]},
    "juicy": {"evidence": ["exploitable"], "evidence_card": [2], "values": [[0.95, 0.4], [0.05, 0.6]]}
  }
}`)

func TestBeliefModel_RejectsEdgesThatDisagreeWithTheCPDs(t *testing.T) {
	art, err := ParseModelArtifact(simpleArtifactJSON)
	if err != nil {
		t.Fatal(err)
	}
	// edges claim reachable -> juicy, the cpds do not.
	art.Edges = [][2]string{{"reachable", "exploitable"}, {"reachable", "juicy"}}
	if _, err := NewBeliefModel(art); err == nil {
		t.Fatal("expected an edges/cpd mismatch error")
	}
}

func TestBeliefModel_AcceptsTheConsistentArtifact(t *testing.T) {
	art, err := ParseModelArtifact(simpleArtifactJSON)
	if err != nil {
		t.Fatal(err)
	}
	m, err := NewBeliefModel(art)
	if err != nil {
		t.Fatal(err)
	}
	out, err := m.Score(Evidence{Reachable: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.Reachable != 1.0 {
		t.Errorf("reachable = %v, want 1.0", out.Reachable)
	}
	if out.Juicy < 0.0 || out.Juicy > 1.0 {
		t.Errorf("juicy out of range: %v", out.Juicy)
	}
	if math.IsNaN(out.Exploitable) || math.IsInf(out.Exploitable, 0) {
		t.Errorf("exploitable not finite: %v", out.Exploitable)
	}
}

func TestBeliefModel_BaseModelExactInferenceIsDeterministic(t *testing.T) {
	art, err := LoadModelArtifact(basePath)
	if err != nil {
		t.Fatal(err)
	}
	m, err := NewBeliefModel(art)
	if err != nil {
		t.Fatal(err)
	}
	for _, ports := range [][]int{{22}, {22, 443}, {}} {
		ev := Evidence{OpenPorts: ports, Reachable: len(ports) > 0}
		a, err := m.Score(ev, nil)
		if err != nil {
			t.Fatal(err)
		}
		b, err := m.Score(ev, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(a, b) {
			t.Fatalf("scores not bit-identical: %+v vs %+v", a, b)
		}
		if a.Version != "base-v1" {
			t.Errorf("version = %q, want base-v1", a.Version)
		}
		for _, v := range []float64{a.Juicy, a.Exploitable, a.Reachable} {
			if v < 0.0 || v > 1.0 {
				t.Errorf("posterior out of [0,1]: %v", v)
			}
		}
	}
}

func TestBeliefModel_BaseModelReachableRaisesBelief(t *testing.T) {
	art, err := LoadModelArtifact(basePath)
	if err != nil {
		t.Fatal(err)
	}
	m, err := NewBeliefModel(art)
	if err != nil {
		t.Fatal(err)
	}
	low, err := m.Score(Evidence{Reachable: false}, nil)
	if err != nil {
		t.Fatal(err)
	}
	high, err := m.Score(Evidence{OpenPorts: []int{22, 443}, Services: []string{"22/ssh", "443/https"}, Reachable: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !(high.Exploitable > low.Exploitable) {
		t.Errorf("high.Exploitable=%v should exceed low.Exploitable=%v", high.Exploitable, low.Exploitable)
	}
	if !(high.Juicy > low.Juicy) {
		t.Errorf("high.Juicy=%v should exceed low.Juicy=%v", high.Juicy, low.Juicy)
	}
	if high.Reachable != 1.0 || low.Reachable != 0.0 {
		t.Errorf("reachable should be exact evidence: high=%v low=%v", high.Reachable, low.Reachable)
	}
}
