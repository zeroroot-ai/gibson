package braintrain

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
)

// minimal base artifact mirroring sidecar/belief/models/base-v1.json structure.
func testBase(t *testing.T, dir string) string {
	t.Helper()
	const base = `{
  "version": "base-v1",
  "variables": ["reachable", "svc_ssh", "exploitable", "juicy"],
  "edges": [["reachable","exploitable"],["svc_ssh","exploitable"],["reachable","juicy"],["exploitable","juicy"]],
  "cpds": {
    "reachable": {"values": [[0.5],[0.5]]},
    "svc_ssh": {"values": [[0.7],[0.3]]},
    "exploitable": {"evidence":["reachable","svc_ssh"],"evidence_card":[2,2],"values":[[0.9,0.7,0.6,0.3],[0.1,0.3,0.4,0.7]]},
    "juicy": {"evidence":["reachable","exploitable"],"evidence_card":[2,2],"values":[[0.95,0.55,0.7,0.2],[0.05,0.45,0.3,0.8]]}
  }
}`
	p := filepath.Join(dir, "base-v1.json")
	if err := os.WriteFile(p, []byte(base), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestFit_ProducesValidArtifactInSidecarFormat(t *testing.T) {
	dir := t.TempDir()
	base, err := LoadArtifact(testBase(t, dir))
	if err != nil {
		t.Fatal(err)
	}
	rows := []Row{
		{"reachable": true, "svc_ssh": true, "exploitable": true, "juicy": true},
		{"reachable": true, "svc_ssh": false, "exploitable": false, "juicy": false},
		{"reachable": false, "svc_ssh": false, "exploitable": false, "juicy": false},
	}
	a, err := Fit(base, rows, "tenant-acme-v1")
	if err != nil {
		t.Fatalf("Fit: %v", err)
	}
	// Same structure as base.
	if len(a.Variables) != len(base.Variables) || len(a.Edges) != len(base.Edges) {
		t.Errorf("trained model should preserve base structure")
	}
	// Each child CPT has 2^|parents| columns and exactly two state rows summing ~1.
	exp := a.CPDs["exploitable"]
	if len(exp.Evidence) != 2 || len(exp.Values) != 2 || len(exp.Values[0]) != 4 {
		t.Fatalf("exploitable CPT wrong shape: %+v", exp)
	}
	for c := 0; c < 4; c++ {
		sum := exp.Values[0][c] + exp.Values[1][c]
		if sum < 0.99 || sum > 1.01 {
			t.Errorf("column %d does not sum to 1: %v", c, sum)
		}
	}
	// Roots have a single column.
	if len(a.CPDs["reachable"].Values[0]) != 1 {
		t.Errorf("root reachable CPT should have one column")
	}
}

func TestFit_SmoothingKeepsTablesNonDegenerate(t *testing.T) {
	dir := t.TempDir()
	base, _ := LoadArtifact(testBase(t, dir))
	// All-positive data — without smoothing P(true)=1 (degenerate; pgmpy-illegal).
	rows := []Row{{"reachable": true, "svc_ssh": true, "exploitable": true, "juicy": true}}
	a, _ := Fit(base, rows, "tenant-acme-v1")
	for v, cpd := range a.CPDs {
		for _, col := range cpd.Values {
			for _, p := range col {
				if p <= 0 || p >= 1 {
					t.Errorf("%s has a degenerate entry %v (smoothing failed)", v, p)
				}
			}
		}
	}
}

func TestFit_CountsConditionalFrequency(t *testing.T) {
	dir := t.TempDir()
	base, _ := LoadArtifact(testBase(t, dir))
	// Many rows where reachable=false,svc_ssh=false ⇒ exploitable nearly always
	// false; the smoothed P(true|...) for that column should be low.
	var rows []Row
	for i := 0; i < 20; i++ {
		rows = append(rows, Row{"reachable": false, "svc_ssh": false, "exploitable": false, "juicy": false})
	}
	a, _ := Fit(base, rows, "tenant-acme-v1")
	exp := a.CPDs["exploitable"]
	// Column for (reachable=false, svc_ssh=false) is index 0 (both low bits 0).
	pTrue := exp.Values[1][0]
	if pTrue > 0.1 {
		t.Errorf("P(exploitable=true | not reachable, no ssh) should be low, got %v", pTrue)
	}
}

func TestNextVersion_BumpsPastExisting(t *testing.T) {
	dir := t.TempDir()
	if v := NextVersion(dir, "acme"); v != "tenant-acme-v1" {
		t.Errorf("empty dir should start at v1, got %q", v)
	}
	os.WriteFile(filepath.Join(dir, "tenant-acme-v1.json"), []byte("{}"), 0o644)
	os.WriteFile(filepath.Join(dir, "tenant-acme-v2.json"), []byte("{}"), 0o644)
	if v := NextVersion(dir, "acme"); v != "tenant-acme-v3" {
		t.Errorf("should bump to v3, got %q", v)
	}
	// A different tenant is independent.
	if v := NextVersion(dir, "other"); v != "tenant-other-v1" {
		t.Errorf("other tenant should be v1, got %q", v)
	}
}

// TrainTenant end-to-end: a Timeline with a Finding + a label produces a written,
// reloadable, versioned per-tenant artifact.
func TestTrainTenant_EndToEnd(t *testing.T) {
	dir := t.TempDir()
	basePath := testBase(t, dir)
	modelsDir := filepath.Join(dir, "models")

	// Build a tenant Timeline: a host with an identity contradiction (→ Finding)
	// that a reviewer labels true_positive.
	e := brain.NewEngine("acme")
	e.AddSystem(brain.SurpriseFindingSystem)
	e.Submit(brain.HostObserved{ScopeID: "s1", Address: "10.0.0.5", SSHHostKey: "AAAA", OpenPorts: []int{22}})
	e.Submit(brain.HostObserved{ScopeID: "s1", Address: "10.0.0.5", SSHHostKey: "BBBB", OpenPorts: []int{22}})
	e.Tick()
	fs := e.Findings()
	if len(fs) == 0 {
		t.Fatal("expected a finding")
	}
	e.Submit(brain.LabelApplied{TargetID: fs[0].ID, Verdict: brain.VerdictTruePositive, UserID: "alice"})
	e.Tick()

	res, err := TrainTenant("acme", e.Events(), basePath, modelsDir)
	if err != nil {
		t.Fatalf("TrainTenant: %v", err)
	}
	if res.Version != "tenant-acme-v1" {
		t.Errorf("first run should be v1, got %q", res.Version)
	}
	if res.Rows == 0 {
		t.Error("expected at least one training row from the labelled finding")
	}
	// The artifact is on disk and reloads + validates.
	reloaded, err := LoadArtifact(res.Path)
	if err != nil {
		t.Fatalf("reload trained artifact: %v", err)
	}
	if reloaded.Version != "tenant-acme-v1" {
		t.Errorf("reloaded version mismatch: %q", reloaded.Version)
	}

	// A second run bumps the version and never overwrites v1.
	res2, err := TrainTenant("acme", e.Events(), basePath, modelsDir)
	if err != nil {
		t.Fatal(err)
	}
	if res2.Version != "tenant-acme-v2" {
		t.Errorf("second run should be v2, got %q", res2.Version)
	}
	if _, err := os.Stat(res.Path); err != nil {
		t.Errorf("v1 artifact must survive a re-train: %v", err)
	}
}

// Tenant isolation: training tenant A's Timeline never produces an artifact for
// or influenced by tenant B (structural — the trainer is handed one tenant's log).
func TestTrainTenant_PerTenantArtifactNaming(t *testing.T) {
	dir := t.TempDir()
	basePath := testBase(t, dir)
	modelsDir := filepath.Join(dir, "models")

	a := brain.NewEngine("acme")
	a.Submit(brain.LabelApplied{TargetID: "anomaly-host-1", Verdict: brain.VerdictTruePositive, UserID: "u"})
	a.Tick()

	res, err := TrainTenant("acme", a.Events(), basePath, modelsDir)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(res.Path) != "tenant-acme-v1.json" {
		t.Errorf("artifact must be named per-tenant, got %q", filepath.Base(res.Path))
	}
	// No artifact named for any other tenant exists.
	entries, _ := os.ReadDir(modelsDir)
	for _, ent := range entries {
		if ent.Name() != "tenant-acme-v1.json" {
			t.Errorf("unexpected cross-tenant artifact: %q", ent.Name())
		}
	}
}
