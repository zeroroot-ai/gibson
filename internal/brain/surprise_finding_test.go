package brain

import "testing"

// A strong-signal identity contradiction (same address, different SSH host key)
// raises a Surprise, which the surprise→Finding pipeline promotes to a Finding.
func TestSurpriseFindingSystem_PromotesIdentityAnomaly(t *testing.T) {
	e := NewEngine("t1")
	e.AddSystem(SurpriseFindingSystem)

	// First host at 10.0.0.5 with host key A.
	e.Submit(HostObserved{ScopeID: "s1", Address: "10.0.0.5", SSHHostKey: "AAAA"})
	// A different host reuses 10.0.0.5 with host key B → contradiction → Surprise.
	e.Submit(HostObserved{ScopeID: "s1", Address: "10.0.0.5", SSHHostKey: "BBBB"})
	e.Tick()

	// A surprised host exists.
	var surprised bool
	for _, h := range e.Hosts() {
		if h.Surprise != "" {
			surprised = true
			if h.Attention < surpriseBoost {
				t.Errorf("surprised host should have attention >= surpriseBoost, got %v", h.Attention)
			}
		}
	}
	if !surprised {
		t.Fatalf("expected a surprised host from the contradiction; hosts=%+v", e.Hosts())
	}

	// The surprise was promoted to a Finding.
	fs := e.Findings()
	if len(fs) != 1 {
		t.Fatalf("expected exactly one anomaly finding, got %d (%+v)", len(fs), fs)
	}
	if fs[0].Severity != "medium" || fs[0].Address != "10.0.0.5" {
		t.Errorf("anomaly finding wrong: %+v", fs[0])
	}
}

// The pipeline is idempotent + quiescent: re-ticking raises no duplicate finding.
func TestSurpriseFindingSystem_Idempotent(t *testing.T) {
	e := NewEngine("t1")
	e.AddSystem(SurpriseFindingSystem)
	e.Submit(HostObserved{ScopeID: "s1", Address: "10.0.0.5", SSHHostKey: "AAAA"})
	e.Submit(HostObserved{ScopeID: "s1", Address: "10.0.0.5", SSHHostKey: "BBBB"})
	e.Tick()
	if n := len(e.Findings()); n != 1 {
		t.Fatalf("want 1 finding, got %d", n)
	}
	if applied := e.Tick(); applied != 0 {
		t.Fatalf("system not quiescent: extra tick applied %d events", applied)
	}
	if n := len(e.Findings()); n != 1 {
		t.Fatalf("idempotent: still want 1 finding, got %d", n)
	}
}

// No surprise → no anomaly finding.
func TestSurpriseFindingSystem_NoSurpriseNoFinding(t *testing.T) {
	e := NewEngine("t1")
	e.AddSystem(SurpriseFindingSystem)
	e.Submit(HostObserved{ScopeID: "s1", Address: "10.0.0.5", SSHHostKey: "AAAA"})
	e.Tick()
	if n := len(e.Findings()); n != 0 {
		t.Fatalf("no contradiction should raise no finding, got %d", n)
	}
}
