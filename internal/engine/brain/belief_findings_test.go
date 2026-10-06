// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/brain/beliefvi"
)

// belief_findings_test.go is the belief-evidence seam (ADR-0129, gibson#478):
// findings and demonstrated exploits reach the belief network, and exploitable
// steers the Decider's host ordering.

// nativeProvider builds the real in-process provider over the embedded base-v1
// model — the one the daemon scores against — so these tests exercise the
// shipped model artifact, not a stand-in.
func nativeProvider(t *testing.T) BeliefProvider {
	t.Helper()
	art, err := beliefvi.DefaultArtifact()
	if err != nil {
		t.Fatalf("default artifact: %v", err)
	}
	model, err := beliefvi.NewBeliefModel(art)
	if err != nil {
		t.Fatalf("build model: %v", err)
	}
	return NativeBeliefProvider(model, nil)
}

// TestExploitable_CriticalFindingRaisesIt is gibson#478's first acceptance
// criterion: a host with one confirmed critical finding scores higher on
// exploitable than an identical host with none.
func TestExploitable_CriticalFindingRaisesIt(t *testing.T) {
	p := nativeProvider(t)

	base := BeliefEvidence{OpenPorts: []int{22}, Services: []string{"22/ssh"}, Reachable: true}
	withCritical := base
	withCritical.FindingCritical = true

	none := p.Score(base)
	crit := p.Score(withCritical)

	if !(crit.Exploitable > none.Exploitable) {
		t.Fatalf("a critical finding must raise exploitable: with=%v without=%v",
			crit.Exploitable, none.Exploitable)
	}

	// Parity: the no-finding host must score exactly as it did before the
	// finding evidence existed — a false noisy-OR cause contributes nothing.
	legacy := p.Score(BeliefEvidence{OpenPorts: []int{22}, Services: []string{"22/ssh"}, Reachable: true})
	if none.Exploitable != legacy.Exploitable {
		t.Fatalf("no-finding posterior drifted: %v != %v", none.Exploitable, legacy.Exploitable)
	}
}

// TestBeliefRecomputes_WhenFindingLandsNotOtherwise is gibson#478's second
// acceptance criterion: a belief score is recomputed when a finding lands on a
// host, and not otherwise (the evidence digest still suppresses no-op requests).
func TestBeliefRecomputes_WhenFindingLandsNotOtherwise(t *testing.T) {
	p := &countingBelief{}
	e, bw := beliefEngine(p)

	e.Submit(HostObserved{ScopeID: "s", Address: "10.0.0.5", OpenPorts: []int{22}})
	settle(e, bw, 3)
	if got := p.count(); got != 1 {
		t.Fatalf("one host, one evidence shape => 1 score, got %d", got)
	}

	// A critical finding lands on the host: its evidence changes, so the belief
	// recomputes exactly once more.
	e.Submit(FindingRaised{ID: "f1", ScopeID: "s", Address: "10.0.0.5", Severity: "critical"})
	settle(e, bw, 3)
	if got := p.count(); got != 2 {
		t.Fatalf("a finding landing must recompute the belief once: got %d, want 2", got)
	}

	// A finding on a DIFFERENT address, and a re-raise of the same finding,
	// change nothing about this host's evidence: the digest suppresses both.
	e.Submit(FindingRaised{ID: "f2", ScopeID: "s", Address: "10.0.0.99", Severity: "high"})
	e.Submit(FindingRaised{ID: "f1", ScopeID: "s", Address: "10.0.0.5", Severity: "critical"})
	settle(e, bw, 3)
	if got := p.count(); got != 2 {
		t.Fatalf("a no-op finding must not re-score: got %d, want 2", got)
	}
}

// TestExploitable_SteersAmbientOrder is gibson#478's third acceptance
// criterion, proven on the projection (AmbientProjection) rather than on the
// sidecar: exploitable changes the host order the Decider sees.
func TestExploitable_SteersAmbientOrder(t *testing.T) {
	// Two hosts, identical juicy, different exploitable. Attention is derived
	// exactly as the World snapshot derives it (attentionScore).
	lowAddr, highAddr := "10.0.0.1", "10.0.0.2"
	host := func(addr string, exploitable float64) HostSnapshot {
		b := Belief{Juicy: 0.5, Exploitable: exploitable}
		return HostSnapshot{
			ScopeID: "s", Address: addr, Belief: b,
			Attention: attentionScore(b.Juicy, b.Exploitable, false),
		}
	}

	// The more-exploitable host ranks first even though it sorts LAST by the
	// address tiebreak — exploitable, not the tiebreak, decides the order.
	kept, _ := AmbientProjection([]HostSnapshot{host(lowAddr, 0.1), host(highAddr, 0.9)}, 0)
	if kept[0].Address != highAddr {
		t.Fatalf("the more-exploitable host must rank first, got order %q then %q",
			kept[0].Address, kept[1].Address)
	}

	// Control: with exploitable equal, the stable address tiebreak decides, so
	// the ordering flip above is attributable to exploitable alone.
	ctrl, _ := AmbientProjection([]HostSnapshot{host(lowAddr, 0.5), host(highAddr, 0.5)}, 0)
	if ctrl[0].Address != lowAddr {
		t.Fatalf("with equal exploitable the address tiebreak must decide, got %q first", ctrl[0].Address)
	}
}

// BeliefEvidenceByHost gives each host the evidence that BeliefSystem
// scores, keyed by the host id (gibson#614).
func TestBeliefEvidenceByHost_MatchesTheScoredEvidence(t *testing.T) {
	w := NewWorld("acme")
	Reduce(w, HostObserved{ScopeID: "s1", Address: "10.0.0.1", OpenPorts: []int{22},
		Services: map[int]ServiceInfo{22: {Name: "ssh"}}})
	hosts := w.Snapshot()
	if len(hosts) != 1 {
		t.Fatalf("want 1 host, got %d", len(hosts))
	}
	ev, ok := w.BeliefEvidenceByHost()[hosts[0].ID]
	if !ok {
		t.Fatal("the host has no evidence")
	}
	events := BeliefSystem(w)
	requested := make([]BeliefEvidence, 0, len(events))
	for _, e := range events {
		requested = append(requested, e.(BeliefScoreRequested).Evidence)
	}
	if len(requested) != 1 || evidenceDigest(requested[0]) != evidenceDigest(ev) {
		t.Fatalf("evidence %+v differs from the scored evidence %+v", ev, requested)
	}
	if !ev.Reachable || len(ev.Services) != 1 || ev.Services[0] != "22/ssh" {
		t.Errorf("evidence = %+v, want reachable with 22/ssh", ev)
	}
}
