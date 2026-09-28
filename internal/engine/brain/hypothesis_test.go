// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"reflect"
	"testing"
)

// TestHypothesisObserved_CreatesNewHypothesis proves a first observation of a
// claim creates one Hypothesis node carrying exactly what was proposed.
func TestHypothesisObserved_CreatesNewHypothesis(t *testing.T) {
	w := NewWorld("t")

	Reduce(w, HypothesisObserved{
		MissionID:    "m1",
		RunID:        "run-1",
		ScopeID:      "s1",
		Proposer:     "recon-agent",
		Confidence:   0.6,
		Claim:        "port 6443 on this host is unauthenticated",
		HypothesisID: "hyp-6443",
		Technique:    "unauthenticated-service-probe",
		References: []ReferencedEntityRef{
			{Label: "Host", IDProperties: map[string]string{"address": "10.0.0.1"}},
		},
	})

	got := w.HypothesisSnapshot()
	want := []HypothesisSnapshot{
		{
			ID:         1,
			ScopeID:    "s1",
			Claim:      "port 6443 on this host is unauthenticated",
			Proposer:   "recon-agent",
			Confidence: 0.6,
			References: []ReferencedEntityRef{
				{Label: "Host", IDProperties: map[string]string{"address": "10.0.0.1"}},
			},
			MissionID:    "m1",
			RunID:        "run-1",
			HypothesisID: "hyp-6443",
			Technique:    "unauthenticated-service-probe",
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("hypothesis:\n got %+v\nwant %+v", got, want)
	}
}

// TestHypothesisObserved_MergesByScopeAndClaim proves a second observation of
// the same (ScopeID, Claim) enriches the existing node — the reducer's
// "creates/updates ... keyed by a stable id" contract (gibson#265) — rather
// than creating a duplicate. Proposer keeps the first attribution; Confidence
// takes the latest report, since it is the proposer's live estimate, not an
// identity signal.
func TestHypothesisObserved_MergesByScopeAndClaim(t *testing.T) {
	w := NewWorld("t")

	Reduce(w, HypothesisObserved{
		ScopeID: "s1", Proposer: "recon-agent", Confidence: 0.4,
		Claim: "the admin panel is reachable without auth",
	})
	Reduce(w, HypothesisObserved{
		ScopeID: "s1", Proposer: "second-agent", Confidence: 0.9,
		Claim: "the admin panel is reachable without auth",
	})

	got := w.HypothesisSnapshot()
	if len(got) != 1 {
		t.Fatalf("two observations of one claim must be one hypothesis, got %d: %+v", len(got), got)
	}
	if got[0].Proposer != "recon-agent" {
		t.Fatalf("proposer must keep the first attribution, got %q", got[0].Proposer)
	}
	if got[0].Confidence != 0.9 {
		t.Fatalf("confidence must take the latest report, got %v", got[0].Confidence)
	}
}

// TestHypothesisObserved_HypothesisIDAndRunIDKeepFirstNonEmpty proves
// HypothesisID, RunID and Technique follow the same progressive-enrichment
// rule as MissionID/Proposer: kept from whichever observation first supplied
// one, never overwritten by a later observation of the same claim.
// HypothesisID is the one join key across Hypothesis, Bet and BetSettlement
// (gibson#339) — an agent that proposes without an id and a second agent
// that re-observes the same claim WITH one must not have the second agent's
// id silently discarded (it is the only source of a bettable identity so
// far), but a hypothesis that already has an id must never have it
// reassigned out from under an in-flight Bet. Technique feeds reputation
// keying (gibson#333/#284) the same way, so a later, possibly-differently-
// labeled re-observation must not silently repoint reputation credit.
func TestHypothesisObserved_HypothesisIDAndRunIDKeepFirstNonEmpty(t *testing.T) {
	w := NewWorld("t")

	Reduce(w, HypothesisObserved{
		ScopeID: "s1", Claim: "the admin panel is reachable without auth",
	})
	Reduce(w, HypothesisObserved{
		ScopeID: "s1", Claim: "the admin panel is reachable without auth",
		HypothesisID: "hyp-admin-panel", RunID: "run-7", Technique: "auth-bypass-probe",
	})
	Reduce(w, HypothesisObserved{
		ScopeID: "s1", Claim: "the admin panel is reachable without auth",
		HypothesisID: "hyp-should-not-win", RunID: "run-should-not-win", Technique: "should-not-win",
	})

	got := w.HypothesisSnapshot()
	if len(got) != 1 {
		t.Fatalf("three observations of one claim must be one hypothesis, got %d: %+v", len(got), got)
	}
	if got[0].HypothesisID != "hyp-admin-panel" {
		t.Fatalf("hypothesis id must keep the first non-empty value, got %q", got[0].HypothesisID)
	}
	if got[0].RunID != "run-7" {
		t.Fatalf("run id must keep the first non-empty value, got %q", got[0].RunID)
	}
	if got[0].Technique != "auth-bypass-probe" {
		t.Fatalf("technique must keep the first non-empty value, got %q", got[0].Technique)
	}
}

// TestHypothesisObserved_DistinctScopesStayDistinct proves identity is the
// (ScopeID, Claim) pair: identical claim text in two different scopes (two
// different target networks) is two hypotheses, never one (ADR-0002).
func TestHypothesisObserved_DistinctScopesStayDistinct(t *testing.T) {
	w := NewWorld("t")

	Reduce(w, HypothesisObserved{ScopeID: "s1", Claim: "shared claim text"})
	Reduce(w, HypothesisObserved{ScopeID: "s2", Claim: "shared claim text"})

	if got := w.HypothesisSnapshot(); len(got) != 2 {
		t.Fatalf("identity is (scope, claim); want 2 hypotheses, got %d: %+v", len(got), got)
	}
}

// TestHypothesisObserved_ReferencesUnionAndNeverDuplicate mirrors
// TestEntityObserved_EdgesUnionAndNeverDuplicate: re-observing the same
// reference adds nothing, and a genuinely new one accretes.
func TestHypothesisObserved_ReferencesUnionAndNeverDuplicate(t *testing.T) {
	w := NewWorld("t")
	hostRef := ReferencedEntityRef{Label: "Host", IDProperties: map[string]string{"address": "10.0.0.1"}}
	pkgRef := ReferencedEntityRef{Label: "Package", IDProperties: map[string]string{"name": "lodash", "version": "4.17.20"}}

	Reduce(w, HypothesisObserved{ScopeID: "s1", Claim: "c", References: []ReferencedEntityRef{hostRef}})
	Reduce(w, HypothesisObserved{ScopeID: "s1", Claim: "c", References: []ReferencedEntityRef{hostRef, pkgRef}})

	got := w.HypothesisSnapshot()
	if len(got) != 1 {
		t.Fatalf("want 1 hypothesis, got %d", len(got))
	}
	want := []ReferencedEntityRef{hostRef, pkgRef}
	if !reflect.DeepEqual(got[0].References, want) {
		t.Fatalf("references:\n got %+v\nwant %+v", got[0].References, want)
	}
}

// TestHypothesisObserved_EmptyClaimIsIgnored proves a claim with no text
// records nothing: there would be no stable node for another agent to test.
func TestHypothesisObserved_EmptyClaimIsIgnored(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, HypothesisObserved{ScopeID: "s1", Claim: ""})
	if got := w.HypothesisSnapshot(); len(got) != 0 {
		t.Fatalf("empty claim must record nothing, got %+v", got)
	}
}

// TestHypothesisObserved_NeverTouchesBelief proves the Hypothesis provenance
// class is folded entirely separately from Evidence (Host) and Belief
// (belief.go): applying HypothesisObserved events creates or enriches
// Hypothesis entities only, never a Host, and never anything belief.go's math
// reads. This is gibson#265's "no change to existing belief math" criterion,
// and the ADR-0021 rule that a Hypothesis never sets a Belief.
func TestHypothesisObserved_NeverTouchesBelief(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, HypothesisObserved{ScopeID: "s1", Claim: "a claim about a host", Confidence: 0.8})

	if got := w.Snapshot(); len(got) != 0 {
		t.Fatalf("a Hypothesis must never create or touch a Host, got %+v", got)
	}
}

// TestHypothesisObserved_ReplayReproducesExactly mirrors
// TestAgentRun_FoldDedupEnrichReplay: replaying the Timeline reproduces the
// identical World, including ids, which is gibson#265's determinism
// criterion.
func TestHypothesisObserved_ReplayReproducesExactly(t *testing.T) {
	tl := &Timeline{}
	w := NewWorld("t")
	apply := func(ev Event) { tl.Append(ev); Reduce(w, ev) }

	apply(HypothesisObserved{ScopeID: "s1", Proposer: "a1", Confidence: 0.3, Claim: "claim one"})
	apply(HypothesisObserved{ScopeID: "s1", Proposer: "a2", Confidence: 0.7, Claim: "claim one"})
	apply(HypothesisObserved{ScopeID: "s1", Proposer: "a1", Confidence: 0.5, Claim: "claim two"})
	apply(HypothesisObserved{ScopeID: "s1", Claim: ""}) // ignored

	want := w.HypothesisSnapshot()
	if len(want) != 2 {
		t.Fatalf("want 2 hypotheses, got %d: %+v", len(want), want)
	}

	if replayed := Replay("t", tl).HypothesisSnapshot(); !reflect.DeepEqual(replayed, want) {
		t.Fatalf("replay mismatch:\n got %+v\nwant %+v", replayed, want)
	}
}

// TestSnapshotRestore_RoundTripsHypotheses mirrors
// TestSnapshotRestore_RoundTripsEntities: a World restored from a snapshot
// holds the same hypotheses and resumes the same id counter.
func TestSnapshotRestore_RoundTripsHypotheses(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, HypothesisObserved{
		ScopeID: "s1", MissionID: "m1", RunID: "run-1", Proposer: "recon-agent", Confidence: 0.6,
		Claim:        "port 6443 is unauthenticated",
		HypothesisID: "hyp-6443",
		Technique:    "unauthenticated-service-probe",
		References:   []ReferencedEntityRef{{Label: "Host", IDProperties: map[string]string{"address": "10.0.0.1"}}},
	})
	Reduce(w, HypothesisObserved{ScopeID: "s1", Claim: "a second claim"})

	restored, err := RestoreWorld(SnapshotWorld(w, "seq-1"), "t")
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if got, want := restored.HypothesisSnapshot(), w.HypothesisSnapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("hypotheses did not round-trip:\n got %+v\nwant %+v", got, want)
	}
	if restored.nextHypothesisID != w.nextHypothesisID {
		t.Fatalf("id counter must be restored exactly: got %d want %d",
			restored.nextHypothesisID, w.nextHypothesisID)
	}
}

// TestHypothesisObserved_Kind pins the durable Timeline codec key
// ("hypothesis.observed"). Changing this string would break replay of every
// already-persisted hypothesis event — see timeline_codec.go's registry.
func TestHypothesisObserved_Kind(t *testing.T) {
	if got := (HypothesisObserved{}).Kind(); got != "hypothesis.observed" {
		t.Fatalf("Kind() = %q, want %q", got, "hypothesis.observed")
	}
}
