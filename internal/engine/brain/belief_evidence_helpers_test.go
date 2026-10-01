// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import "testing"

// belief_evidence_helpers_test.go unit-tests the per-host evidence gathering the
// belief gate uses (gibson#478): which findings and which demonstrated exploits
// correlate to which host, branch by branch.

// TestFindingSeverityByHost exercises every branch of findingSeverityByHost: a
// critical and a high finding on real hosts, a fixed/verified finding that is
// excluded, a finding with no address that cannot correlate, and two findings on
// one host whose severities both register.
func TestFindingSeverityByHost(t *testing.T) {
	w := NewWorld("t")
	apply := func(e Event) { Reduce(w, e) }

	// A critical finding on host A.
	apply(FindingRaised{ID: "f-crit", ScopeID: "s", Address: "10.0.0.1", Severity: "critical"})
	// A high (not critical) finding on host B — with mixed case, to prove the
	// severity match is case-insensitive.
	apply(FindingRaised{ID: "f-high", ScopeID: "s", Address: "10.0.0.2", Severity: "HIGH"})
	// A critical finding that has been remediated (verified) on host C: excluded.
	apply(FindingRaised{ID: "f-fixed", ScopeID: "s", Address: "10.0.0.3", Severity: "critical", Status: FindingStatusVerified})
	// A critical finding whose status is "fixed": also excluded.
	apply(FindingRaised{ID: "f-fixed2", ScopeID: "s", Address: "10.0.0.4", Severity: "critical", Status: FindingStatusFixed})
	// A finding with no address cannot correlate to a host: skipped.
	apply(FindingRaised{ID: "f-noaddr", ScopeID: "s", Address: "", Severity: "critical"})
	// A medium finding does not raise either flag.
	apply(FindingRaised{ID: "f-med", ScopeID: "s", Address: "10.0.0.5", Severity: "medium"})
	// Host D carries both a critical and a high finding: both flags register
	// (they are independent noisy-OR causes, not a single highest-severity pick).
	apply(FindingRaised{ID: "f-both-c", ScopeID: "s", Address: "10.0.0.6", Severity: "critical"})
	apply(FindingRaised{ID: "f-both-h", ScopeID: "s", Address: "10.0.0.6", Severity: "high"})
	// Same address, different scope: a distinct host key (scope-relative identity).
	apply(FindingRaised{ID: "f-otherscope", ScopeID: "s2", Address: "10.0.0.1", Severity: "high"})

	critical, high := findingSeverityByHost(w)

	keyA := hostEvidenceKey("s", "10.0.0.1")
	keyB := hostEvidenceKey("s", "10.0.0.2")
	keyC := hostEvidenceKey("s", "10.0.0.3")
	keyFixed := hostEvidenceKey("s", "10.0.0.4")
	keyMed := hostEvidenceKey("s", "10.0.0.5")
	keyD := hostEvidenceKey("s", "10.0.0.6")
	keyOther := hostEvidenceKey("s2", "10.0.0.1")

	if !critical[keyA] || high[keyA] {
		t.Errorf("host A: want critical only, got critical=%v high=%v", critical[keyA], high[keyA])
	}
	if critical[keyB] || !high[keyB] {
		t.Errorf("host B: want high only, got critical=%v high=%v", critical[keyB], high[keyB])
	}
	if critical[keyC] || high[keyC] {
		t.Errorf("verified finding must be excluded, got critical=%v high=%v", critical[keyC], high[keyC])
	}
	if critical[keyFixed] || high[keyFixed] {
		t.Errorf("fixed finding must be excluded, got critical=%v high=%v", critical[keyFixed], high[keyFixed])
	}
	if critical[keyMed] || high[keyMed] {
		t.Errorf("medium finding must raise neither flag, got critical=%v high=%v", critical[keyMed], high[keyMed])
	}
	if !critical[keyD] || !high[keyD] {
		t.Errorf("host D with both severities: want both flags, got critical=%v high=%v", critical[keyD], high[keyD])
	}
	if critical[keyOther] || !high[keyOther] {
		t.Errorf("same address, other scope must be a distinct host key: got critical=%v high=%v", critical[keyOther], high[keyOther])
	}
	// The empty-address finding must not have produced a key.
	if critical[hostEvidenceKey("s", "")] {
		t.Errorf("a finding with no address must not produce a host key")
	}
}

// TestDemonstratedExploitByHost exercises every branch of
// demonstratedExploitByHost: a TRUE settlement whose hypothesis references a
// host is counted, a FALSE settlement is not, a TRUE settlement with no matching
// hypothesis is skipped, a hypothesis with no join id is not indexed, and an
// empty reference value is ignored.
func TestDemonstratedExploitByHost(t *testing.T) {
	w := NewWorld("t")
	apply := func(e Event) { Reduce(w, e) }

	// A hypothesis about host 10.0.0.1, joined by HypothesisID, then a TRUE
	// settlement of that bet: the exploit is demonstrated on that host.
	apply(HypothesisObserved{
		ScopeID: "s", Claim: "escape on .1", HypothesisID: "hyp-true",
		References: []ReferencedEntityRef{{Label: "Host", IDProperties: map[string]string{"address": "10.0.0.1", "noise": ""}}},
	})
	apply(BetSettledTrue{HypothesisID: "hyp-true", ScopeID: "s"})

	// A hypothesis about host 10.0.0.2 whose bet settled FALSE: not counted.
	apply(HypothesisObserved{
		ScopeID: "s", Claim: "escape on .2", HypothesisID: "hyp-false",
		References: []ReferencedEntityRef{{Label: "Host", IDProperties: map[string]string{"address": "10.0.0.2"}}},
	})
	apply(BetSettledFalse{HypothesisID: "hyp-false"})

	// A TRUE settlement whose HypothesisID has no hypothesis in the world: the
	// join fails, so nothing is marked.
	apply(BetSettledTrue{HypothesisID: "hyp-orphan", ScopeID: "s"})

	// A hypothesis with no HypothesisID is never indexed, so even a TRUE
	// settlement (which could never name it) resolves to nothing.
	apply(HypothesisObserved{
		ScopeID: "s", Claim: "unjoinable", HypothesisID: "",
		References: []ReferencedEntityRef{{Label: "Host", IDProperties: map[string]string{"address": "10.0.0.9"}}},
	})

	out := demonstratedExploitByHost(w)

	if !out[hostEvidenceKey("s", "10.0.0.1")] {
		t.Errorf("a TRUE settlement must mark the referenced host as exploited")
	}
	if out[hostEvidenceKey("s", "10.0.0.2")] {
		t.Errorf("a FALSE settlement must not mark the host as exploited")
	}
	if out[hostEvidenceKey("s", "10.0.0.9")] {
		t.Errorf("a hypothesis with no join id must not resolve to an exploited host")
	}
	// The empty "noise" reference value must have been ignored, not turned into
	// a (scope, "") key.
	if out[hostEvidenceKey("s", "")] {
		t.Errorf("an empty reference value must be ignored")
	}
	// Exactly one host is marked.
	if len(out) != 1 {
		t.Errorf("want exactly one exploited host, got %d: %v", len(out), out)
	}
}
