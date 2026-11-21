// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"strconv"
	"testing"
	"time"

	typespb "github.com/zeroroot-ai/sdk/api/gen/gibson/types/v1"
)

func recordedAt(t time.Time) *typespb.Evidence {
	return &typespb.Evidence{
		Tier:     typespb.EvidenceTier_EVIDENCE_TIER_RECORDED,
		Metadata: map[string]string{recordedAtKey: strconv.FormatInt(t.UnixNano(), 10)},
	}
}

// The daemon's own evaluation of an attack predicate is the rerun of the check
// of each fixed Finding that the predicate raised on the target (review M11).
// A predicate that no longer holds on evidence newer than the deploy verifies
// the fix. Text that an agent typed, another predicate and another target give
// no rerun.
func TestPredicateReruns_VerifyAFixOnNewerEvidence(t *testing.T) {
	w := NewWorld("t1")
	w.clock = func() time.Time { return testScanTime }
	Reduce(w, FindingRaised{ID: "f1", ScopeID: "target-a", CheckKind: "predicate", CheckRef: "unauthenticated_endpoint_exposed"})
	Reduce(w, FindingRaised{ID: "other-target", ScopeID: "target-b", CheckKind: "predicate", CheckRef: "unauthenticated_endpoint_exposed"})
	Reduce(w, FindingRaised{ID: "other-check", ScopeID: "target-a", CheckKind: "predicate", CheckRef: "node_token_readable"})
	for _, id := range []string{"f1", "other-target", "other-check"} {
		walk(w, id, FindingStatusFixed, "mr-"+id)
		Reduce(w, DeployObserved{MergeRequest: "mr-" + id, At: testDeployTime})
		Reduce(w, HealthObserved{MergeRequest: "mr-" + id, Held: true, At: testDeployTime})
	}

	typed := &typespb.Evidence{Tier: typespb.EvidenceTier_EVIDENCE_TIER_TYPED}
	if evs := predicateReruns(w.FindingSnapshot(), "unauthenticated_endpoint_exposed", "target-a", "m2", false,
		[]*typespb.Evidence{recordedAt(testScanTime), typed}); len(evs) != 0 {
		t.Fatalf("typed evidence gave a rerun: %+v", evs)
	}

	evs := predicateReruns(w.FindingSnapshot(), "unauthenticated_endpoint_exposed", "target-a", "m2", false,
		[]*typespb.Evidence{recordedAt(testScanTime), recordedAt(testScanTime.Add(time.Minute))})
	if len(evs) != 1 || evs[0].(CheckRerun).ID != "f1" || !evs[0].(CheckRerun).EvidenceAt.Equal(testScanTime) {
		t.Fatalf("reruns = %+v, want one for f1 at the oldest call", evs)
	}
	applyAll(w, evs)
	applyAll(w, VerificationSystem(w))
	if got := findingByID(t, w, "f1").Status; got != FindingStatusVerified {
		t.Fatalf("status = %q, want verified", got)
	}
	if got := findingByID(t, w, "other-target").Status; got != FindingStatusFixed {
		t.Fatalf("another target moved to %q", got)
	}
}

// A predicate that still holds after the deploy opens the Finding again. A
// call older than the deploy decides nothing.
func TestPredicateReruns_FoundAgainOpensAndOldEvidenceDecidesNothing(t *testing.T) {
	for _, tc := range []struct {
		at   time.Time
		want string
	}{{testScanTime, FindingStatusOpen}, {testDeployTime.Add(-time.Minute), FindingStatusFixed}} {
		w := NewWorld("t1")
		w.clock = func() time.Time { return testScanTime }
		Reduce(w, FindingRaised{ID: "f1", ScopeID: "target-a", CheckKind: "predicate", CheckRef: "p"})
		walk(w, "f1", FindingStatusFixed, "mr-1")
		Reduce(w, DeployObserved{MergeRequest: "mr-1", At: testDeployTime})
		Reduce(w, HealthObserved{MergeRequest: "mr-1", Held: true, At: testDeployTime})
		applyAll(w, predicateReruns(w.FindingSnapshot(), "p", "target-a", "m2", true, []*typespb.Evidence{recordedAt(tc.at)}))
		applyAll(w, VerificationSystem(w))
		if got := findingByID(t, w, "f1").Status; got != tc.want {
			t.Fatalf("evidence at %v: status = %q, want %q", tc.at, got, tc.want)
		}
	}
}
