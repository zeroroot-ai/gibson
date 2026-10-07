// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"context"
	"strings"
	"testing"
	"time"
)

func reviewEvent(hypothesisID, content string) BetProofSubmittedForReview {
	return BetProofSubmittedForReview{
		HypothesisID: hypothesisID, MissionID: "m1", ScopeID: "s1", Technique: "T1190",
		Evidence:            []ProofReviewEvidence{{Type: "EVIDENCE_TYPE_LOG", Title: "proof", Content: content}},
		SubmittedAtUnixNano: 7,
	}
}

// A proof that waits for a review is in the snapshot until its bet settles,
// the latest submission replaces an earlier one, and the list survives a
// snapshot round trip.
func TestProofReview_PendingUntilTheBetSettles(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, reviewEvent("hyp-1", "first"))
	Reduce(w, reviewEvent("hyp-1", "second"))
	Reduce(w, reviewEvent("hyp-2", "other"))
	Reduce(w, BetProofSubmittedForReview{MissionID: "m1"}) // no hypothesis: ignored

	got := w.ProofReviewSnapshot()
	if len(got) != 2 || got[0].HypothesisID != "hyp-1" || got[0].Evidence[0].Content != "second" {
		t.Fatalf("snapshot = %+v", got)
	}

	restored, err := RestoreWorld(SnapshotWorld(w, "seq-1"), "t")
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if again := restored.ProofReviewSnapshot(); len(again) != 2 || again[0].Evidence[0].Content != "second" {
		t.Fatalf("after restore = %+v", again)
	}

	Reduce(w, BetSettledByHITL{HypothesisID: "hyp-1", Verdict: SettlementVerdictTrue, UserID: "reviewer"})
	left := w.ProofReviewSnapshot()
	if len(left) != 1 || left[0].HypothesisID != "hyp-2" {
		t.Fatalf("a settled bet must leave the review list, got %+v", left)
	}
}

// The event belongs to the mission whose agent submitted the proof.
func TestProofReview_MissionScope(t *testing.T) {
	if !eventInMission(reviewEvent("hyp-1", "x"), "m1", nil) {
		t.Fatal("the event must be in the frame of its own mission")
	}
	if eventInMission(reviewEvent("hyp-1", "x"), "m2", nil) {
		t.Fatal("the event must not be in the frame of another mission")
	}
}

// The engine refuses a review request with no hypothesis, with no evidence,
// and over each bound.
func TestEngine_SubmitProofForReview_Refusals(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e := NewRegistry(ctx, memStoreFactory()).For("t")

	item := ProofReviewEvidence{Content: "x"}
	many := make([]ProofReviewEvidence, MaxProofReviewEvidenceItems+1)
	cases := map[string]ProofReviewRequest{
		"no hypothesis":  {Evidence: []ProofReviewEvidence{item}},
		"no evidence":    {HypothesisID: "hyp-1"},
		"too many items": {HypothesisID: "hyp-1", Evidence: many},
		"item too large": {HypothesisID: "hyp-1", Evidence: []ProofReviewEvidence{{Content: strings.Repeat("a", MaxProofReviewEvidenceBytes+1)}}},
	}
	for name, req := range cases {
		if err := e.SubmitProofForReview(ctx, req); err == nil {
			t.Errorf("%s: want a refusal", name)
		}
	}
	if err := e.SubmitProofForReview(ctx, ProofReviewRequest{HypothesisID: "hyp-1", Evidence: []ProofReviewEvidence{item}}); err != nil {
		t.Fatalf("a valid request: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for len(e.ProofReviews()) != 1 {
		if time.Now().After(deadline) {
			t.Fatal("the review never reached the world")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// RecordedToolCalls returns records in the order asked, and reports an
// unknown id and the id of another mission's call as missing.
func TestEngine_RecordedToolCalls(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e := NewRegistry(ctx, memStoreFactory()).For("t")
	e.Submit(AgentToolCallObserved{ToolCallID: "a", MissionID: "m1", Result: "ra"})
	e.Submit(AgentToolCallObserved{ToolCallID: "b", MissionID: "m1", Result: "rb"})
	e.Submit(AgentToolCallObserved{ToolCallID: "c", MissionID: "m2", Result: "rc"})
	deadline := time.Now().Add(2 * time.Second)
	for len(e.AgentToolCalls()) != 3 {
		if time.Now().After(deadline) {
			t.Fatal("the tool calls never reached the world")
		}
		time.Sleep(5 * time.Millisecond)
	}

	found, missing := e.RecordedToolCalls("m1", []string{"b", "nope", "a", "c"})
	if len(found) != 2 || found[0].ToolCallID != "b" || found[1].Result != "ra" {
		t.Fatalf("found = %+v", found)
	}
	if len(missing) != 2 || missing[0] != "nope" || missing[1] != "c" {
		t.Fatalf("missing = %v", missing)
	}
}
