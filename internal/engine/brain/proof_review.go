// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/mlange-42/ark/ecs"
)

// A proof reaches the daemon in one of two forms (ADR-0131). It names tool
// calls the daemon itself recorded, and then the daemon evaluates the pack
// predicate on its own record. Or it carries evidence the agent typed, and
// then no predicate runs on it: the daemon has no record of where that text
// came from, so a human reviews it and settles the bet with SettleBetByHITL.
// This file is the second form: the record a reviewer reads.

// Bounds on one proof sent for review. A submission over a bound is refused,
// never truncated: a reviewer must see what the agent sent.
const (
	MaxProofReviewEvidenceItems = 16
	MaxProofReviewEvidenceBytes = 64 << 10
)

// ProofReviewEvidence is one item of evidence as the agent typed it.
type ProofReviewEvidence struct {
	Type    string
	Title   string
	Content string
}

// ProofReviewRequest asks for a human review of a proof that carries only
// agent-typed evidence.
type ProofReviewRequest struct {
	HypothesisID string
	MissionID    string
	ScopeID      string
	Technique    string
	Evidence     []ProofReviewEvidence
	// SubmittedAtUnixNano is the daemon's receipt time.
	SubmittedAtUnixNano int64
}

// BetProofSubmittedForReview records that an agent submitted a proof with
// typed evidence for HypothesisID. It settles nothing.
type BetProofSubmittedForReview struct {
	HypothesisID        string
	MissionID           string
	ScopeID             string
	Technique           string
	Evidence            []ProofReviewEvidence
	SubmittedAtUnixNano int64
}

// Kind identifies this event on the Timeline.
func (BetProofSubmittedForReview) Kind() string { return "bet.proof_submitted_for_review" }

// applyBetProofSubmittedForReview keeps the latest submission for a
// hypothesis. Content is redacted by the tenant's flight recorder policy at
// fold time, the same rule a recorded tool call follows.
func applyBetProofSubmittedForReview(w *World, e BetProofSubmittedForReview) {
	if e.HypothesisID == "" {
		return
	}
	evidence := make([]ProofReviewEvidence, len(e.Evidence))
	for i, item := range e.Evidence {
		evidence[i] = ProofReviewEvidence{
			Type:    item.Type,
			Title:   item.Title,
			Content: redactForTenant(w, item.Content),
		}
	}
	w.proofReviews[e.HypothesisID] = BetProofSubmittedForReview{
		HypothesisID:        e.HypothesisID,
		MissionID:           e.MissionID,
		ScopeID:             e.ScopeID,
		Technique:           e.Technique,
		Evidence:            evidence,
		SubmittedAtUnixNano: e.SubmittedAtUnixNano,
	}
}

// ProofReviewSnapshot is a stable view of one proof that waits for a review.
type ProofReviewSnapshot struct {
	HypothesisID        string                `json:"hypothesis_id"`
	MissionID           string                `json:"mission_id"`
	ScopeID             string                `json:"scope_id"`
	Technique           string                `json:"technique"`
	Evidence            []ProofReviewEvidence `json:"evidence"`
	SubmittedAtUnixNano int64                 `json:"submitted_at_unix_nano"`
}

// ProofReviewSnapshot returns the proofs that wait for a review, in
// HypothesisID order. A hypothesis whose bet is settled, by any method, no
// longer waits and is not in the list.
func (w *World) ProofReviewSnapshot() []ProofReviewSnapshot {
	if len(w.proofReviews) == 0 {
		return nil
	}
	settled := make(map[string]struct{})
	for _, s := range w.BetSettlementSnapshot() {
		settled[s.HypothesisID] = struct{}{}
	}
	var out []ProofReviewSnapshot
	for id, r := range w.proofReviews {
		if _, done := settled[id]; done {
			continue
		}
		out = append(out, ProofReviewSnapshot{
			HypothesisID:        r.HypothesisID,
			MissionID:           r.MissionID,
			ScopeID:             r.ScopeID,
			Technique:           r.Technique,
			Evidence:            append([]ProofReviewEvidence(nil), r.Evidence...),
			SubmittedAtUnixNano: r.SubmittedAtUnixNano,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].HypothesisID < out[j].HypothesisID })
	return out
}

// ProofReviews returns the tenant's proofs that wait for a review.
func (e *Engine) ProofReviews() []ProofReviewSnapshot {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.World.ProofReviewSnapshot()
}

// SubmitProofForReview records a proof with typed evidence so a human can
// review it. It refuses a request with no hypothesis, with no evidence, or
// over a bound.
func (e *Engine) SubmitProofForReview(_ context.Context, req ProofReviewRequest) error {
	if req.HypothesisID == "" {
		return errors.New("brain: a proof review requires a hypothesis id")
	}
	if len(req.Evidence) == 0 {
		return errors.New("brain: a proof review requires evidence")
	}
	if len(req.Evidence) > MaxProofReviewEvidenceItems {
		return fmt.Errorf("brain: a proof review carries %d evidence items, over the limit of %d",
			len(req.Evidence), MaxProofReviewEvidenceItems)
	}
	for i, item := range req.Evidence {
		if len(item.Content) > MaxProofReviewEvidenceBytes {
			return fmt.Errorf("brain: proof review evidence item %d is %d bytes, over the limit of %d",
				i, len(item.Content), MaxProofReviewEvidenceBytes)
		}
	}
	e.Submit(BetProofSubmittedForReview(req))
	return nil
}

// MaxProofToolCallIDs bounds the tool calls one proof names.
const MaxProofToolCallIDs = 32

// RecordedToolCalls returns the tool calls the daemon recorded for missionID
// under the given ids, in the order of ids, and the ids it holds no record
// for. A record of another mission counts as missing: a proof settles only on
// the calls of its own mission. It reads under the engine's read lock and
// copies only the records it returns.
func (e *Engine) RecordedToolCalls(missionID string, ids []string) (found []AgentToolCallSnapshot, missing []string) {
	want := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		want[id] = struct{}{}
	}
	byID := make(map[string]AgentToolCallSnapshot, len(want))

	e.mu.RLock()
	q := ecs.NewFilter1[AgentToolCall](e.World.ecs).Query()
	for q.Next() {
		c := q.Get()
		if _, ok := want[c.ToolCallID]; !ok || c.MissionID != missionID {
			continue
		}
		byID[c.ToolCallID] = AgentToolCallSnapshot(*c)
	}
	e.mu.RUnlock()

	for _, id := range ids {
		if c, ok := byID[id]; ok {
			found = append(found, c)
		} else {
			missing = append(missing, id)
		}
	}
	return found, missing
}
