// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
)

// hypothesisEvents is a small Timeline with two hypotheses. The second event
// repeats the first claim, so the fold must keep one hypothesis for it.
func hypothesisEvents() []brain.Event {
	return []brain.Event{
		brain.HypothesisObserved{
			MissionID: "m1", RunID: "run-1", ScopeID: "s1", Proposer: "recon",
			Confidence: 0.4, Claim: "port 6443 has no authentication",
			HypothesisID: "h-open-api", Technique: "T1190",
			References: []brain.ReferencedEntityRef{
				{Label: "Host", IDProperties: map[string]string{"scope": "s1", "address": "10.0.0.5"}},
			},
		},
		brain.HypothesisObserved{
			MissionID: "m1", RunID: "run-2", ScopeID: "s1", Proposer: "exploit",
			Confidence: 0.7, Claim: "port 6443 has no authentication",
		},
		brain.HypothesisObserved{
			MissionID: "m1", RunID: "run-1", ScopeID: "s1", Proposer: "recon",
			Confidence: 0.2, Claim: "the admin account uses a default password",
		},
	}
}

// projectHypotheses folds evs into the World of a new tenant engine, runs one
// projection pass, and returns the hypotheses that the writer received.
func projectHypotheses(t *testing.T, evs []brain.Event) []brain.HypothesisSnapshot {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx)
	eng := reg.For("acme")
	for _, ev := range evs {
		eng.Submit(ev)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && len(eng.Hypotheses()) < 2 {
		time.Sleep(10 * time.Millisecond)
	}

	writer := newFakeGraphWriter()
	NewGraphProjector(reg, writer, time.Hour, nil).project(ctx)

	writer.mu.Lock()
	defer writer.mu.Unlock()
	folded := eng.Hypotheses()
	if len(folded) == 0 {
		t.Fatal("the World folded no hypothesis")
	}
	// The guard of gibson#670: each folded hypothesis has one projected node.
	if got := len(writer.hypotheses["acme"]); got != len(folded) {
		t.Fatalf("the projector wrote %d Hypothesis nodes for %d folded hypotheses", got, len(folded))
	}
	return writer.hypotheses["acme"]
}

func TestGraphProjector_WritesOneNodeForEachHypothesis(t *testing.T) {
	got := projectHypotheses(t, hypothesisEvents())
	if len(got) != 2 {
		t.Fatalf("projected %d hypotheses, want 2 (a repeated claim is one hypothesis)", len(got))
	}
	seen := map[uint64]bool{}
	for _, h := range got {
		if h.ID == 0 {
			t.Fatalf("a projected hypothesis has no stable id: %+v", h)
		}
		if seen[h.ID] {
			t.Fatalf("two projected hypotheses share the id %d", h.ID)
		}
		seen[h.ID] = true
	}
}

// A replay of the same Timeline gives the same nodes: the same ids and the
// same properties.
func TestGraphProjector_HypothesisNodesAreTheSameAfterAReplay(t *testing.T) {
	first := projectHypotheses(t, hypothesisEvents())
	second := projectHypotheses(t, hypothesisEvents())
	if len(first) != len(second) {
		t.Fatalf("the replay projected %d hypotheses, the first run %d", len(second), len(first))
	}
	for i := range first {
		a, b := hypothesisUpsertParams(first[i]), hypothesisUpsertParams(second[i])
		if !reflect.DeepEqual(a, b) {
			t.Fatalf("the replay gave a different node:\n first  %v\n second %v", a, b)
		}
	}
}

func TestHypothesisUpsertParams_CarriesTheClaimAndItsReferences(t *testing.T) {
	p := hypothesisUpsertParams(brain.HypothesisSnapshot{
		ID: 7, ScopeID: "s1", Claim: "c", Proposer: "recon", Confidence: 0.4,
		MissionID: "m1", RunID: "r1", HypothesisID: "h1", Technique: "T1190",
		References: []brain.ReferencedEntityRef{
			{Label: "Host", IDProperties: map[string]string{"scope": "s1", "address": "10.0.0.5"}},
			{Label: "Domain", IDProperties: map[string]string{"name": "example.com"}},
		},
	})
	want := map[string]any{
		"id": int64(7), "scope": "s1", "claim": "c", "proposer": "recon", "confidence": 0.4,
		"mission_id": "m1", "run_id": "r1", "hypothesis_id": "h1", "technique": "T1190",
		"reference_labels": []string{"Host", "Domain"},
		"reference_ids":    []string{"address=10.0.0.5,scope=s1", "name=example.com"},
	}
	if !reflect.DeepEqual(p, want) {
		t.Fatalf("params = %v\nwant     %v", p, want)
	}

	// A hypothesis with no reference sends two empty lists, never nil: a nil
	// list would remove the property and a reader could not tell the two apart.
	empty := hypothesisUpsertParams(brain.HypothesisSnapshot{ID: 1})
	if l, ok := empty["reference_labels"].([]string); !ok || l == nil || len(l) != 0 {
		t.Fatalf("reference_labels = %#v, want an empty list", empty["reference_labels"])
	}
}
