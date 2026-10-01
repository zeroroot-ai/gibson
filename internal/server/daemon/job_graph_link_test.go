// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/jobnode"
	"github.com/zeroroot-ai/gibson/internal/platform/job"
)

const testMRURL = "https://forge.example/g/r/-/merge_requests/7"

func closedJob(inputs []string, ds ...job.Deliverable) jobnode.ClosedJob {
	return jobnode.ClosedJob{TenantID: "acme", MissionRunID: "run-1", JobID: "job-1", Inputs: inputs, Deliverables: ds}
}

func worldWith(findings map[string]string) func(string) map[string]string {
	return func(string) map[string]string { return findings }
}

var mrDeliverable = job.Deliverable{Kind: "merge_request", Ref: "!7", URL: testMRURL}

func entities(t *testing.T, evs []brain.Event) []brain.EntityObserved {
	t.Helper()
	var out []brain.EntityObserved
	for _, ev := range evs {
		e, ok := ev.(brain.EntityObserved)
		if !ok {
			t.Fatalf("event %T is not an EntityObserved", ev)
		}
		out = append(out, e)
	}
	return out
}

func TestFixedByEvents_MergeRequestLinksEachFinding(t *testing.T) {
	evs, skipped := fixedByEvents(closedJob([]string{"f-1", "f-2"}, mrDeliverable),
		worldWith(map[string]string{"f-1": "scope-a", "f-2": "scope-a"}))
	got := entities(t, evs)
	if skipped != 0 || len(got) != 3 {
		t.Fatalf("events = %d skipped = %d, want 3 and 0", len(got), skipped)
	}
	mr := got[0]
	if mr.Label != "MergeRequest" || mr.Key != testMRURL || mr.Props["url"] != testMRURL || mr.Props["ref"] != "!7" {
		t.Errorf("merge request entity = %+v", mr)
	}
	for i, id := range []string{"f-1", "f-2"} {
		f := got[i+1]
		if f.Label != "Finding" || f.Key != id || f.ScopeID != "scope-a" || f.MissionID != "run-1" {
			t.Errorf("finding entity = %+v", f)
		}
		// Direction: the edge is outgoing from the Finding.
		if len(f.Edges) != 1 || f.Edges[0] != (brain.EntityEdge{Type: "FIXED_BY", TargetLabel: "MergeRequest", TargetKey: testMRURL}) {
			t.Errorf("finding edges = %+v", f.Edges)
		}
	}
	if len(mr.Edges) != 0 {
		t.Errorf("the merge request must carry no FIXED_BY edge, got %+v", mr.Edges)
	}
}

// The projector merges a Finding on brain_id, which is the World id. A key
// taken from anywhere else writes a second node.
func TestFixedByEvents_FindingKeyIsTheWorldID(t *testing.T) {
	evs, _ := fixedByEvents(closedJob([]string{"world-id-9"}, mrDeliverable),
		worldWith(map[string]string{"world-id-9": "s"}))
	got := entities(t, evs)
	if len(got) != 2 || got[1].Key != "world-id-9" {
		t.Fatalf("events = %+v", got)
	}
}

// An input that is not a finding must emit no Finding event: the projector
// creates a missing edge target, so it would invent a phantom :Finding.
func TestFixedByEvents_PhantomFindingGuard_NonFindingInputEmitsNoFinding(t *testing.T) {
	evs, skipped := fixedByEvents(closedJob([]string{"f-1", "plan-1", "plan-1"}, mrDeliverable),
		worldWith(map[string]string{"f-1": "s"}))
	got := entities(t, evs)
	if skipped != 1 {
		t.Errorf("skipped = %d, want 1 (the duplicate is not a second skip)", skipped)
	}
	for _, e := range got {
		if e.Label == "Finding" && e.Key != "f-1" {
			t.Errorf("phantom Finding event: %+v", e)
		}
	}
	if len(got) != 2 {
		t.Errorf("events = %d, want the merge request and one finding", len(got))
	}
}

func TestFixedByEvents_NoFindingInputEmitsNothing(t *testing.T) {
	evs, skipped := fixedByEvents(closedJob([]string{"plan-1"}, mrDeliverable), worldWith(nil))
	if len(evs) != 0 || skipped != 1 {
		t.Errorf("events = %v skipped = %d: a merge request nobody is fixed by must not be written", evs, skipped)
	}
}

func TestFixedByEvents_OtherDeliverablesEmitNothing(t *testing.T) {
	for _, d := range []job.Deliverable{
		{Kind: "push_branch", Ref: "fix"}, {Kind: "none"}, {Kind: "merge_request"},
	} {
		evs, _ := fixedByEvents(closedJob([]string{"f-1"}, d), worldWith(map[string]string{"f-1": "s"}))
		if len(evs) != 0 {
			t.Errorf("%+v emitted %v", d, evs)
		}
	}
}

func TestJobGraphLink_SubmitsToTheClosingTenant(t *testing.T) {
	var tenants []string
	var n int
	l := &jobGraphLink{
		submit:   func(tenant string, _ brain.Event) { tenants = append(tenants, tenant); n++ },
		findings: worldWith(map[string]string{"f-1": "s"}),
		logger:   testObsLogger().Slog(),
	}
	l.JobClosed(context.Background(), closedJob([]string{"f-1"}, mrDeliverable))
	if n != 2 || tenants[0] != "acme" || tenants[1] != "acme" {
		t.Errorf("submits = %d to %v", n, tenants)
	}
}
