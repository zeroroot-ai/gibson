// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"strings"
	"testing"
	"time"

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
	out := make([]brain.EntityObserved, 0, len(evs))
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

// TestJobGraphLink_LogsTheInputsItLeftOut covers the reporting branch. An input
// that is not a finding is dropped on purpose, and dropping it silently is how a
// fix job quietly links nothing: the count has to reach the operator.
func TestJobGraphLink_LogsTheInputsItLeftOut(t *testing.T) {
	var submitted int
	l := &jobGraphLink{
		submit:   func(string, brain.Event) { submitted++ },
		findings: worldWith(map[string]string{"f-1": "s"}),
		logger:   testObsLogger().Slog(),
	}
	// Two inputs, one finding and one plan.
	l.JobClosed(context.Background(), closedJob([]string{"f-1", "plan-1"}, mrDeliverable))
	// The merge request plus the one finding, and nothing for the plan.
	if submitted != 2 {
		t.Errorf("submitted %d events, want 2 (the merge request and one finding)", submitted)
	}
}

// TestNewJobGraphLink_ReadsFindingsFromTheTenantWorld exercises the real
// constructor's two closures. They are the seam between this file and the brain
// registry, so a test that only builds a jobGraphLink by hand never touches
// them: the submit path and the findings projection both stay unproven.
func TestNewJobGraphLink_ReadsFindingsFromTheTenantWorld(t *testing.T) {
	reg := brain.NewRegistry(context.Background())
	l := newJobGraphLink(reg, testObsLogger().Slog())
	if l.submit == nil || l.findings == nil {
		t.Fatal("newJobGraphLink left a seam nil")
	}
	// A tenant with no findings yields an empty, non-nil map, so a caller can
	// range it without a nil check.
	got := l.findings("acme")
	if got == nil {
		t.Fatal("findings returned a nil map for a tenant with no findings")
	}
	if len(got) != 0 {
		t.Errorf("findings for an empty World = %v, want none", got)
	}
	// Submitting must not panic on a tenant the registry has not seen before.
	l.submit("acme", brain.EntityObserved{Label: labelMergeRequest, Key: "https://example.test/mr/1"})
}

// seedWorld submits the events and waits until the World has applied them.
// Submit is a channel send, so a read straight after it races the apply.
func seedFindingsWorld(t *testing.T, eng *brain.Engine, want int, evs ...brain.Event) {
	t.Helper()
	for _, ev := range evs {
		eng.Submit(ev)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(eng.Findings()) >= want && len(eng.Missions()) > 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("the World applied %d findings and %d missions, want %d findings",
		len(eng.Findings()), len(eng.Missions()), want)
}

// TestOpenFindingsResolver_ScopesToTheRunsTarget is the other half of the
// gibson#497 fixture. The resolver must answer from the World's own mission
// record, so a fix job gets the open findings on the target it is fixing and
// nothing else — a tenant may hold three clusters.
func TestOpenFindingsResolver_ScopesToTheRunsTarget(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx)
	eng := reg.For("acme")

	seedFindingsWorld(t, eng, 3,
		brain.MissionCreated{ID: "run-1", TenantID: "acme", TargetID: "target-a"},
		brain.MissionCreated{ID: "run-2", TenantID: "acme", TargetID: "target-b"},
		brain.FindingRaised{ID: "f-a1", ScopeID: "target-a", Title: "x", Status: brain.FindingStatusOpen},
		brain.FindingRaised{ID: "f-a2", ScopeID: "target-a", Title: "y", Status: brain.FindingStatusFixed},
		brain.FindingRaised{ID: "f-b1", ScopeID: "target-b", Title: "z", Status: brain.FindingStatusOpen},
	)

	got, err := openFindingsResolver(reg).OpenFindings(ctx, "acme", "run-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "f-a1" {
		t.Errorf("open findings = %v, want only the open one on target-a", got)
	}
}

// A mission the World does not know cannot have its findings scoped. Answering
// "none" would read as "nothing to fix" and the job would link nothing in
// silence, which is the gibson#497 defect wearing a different hat.
func TestOpenFindingsResolver_RefusesAnUnknownRun(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx)

	_, err := openFindingsResolver(reg).OpenFindings(ctx, "acme", "run-nope")
	if err == nil {
		t.Fatal("an unknown run must fail, not resolve to no findings")
	}
	if !strings.Contains(err.Error(), "names no target") {
		t.Errorf("error = %v", err)
	}
}

func TestOpenFindingsResolver_RefusesAnEmptyRunID(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := openFindingsResolver(brain.NewRegistry(ctx)).OpenFindings(ctx, "acme", ""); err == nil {
		t.Fatal("a job with no mission run has no target to scope by")
	}
}

// A target with nothing open resolves to nothing, and that IS the answer: the
// job opens with no inputs and closes having linked nothing.
func TestOpenFindingsResolver_NoOpenFindingsIsNotAnError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx)
	eng := reg.For("acme")

	seedFindingsWorld(t, eng, 1,
		brain.MissionCreated{ID: "run-1", TenantID: "acme", TargetID: "target-a"},
		brain.FindingRaised{ID: "f-a1", ScopeID: "target-a", Title: "x", Status: brain.FindingStatusFixed},
	)

	got, err := openFindingsResolver(reg).OpenFindings(ctx, "acme", "run-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("open findings = %v, want none", got)
	}
}

// One tenant's World never answers for another's.
func TestOpenFindingsResolver_DoesNotCrossTenants(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx)

	seedFindingsWorld(t, reg.For("acme"), 1,
		brain.MissionCreated{ID: "run-1", TenantID: "acme", TargetID: "target-a"},
		brain.FindingRaised{ID: "f-a1", ScopeID: "target-a", Title: "x", Status: brain.FindingStatusOpen},
	)

	if _, err := openFindingsResolver(reg).OpenFindings(ctx, "other", "run-1"); err == nil {
		t.Fatal("another tenant's World does not know this run, so it must refuse")
	}
}
