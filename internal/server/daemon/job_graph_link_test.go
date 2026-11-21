// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/brain/braintest"
	"github.com/zeroroot-ai/gibson/internal/engine/fixloop"
	"github.com/zeroroot-ai/gibson/internal/engine/jobnode"
	"github.com/zeroroot-ai/gibson/internal/platform/job"
)

// testNow is the time that the tests pass to fixedByEvents.
var testNow = time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)

const testMRURL = "https://forge.example/g/r/-/merge_requests/7"

func closedJob(inputs []string, ds ...job.Deliverable) jobnode.ClosedJob {
	return jobnode.ClosedJob{
		TenantID: "acme", MissionRunID: "run-1", NodeID: "fix", JobID: "job-1", Inputs: inputs, Deliverables: ds,
	}
}

// testClaimedAt is the time of the claim of the test job.
var testClaimedAt = testNow.Add(-time.Hour)

// heldWorld builds a World view in which the job of closedJob holds every
// finding, and each is open with the scope that the map gives.
func heldWorld(findings map[string]string) func(string) map[string]findingRef {
	refs := make(map[string]findingRef, len(findings))
	for id, scope := range findings {
		refs[id] = findingRef{scope: scope, status: brain.FindingStatusOpen, claim: "run-1/fix", claimedAt: testClaimedAt}
	}
	return func(string) map[string]findingRef { return refs }
}

// fakeMRReader is the Git host of the link tests. failures is the number of
// reads that fail before the reads succeed.
type fakeMRReader struct {
	fact     fixloop.MergeFact
	err      error
	failures int
	calls    []string
}

func (f *fakeMRReader) MergeRequest(_ context.Context, tenant, missionID, key string) (fixloop.MergeFact, error) {
	f.calls = append(f.calls, tenant+"/"+missionID+"/"+key)
	if f.failures > 0 {
		f.failures--
		return fixloop.MergeFact{}, errors.New("the connector is down for a moment")
	}
	return f.fact, f.err
}

// jobMR is the merge request that the test job opened: open, on the job
// branch, after the claim.
func jobMR() *fakeMRReader {
	return &fakeMRReader{fact: fixloop.MergeFact{
		State: fixloop.MROpen, SourceBranch: "job/job-1", CreatedAt: testClaimedAt.Add(10 * time.Minute),
	}}
}

// worldWith builds a World view in which every finding is open and has the
// scope that the map gives.
func worldWith(findings map[string]string) func(string) map[string]findingRef {
	refs := make(map[string]findingRef, len(findings))
	for id, scope := range findings {
		refs[id] = findingRef{scope: scope, status: brain.FindingStatusOpen}
	}
	return func(string) map[string]findingRef { return refs }
}

var mrDeliverable = job.Deliverable{Kind: "merge_request", Ref: "!7", URL: testMRURL}

func entities(t *testing.T, evs []brain.Event) []brain.EntityObserved {
	t.Helper()
	out := make([]brain.EntityObserved, 0, len(evs))
	for _, ev := range evs {
		if _, ok := ev.(brain.FindingStatusChanged); ok {
			continue // the status changes have their own test
		}
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
		worldWith(map[string]string{"f-1": "scope-a", "f-2": "scope-a"}), testNow)
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
		worldWith(map[string]string{"world-id-9": "s"}), testNow)
	got := entities(t, evs)
	if len(got) != 2 || got[1].Key != "world-id-9" {
		t.Fatalf("events = %+v", got)
	}
}

// An input that is not a finding must emit no Finding event: the projector
// creates a missing edge target, so it would invent a phantom :Finding.
func TestFixedByEvents_PhantomFindingGuard_NonFindingInputEmitsNoFinding(t *testing.T) {
	evs, skipped := fixedByEvents(closedJob([]string{"f-1", "plan-1", "plan-1"}, mrDeliverable),
		worldWith(map[string]string{"f-1": "s"}), testNow)
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
	evs, skipped := fixedByEvents(closedJob([]string{"plan-1"}, mrDeliverable), worldWith(nil), testNow)
	if len(evs) != 0 || skipped != 1 {
		t.Errorf("events = %v skipped = %d: a merge request nobody is fixed by must not be written", evs, skipped)
	}
}

func TestFixedByEvents_OtherDeliverablesEmitNothing(t *testing.T) {
	for _, d := range []job.Deliverable{
		{Kind: "push_branch", Ref: "fix"}, {Kind: "none"}, {Kind: "merge_request"},
	} {
		evs, _ := fixedByEvents(closedJob([]string{"f-1"}, d), worldWith(map[string]string{"f-1": "s"}), testNow)
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
		findings: heldWorld(map[string]string{"f-1": "s"}), mergeRequests: jobMR(), now: func() time.Time { return testNow },
		logger: testObsLogger().Slog(),
	}
	l.JobClosed(context.Background(), closedJob([]string{"f-1"}, mrDeliverable))
	if n != 3 || tenants[0] != "acme" || tenants[2] != "acme" {
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
		findings: heldWorld(map[string]string{"f-1": "s"}), mergeRequests: jobMR(), now: func() time.Time { return testNow },
		logger: testObsLogger().Slog(),
	}
	// Two inputs, one finding and one plan.
	l.JobClosed(context.Background(), closedJob([]string{"f-1", "plan-1"}, mrDeliverable))
	// The merge request, the one finding and its status change, and nothing for the plan.
	if submitted != 3 {
		t.Errorf("submitted %d events, want 3 (the merge request, one finding and its status change)", submitted)
	}
}

// TestNewJobGraphLink_ReadsFindingsFromTheTenantWorld exercises the real
// constructor's two closures. They are the seam between this file and the brain
// registry, so a test that only builds a jobGraphLink by hand never touches
// them: the submit path and the findings projection both stay unproven.
func TestNewJobGraphLink_ReadsFindingsFromTheTenantWorld(t *testing.T) {
	reg := brain.NewRegistry(context.Background(), braintest.StoreFactory())
	l := newJobGraphLink(reg, jobMR(), testObsLogger().Slog())
	if l.submit == nil || l.findings == nil || l.mergeRequests == nil || l.now == nil {
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
	reg := brain.NewRegistry(ctx, braintest.StoreFactory())
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
	reg := brain.NewRegistry(ctx, braintest.StoreFactory())

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
	if _, err := openFindingsResolver(brain.NewRegistry(ctx, braintest.StoreFactory())).OpenFindings(ctx, "acme", ""); err == nil {
		t.Fatal("a job with no mission run has no target to scope by")
	}
}

// A target with nothing open resolves to nothing, and that IS the answer: the
// job opens with no inputs and closes having linked nothing.
func TestOpenFindingsResolver_NoOpenFindingsIsNotAnError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx, braintest.StoreFactory())
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
	reg := brain.NewRegistry(ctx, braintest.StoreFactory())

	seedFindingsWorld(t, reg.For("acme"), 1,
		brain.MissionCreated{ID: "run-1", TenantID: "acme", TargetID: "target-a"},
		brain.FindingRaised{ID: "f-a1", ScopeID: "target-a", Title: "x", Status: brain.FindingStatusOpen},
	)

	if _, err := openFindingsResolver(reg).OpenFindings(ctx, "other", "run-1"); err == nil {
		t.Fatal("another tenant's World does not know this run, so it must refuse")
	}
}

// A merge request deliverable moves each open finding to fixing and records the
// merge request on it (gibson#1505). A finding in another status does not move.
func TestFixedByEvents_OpenFindingBecomesFixing(t *testing.T) {
	known := func(string) map[string]findingRef {
		return map[string]findingRef{
			"f-open":  {scope: "s", status: brain.FindingStatusOpen},
			"f-fixed": {scope: "s", status: brain.FindingStatusFixed},
		}
	}
	evs, _ := fixedByEvents(closedJob([]string{"f-open", "f-fixed"}, mrDeliverable), known, testNow)
	var changes []brain.FindingStatusChanged
	for _, ev := range evs {
		if c, ok := ev.(brain.FindingStatusChanged); ok {
			changes = append(changes, c)
		}
	}
	want := brain.FindingStatusChanged{
		ID: "f-open", Status: brain.FindingStatusFixing, MissionID: "run-1", MergeRequest: testMRURL, At: testNow,
	}
	if len(changes) != 1 || changes[0] != want {
		t.Fatalf("status changes = %+v, want only %+v", changes, want)
	}
}

// One fix job at a time works on one Finding (gibson#1454). A second job for
// a claimed Finding is refused. After the first job releases its claim, the
// next job can claim it. An input that is no Finding takes no claim.
func TestFixClaims_OneJobAtATimeForOneFinding(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	reg := brain.NewRegistry(ctx, braintest.StoreFactory())
	eng := reg.For("acme")
	if err := eng.SubmitAndWait(ctx, brain.FindingRaised{ID: "f-1", At: testNow}); err != nil {
		t.Fatal(err)
	}
	c := newFixClaims(reg)
	if err := c.Claim(ctx, "acme", "run-1/fix", "run-1", []string{"f-1", "the build log"}); err != nil {
		t.Fatalf("first claim: %v", err)
	}
	if err := c.Claim(ctx, "acme", "run-2/fix", "run-2", []string{"f-1"}); !errors.Is(err, jobnode.ErrFindingClaimed) {
		t.Fatalf("second claim: err = %v, want ErrFindingClaimed", err)
	}
	holder := func() string {
		var h string
		eng.ReadWorld(func(w *brain.World) { h = w.FixClaimOf("f-1") })
		return h
	}
	c.Release(ctx, "acme", "run-1/fix", "run-1", []string{"f-1"})
	deadline := time.Now().Add(2 * time.Second)
	for holder() != "" && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if h := holder(); h != "" {
		t.Fatalf("holder after the release = %q, want none", h)
	}
	if err := c.Claim(ctx, "acme", "run-2/fix", "run-2", []string{"f-1"}); err != nil {
		t.Fatalf("claim after the release: %v", err)
	}
}

// testFixClaims is a claim store over a fresh World of its own.
func testFixClaims(t *testing.T) fixClaims {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return newFixClaims(brain.NewRegistry(ctx, braintest.StoreFactory()))
}

// The daemon links only a merge request that the job opened: open on the Git
// host, from the job branch, and newer than the claim (review B1). Any other
// merge request is refused, the refusal is recorded on each finding, the
// claim ends, and no finding moves to fixing.
func TestJobGraphLink_RefusesAMergeRequestThatIsNotTheWorkOfTheJob(t *testing.T) {
	good := jobMR().fact
	cases := map[string]*fakeMRReader{
		"merged by a person": {fact: fixloop.MergeFact{
			State: fixloop.MRMerged, SourceBranch: good.SourceBranch, CreatedAt: good.CreatedAt}},
		"closed": {fact: fixloop.MergeFact{
			State: fixloop.MRClosed, SourceBranch: good.SourceBranch, CreatedAt: good.CreatedAt}},
		"another branch": {fact: fixloop.MergeFact{
			State: fixloop.MROpen, SourceBranch: "release-hotfix", CreatedAt: good.CreatedAt}},
		"older than the claim": {fact: fixloop.MergeFact{
			State: fixloop.MROpen, SourceBranch: good.SourceBranch, CreatedAt: testClaimedAt.Add(-time.Minute)}},
		"no time of creation": {fact: fixloop.MergeFact{State: fixloop.MROpen, SourceBranch: good.SourceBranch}},
		"an old connector":    {fact: fixloop.MergeFact{State: fixloop.MROpen}},
	}
	for name, mrs := range cases {
		t.Run(name, func(t *testing.T) {
			var evs []brain.Event
			l := &jobGraphLink{
				submit:        func(_ string, ev brain.Event) { evs = append(evs, ev) },
				findings:      heldWorld(map[string]string{"f-1": "s"}),
				mergeRequests: mrs, now: func() time.Time { return testNow }, logger: testObsLogger().Slog(),
			}
			l.JobClosed(context.Background(), closedJob([]string{"f-1"}, mrDeliverable))
			if len(mrs.calls) == 0 || mrs.calls[0] != "acme/run-1/"+testMRURL {
				t.Fatalf("reads = %v", mrs.calls)
			}
			if len(evs) != 2 {
				t.Fatalf("events = %+v, want the refusal and the release", evs)
			}
			ref, ok := evs[0].(brain.FixLinkRefused)
			if !ok || ref.ID != "f-1" || ref.MergeRequest != testMRURL || ref.JobID != "job-1" || ref.Reason == "" {
				t.Fatalf("refusal = %+v", evs[0])
			}
			rel, ok := evs[1].(brain.FixClaimReleased)
			if !ok || rel.ID != "f-1" || rel.Claim != "run-1/fix" {
				t.Fatalf("release = %+v", evs[1])
			}
		})
	}
}

// A finding that the job does not hold takes no link, even when the merge
// request is the work of the job.
func TestJobGraphLink_LinksOnlyTheFindingsThatTheJobHolds(t *testing.T) {
	var evs []brain.Event
	known := heldWorld(map[string]string{"f-1": "s"})("")
	known["f-other"] = findingRef{scope: "s", status: brain.FindingStatusOpen, claim: "run-2/fix", claimedAt: testClaimedAt}
	l := &jobGraphLink{
		submit:   func(_ string, ev brain.Event) { evs = append(evs, ev) },
		findings: func(string) map[string]findingRef { return known }, mergeRequests: jobMR(),
		now: func() time.Time { return testNow }, logger: testObsLogger().Slog(),
	}
	l.JobClosed(context.Background(), closedJob([]string{"f-1", "f-other"}, mrDeliverable))
	for _, ev := range evs {
		if c, ok := ev.(brain.FindingStatusChanged); ok && c.ID != "f-1" {
			t.Fatalf("a finding that the job does not hold moved: %+v", c)
		}
		if e, ok := ev.(brain.EntityObserved); ok && e.Key == "f-other" {
			t.Fatalf("a finding that the job does not hold took the link: %+v", e)
		}
	}
}

// A connector that sends no source_branch and no created_at gets a refusal
// that names the cause, not a refusal about branch "" (review R2).
func TestMergeRequestRefusal_NamesAnOldConnector(t *testing.T) {
	for _, fact := range []fixloop.MergeFact{
		{State: fixloop.MROpen},
		{State: fixloop.MROpen, SourceBranch: "job/job-1"},
		{State: fixloop.MROpen, CreatedAt: testNow},
	} {
		if got := mergeRequestRefusal(fact, "job/job-1", testClaimedAt); got != errConnectorLacksMergeFields {
			t.Errorf("fact %+v: refusal = %q", fact, got)
		}
	}
}

// A Git host read that fails during the close leaves the link pending, not
// refused, and the close does not wait or read again (gibson#1581). The claim
// stays. A later read links the fix.
func TestJobGraphLink_AFailedReadLeavesTheLinkPendingAndALaterReadLinksIt(t *testing.T) {
	var evs []brain.Event
	mrs := jobMR()
	mrs.failures = 1
	l := &jobGraphLink{
		submit:   func(_ string, ev brain.Event) { evs = append(evs, ev) },
		findings: heldWorld(map[string]string{"f-1": "s"}), mergeRequests: mrs,
		now: func() time.Time { return testNow }, logger: testObsLogger().Slog(),
	}
	l.JobClosed(context.Background(), closedJob([]string{"f-1"}, mrDeliverable))
	if len(mrs.calls) != 1 {
		t.Fatalf("reads in the close = %d, want 1 (no retry in the close path)", len(mrs.calls))
	}
	if len(evs) != 1 {
		t.Fatalf("events = %+v, want the pending record only", evs)
	}
	pending, ok := evs[0].(brain.FixLinkPending)
	if !ok || pending.ID != "f-1" || pending.MergeRequest != testMRURL || pending.JobID != "job-1" || pending.Reason == "" {
		t.Fatalf("event = %+v, want a FixLinkPending", evs[0])
	}

	// The reconciliation reads again. The Git host is up now, so the fix is linked.
	evs = nil
	l.RetryPending(context.Background())
	if len(mrs.calls) != 2 {
		t.Fatalf("reads after the retry = %d, want 2", len(mrs.calls))
	}
	var fixing bool
	for _, ev := range evs {
		if c, ok := ev.(brain.FindingStatusChanged); ok && c.Status == brain.FindingStatusFixing {
			fixing = true
		}
		if _, ok := ev.(brain.FixLinkRefused); ok {
			t.Fatalf("a good read refused the link: %+v", ev)
		}
	}
	if !fixing {
		t.Fatalf("events = %+v, want the finding moved to fixing", evs)
	}

	// The link is not pending any more.
	evs = nil
	l.RetryPending(context.Background())
	if len(evs) != 0 || len(mrs.calls) != 2 {
		t.Fatalf("a settled link was read again: events = %+v, reads = %d", evs, len(mrs.calls))
	}
}

// A read that keeps failing keeps the link pending until the limit, and then
// refuses it and releases the claim.
func TestJobGraphLink_APendingLinkIsRefusedAfterTheLimit(t *testing.T) {
	var evs []brain.Event
	down := jobMR()
	down.failures = 100
	clock := testNow
	l := &jobGraphLink{
		submit:   func(_ string, ev brain.Event) { evs = append(evs, ev) },
		findings: heldWorld(map[string]string{"f-1": "s"}), mergeRequests: down,
		now: func() time.Time { return clock }, logger: testObsLogger().Slog(),
	}
	l.JobClosed(context.Background(), closedJob([]string{"f-1"}, mrDeliverable))
	evs = nil

	clock = testNow.Add(pendingLinkLimit - time.Minute)
	l.RetryPending(context.Background())
	if len(evs) != 0 {
		t.Fatalf("a link inside the limit was refused: %+v", evs)
	}

	clock = testNow.Add(pendingLinkLimit)
	l.RetryPending(context.Background())
	if len(evs) != 2 {
		t.Fatalf("events = %+v, want the refusal and the release", evs)
	}
	if _, ok := evs[0].(brain.FixLinkRefused); !ok {
		t.Fatalf("event 0 = %+v, want the refusal", evs[0])
	}
	if _, ok := evs[1].(brain.FixClaimReleased); !ok {
		t.Fatalf("event 1 = %+v, want the release", evs[1])
	}
}

// A host that gives no source branch and says why, for example a fork, gets
// that reason in the refusal (connectors v0.2.0).
func TestMergeRequestRefusal_NamesTheReasonOfTheHost(t *testing.T) {
	got := mergeRequestRefusal(fixloop.MergeFact{
		State: fixloop.MROpen, CreatedAt: testNow, SourceBranchReason: "the source branch is in a fork",
	}, "job/job-1", testClaimedAt)
	if !strings.Contains(got, "the source branch is in a fork") {
		t.Fatalf("refusal = %q, want the reason of the host", got)
	}
}

// Run reads the pending links until the context ends. A pending link whose
// claims ended is dropped. A daemon with no Git host reader refuses a close.
func TestJobGraphLink_RunStopsWithTheContextAndASettledLinkIsDropped(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	l := &jobGraphLink{logger: testObsLogger().Slog()}
	done := make(chan struct{})
	go func() { l.Run(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop with its context")
	}

	// The claims of a pending link ended: the retry drops it and reads nothing.
	mrs := jobMR()
	mrs.failures = 1
	held := true
	l = &jobGraphLink{
		submit: func(string, brain.Event) {},
		findings: func(string) map[string]findingRef {
			if held {
				return heldWorld(map[string]string{"f-1": "s"})("")
			}
			return map[string]findingRef{}
		},
		mergeRequests: mrs, logger: testObsLogger().Slog(), // no clock: the real one is used
	}
	l.JobClosed(context.Background(), closedJob([]string{"f-1"}, mrDeliverable))
	held = false
	l.RetryPending(context.Background())
	if len(mrs.calls) != 1 || len(l.pending) != 0 {
		t.Fatalf("reads = %d, pending = %d, want 1 read and no pending link", len(mrs.calls), len(l.pending))
	}
}

func TestJobGraphLink_NoGitHostReaderRefusesTheClose(t *testing.T) {
	var evs []brain.Event
	l := &jobGraphLink{
		submit:   func(_ string, ev brain.Event) { evs = append(evs, ev) },
		findings: heldWorld(map[string]string{"f-1": "s"}), now: func() time.Time { return testNow },
		logger: testObsLogger().Slog(),
	}
	l.JobClosed(context.Background(), closedJob([]string{"f-1"}, mrDeliverable))
	if len(evs) != 2 {
		t.Fatalf("events = %+v, want the refusal and the release", evs)
	}
	if _, ok := evs[0].(brain.FixLinkRefused); !ok {
		t.Fatalf("event 0 = %+v, want the refusal", evs[0])
	}
}
