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
)

func failedJob(inputs []string, reason string) jobnode.FailedJob {
	c := closedJob(inputs, mrDeliverable)
	return jobnode.FailedJob{
		TenantID: c.TenantID, MissionRunID: c.MissionRunID, NodeID: c.NodeID, JobID: c.JobID,
		Inputs: c.Inputs, Deliverables: c.Deliverables, Reason: reason,
	}
}

// failedLink builds a link over a World where the job holds f-1. It returns
// the events that the link submitted, and the findings that it reads.
func failedLink(mrs *fakeMRReader) (*jobGraphLink, *[]brain.Event, map[string]findingRef) {
	var evs []brain.Event
	known := heldWorld(map[string]string{"f-1": "s"})("")
	l := &jobGraphLink{
		submit:        func(_ string, ev brain.Event) { evs = append(evs, ev) },
		findings:      func(string) map[string]findingRef { return known },
		mergeRequests: mrs, now: func() time.Time { return testNow }, logger: testObsLogger().Slog(),
	}
	return l, &evs, known
}

// A failed job closes its merge request through the governed tool. The comment
// names the job and the reason. The attempt lands on the finding.
func TestJobGraphLink_AFailedJobsMergeRequestIsClosedWithTheJobAndTheReason(t *testing.T) {
	mrs := jobMR()
	l, evs, _ := failedLink(mrs)

	l.JobFailed(context.Background(), failedJob([]string{"f-1"}, "the delivery was refused"))

	if len(mrs.closes) != 1 || !strings.HasPrefix(mrs.closes[0], testMRURL+": ") ||
		!strings.Contains(mrs.closes[0], "job-1") || !strings.Contains(mrs.closes[0], "the delivery was refused") {
		t.Fatalf("closes = %v, want one with the job and the reason", mrs.closes)
	}
	if len(*evs) != 1 {
		t.Fatalf("events = %+v, want the failed attempt only", *evs)
	}
	a, ok := (*evs)[0].(brain.FixAttemptFailed)
	if !ok || a.ID != "f-1" || a.JobID != "job-1" || a.Reason != "the delivery was refused" || a.Verdict != "failed" {
		t.Errorf("attempt = %+v", (*evs)[0])
	}
}

// A merge request that is not the work of the job is not closed. An agent names
// the merge request, so the daemon checks it on the Git host first.
func TestJobGraphLink_AFailedJobDoesNotCloseAForeignMergeRequest(t *testing.T) {
	cases := map[string]fixloop.MergeFact{
		"another branch": {State: fixloop.MROpen, SourceBranch: "feature/x", CreatedAt: testClaimedAt.Add(time.Minute)},
		"older than the claim": {
			State: fixloop.MROpen, SourceBranch: "job/job-1", CreatedAt: testClaimedAt.Add(-time.Minute),
		},
		"closed already": {State: fixloop.MRClosed, SourceBranch: "job/job-1", CreatedAt: testClaimedAt.Add(time.Minute)},
		"merged":         {State: fixloop.MRMerged, SourceBranch: "job/job-1", CreatedAt: testClaimedAt.Add(time.Minute)},
	}
	for name, fact := range cases {
		t.Run(name, func(t *testing.T) {
			mrs := &fakeMRReader{fact: fact}
			l, evs, _ := failedLink(mrs)
			l.JobFailed(context.Background(), failedJob([]string{"f-1"}, "no"))
			if len(mrs.closes) != 0 {
				t.Errorf("closed %v", mrs.closes)
			}
			for _, ev := range *evs {
				if _, ok := ev.(brain.FixCloseWaiting); ok {
					t.Errorf("a wait for a merge request that needs no close: %+v", ev)
				}
			}
		})
	}
}

// A close that fails leaves a wait that names the merge request. RetryPending
// tries it again, and a good close ends the wait.
func TestJobGraphLink_AFailedCloseLeavesAWaitAndTheRetryEndsIt(t *testing.T) {
	mrs := jobMR()
	mrs.closeFailures = 1
	l, evs, known := failedLink(mrs)

	l.JobFailed(context.Background(), failedJob([]string{"f-1"}, "no"))

	var wait brain.FixCloseWaiting
	for _, ev := range *evs {
		if w, ok := ev.(brain.FixCloseWaiting); ok {
			wait = w
		}
	}
	if !wait.Waiting || wait.ID != "f-1" || wait.MergeRequest != testMRURL || wait.JobID != "job-1" || wait.Reason == "" {
		t.Fatalf("wait = %+v, want a wait that names the merge request", wait)
	}

	// The World shows the wait. The retry closes the merge request and ends it.
	ref := known["f-1"]
	ref.closeWaitJob = "job-1"
	known["f-1"] = ref
	*evs = nil
	l.RetryPending(context.Background())
	if len(mrs.closes) != 1 {
		t.Fatalf("closes = %v, want the retry to close", mrs.closes)
	}
	if len(*evs) != 1 {
		t.Fatalf("events = %+v, want the end of the wait", *evs)
	}
	if end, ok := (*evs)[0].(brain.FixCloseWaiting); !ok || end.Waiting || end.JobID != "job-1" || end.ID != "f-1" {
		t.Errorf("end = %+v", (*evs)[0])
	}
	// A second pass has nothing to do.
	*evs = nil
	l.RetryPending(context.Background())
	if len(*evs) != 0 || len(mrs.closes) != 1 {
		t.Errorf("a second pass acted: %v %v", *evs, mrs.closes)
	}
}

// A job that delivered no merge request records the attempt and closes nothing.
func TestJobGraphLink_AFailedJobWithNoMergeRequestOnlyRecordsTheAttempt(t *testing.T) {
	mrs := jobMR()
	l, evs, _ := failedLink(mrs)
	f := failedJob([]string{"f-1"}, "no")
	f.Deliverables = nil
	l.JobFailed(context.Background(), f)
	if len(mrs.closes) != 0 || len(mrs.calls) != 0 {
		t.Errorf("the Git host was called: %v %v", mrs.calls, mrs.closes)
	}
	if len(*evs) != 1 {
		t.Errorf("events = %+v", *evs)
	}
}

// A restart rebuilds the pending close from the wait on the finding.
func TestJobGraphLink_AdoptRebuildsAPendingClose(t *testing.T) {
	mrs := jobMR()
	l, evs, known := failedLink(mrs)
	ref := known["f-1"]
	ref.closeWaitJob = "job-1"
	known["f-1"] = ref
	l.Adopt("acme", []brain.FindingSnapshot{{
		ID: "f-1", Status: brain.FindingStatusOpen,
		FixFacts: brain.FixFacts{
			FixCloseWait: brain.FixCloseWait{
				JobID: "job-1", MissionRunID: "run-1", MergeRequest: testMRURL, ClaimedAt: testClaimedAt,
			},
			FixAttempts: []brain.FixAttempt{{JobID: "job-1", Reason: "the delivery was refused"}},
		},
	}})
	l.RetryPending(context.Background())
	if len(mrs.closes) != 1 || !strings.Contains(mrs.closes[0], "the delivery was refused") {
		t.Fatalf("closes = %v", mrs.closes)
	}
	if len(*evs) != 1 {
		t.Errorf("events = %+v", *evs)
	}
}

// A finding with three failed jobs in a row takes no new fix job, and the claim
// says why. The open-findings reference of a job leaves it out (gibson#1674).
func TestFixClaims_ABlockedFindingTakesNoNewJob(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	reg := brain.NewRegistry(ctx, braintest.StoreFactory())
	eng := reg.For("acme")
	for _, ev := range []brain.Event{
		brain.FindingRaised{ID: "f-1", ScopeID: "s", At: testNow},
		brain.FindingRaised{ID: "f-2", ScopeID: "s", At: testNow},
	} {
		if err := eng.SubmitAndWait(ctx, ev); err != nil {
			t.Fatal(err)
		}
	}
	for i, j := range []string{"j1", "j2", "j3"} {
		ev := brain.FixAttemptFailed{
			ID: "f-1", JobID: j, Verdict: "failed", Reason: "no", At: testNow.Add(time.Duration(i) * time.Minute),
		}
		if err := eng.SubmitAndWait(ctx, ev); err != nil {
			t.Fatal(err)
		}
	}
	c := newFixClaims(reg)
	if err := c.Claim(ctx, "acme", "run-9/fix", "run-9", []string{"f-1"}); !errors.Is(err, jobnode.ErrFindingBlocked) {
		t.Fatalf("claim of a blocked finding: err = %v, want ErrFindingBlocked", err)
	}
	if err := c.Claim(ctx, "acme", "run-9/fix", "run-9", []string{"f-2"}); err != nil {
		t.Fatalf("claim of a finding with no failures: %v", err)
	}
}

// An abandoned job counts as a failed attempt and its merge request is closed.
// A job that a cancel ended records no attempt, and its merge request is still
// closed.
func TestJobGraphLink_AnAbandonedJobIsAnAttemptUnlessCancelled(t *testing.T) {
	for name, tc := range map[string]struct {
		cancelled bool
		attempts  int
	}{"abandoned": {false, 1}, "cancelled": {true, 0}} {
		t.Run(name, func(t *testing.T) {
			mrs := jobMR()
			l, evs, _ := failedLink(mrs)
			f := failedJob([]string{"f-1"}, "the reviewer is down")
			f.Verdict, f.Cancelled = "abandoned", tc.cancelled
			l.JobFailed(context.Background(), f)
			if len(mrs.closes) != 1 {
				t.Errorf("closes = %v", mrs.closes)
			}
			var got []brain.FixAttemptFailed
			for _, ev := range *evs {
				if a, ok := ev.(brain.FixAttemptFailed); ok {
					got = append(got, a)
				}
			}
			if len(got) != tc.attempts || (tc.attempts == 1 && got[0].Verdict != "abandoned") {
				t.Errorf("attempts = %+v, want %d", got, tc.attempts)
			}
		})
	}
}
