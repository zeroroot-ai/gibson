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

// failedJob is a job that the verifier refused. The report holds an internal name
// and an @name, so a test can show that neither reaches the merge request.
func failedJob(inputs []string) jobnode.FailedJob {
	return jobnode.FailedJob{
		TenantID: "acme", MissionRunID: "run-1", NodeID: "fix", JobID: "job-1", Inputs: inputs,
		Verdict: "failed", Class: jobnode.ReasonAcceptanceFailed,
		Reason: "the check refused it, ask @alice about the internal host db-7.corp",
	}
}

// failedRig is a link over a World where the job holds f-1 and f-2. The World
// folds the events that the link submits into the findings that it reads, as the
// reducer does for the waits.
type failedRig struct {
	l     *jobGraphLink
	evs   []brain.Event
	known map[string]findingRef
	now   time.Time
}

func newFailedRig(mrs *fakeMRReader, opened openedHeadReader) *failedRig {
	r := &failedRig{known: heldWorld(map[string]string{"f-1": "s", "f-2": "s"})(""), now: testNow}
	r.l = &jobGraphLink{
		findings:      func(string) map[string]findingRef { return r.known },
		mergeRequests: mrs, opened: opened, now: func() time.Time { return r.now }, logger: testObsLogger().Slog(),
	}
	r.l.submit = func(_ string, ev brain.Event) {
		r.evs = append(r.evs, ev)
		w, ok := ev.(brain.FixCloseWaiting)
		if !ok {
			return
		}
		ref := r.known[w.ID]
		waits := map[string]bool{}
		for k := range ref.closeWaits {
			waits[k] = true
		}
		if w.Waiting {
			waits[closeKey(w.JobID, w.MergeRequest)] = true
		} else {
			delete(waits, closeKey(w.JobID, w.MergeRequest))
		}
		ref.closeWaits = waits
		r.known[w.ID] = ref
	}
	return r
}

func (r *failedRig) waitEvents() []brain.FixCloseWaiting {
	var out []brain.FixCloseWaiting
	for _, ev := range r.evs {
		if w, ok := ev.(brain.FixCloseWaiting); ok {
			out = append(out, w)
		}
	}
	return out
}

// jobOpened is the record of the daemon: the job opened these merge requests.
func jobOpened(mrs ...string) mapHeads {
	out := mapHeads{}
	for _, mr := range mrs {
		out["acme\x00"+mr+"\x00job-1"] = openedHead{sha: testHeadSHA, sourceBranch: "job/job-1", jobID: "job-1"}
	}
	return out
}

// A failed job closes the merge request that the record of the daemon holds. The
// comment has the job id, the verdict and a class of reason in fixed words. The
// report of the verifier, with its @name and its internal host, stays out of it.
// The attempt lands on the finding with the full report.
func TestJobGraphLink_AFailedJobsMergeRequestIsClosedWithAFixedComment(t *testing.T) {
	mrs := jobMR()
	r := newFailedRig(mrs, jobOpened(testMRURL))

	r.l.JobFailed(context.Background(), failedJob([]string{"f-1"}))

	if len(mrs.closes) != 1 || !strings.HasPrefix(mrs.closes[0], testMRURL+": ") {
		t.Fatalf("closes = %v, want one", mrs.closes)
	}
	comment := strings.TrimPrefix(mrs.closes[0], testMRURL+": ")
	const want = "Gibson closed this merge request. Fix job job-1 ended as failed. " +
		"Reason: the fix did not pass acceptance."
	if comment != want {
		t.Errorf("comment = %q", comment)
	}
	if strings.Contains(comment, "@") || strings.Contains(comment, "db-7") {
		t.Errorf("the comment holds text of the report: %q", comment)
	}
	var attempt brain.FixAttemptFailed
	for _, ev := range r.evs {
		if a, ok := ev.(brain.FixAttemptFailed); ok {
			attempt = a
		}
	}
	if attempt.ID != "f-1" || attempt.JobID != "job-1" || attempt.Verdict != "failed" ||
		!strings.Contains(attempt.Reason, "@alice") {
		t.Errorf("attempt = %+v, want the full report in the record of the daemon", attempt)
	}
	if len(r.waitEvents()) != 0 {
		t.Errorf("waits = %+v", r.waitEvents())
	}
}

// The daemon closes each merge request of its record, and only those. An agent that
// opened a merge request and names none still has it closed. A merge request that
// the agent names and the record does not hold is never closed.
func TestJobGraphLink_ACloseReadsTheRecordOfTheDaemonAndNotTheAgent(t *testing.T) {
	mrs := jobMR()
	r := newFailedRig(mrs, jobOpened(testMRURL, "g/r!9"))
	// The agent names no merge request: FailedJob has no deliverables at all.
	r.l.JobFailed(context.Background(), failedJob([]string{"f-1"}))
	if len(mrs.closes) != 2 {
		t.Fatalf("closes = %v, want both merge requests of the record", mrs.closes)
	}

	// A job with an empty record closes nothing, whatever the agent names.
	mrs = jobMR()
	r = newFailedRig(mrs, jobOpened())
	r.l.JobFailed(context.Background(), failedJob([]string{"f-1"}))
	if len(mrs.closes) != 0 || len(mrs.calls) != 0 {
		t.Errorf("the Git host was called: %v %v", mrs.calls, mrs.closes)
	}
	// A record of another job is not this job's.
	mrs = jobMR()
	r = newFailedRig(mrs, mapHeads{"acme\x00" + testMRURL + "\x00job-2": openedHead{jobID: "job-2"}})
	r.l.JobFailed(context.Background(), failedJob([]string{"f-1"}))
	if len(mrs.closes) != 0 {
		t.Errorf("closed %v", mrs.closes)
	}
}

// The branch and the record prove that the job owns the merge request. The age
// does not enter: a merge request older than the claim, and a claim with no time,
// still close.
func TestJobGraphLink_ACloseDoesNotCompareTheAgeOfTheMergeRequest(t *testing.T) {
	for name, tc := range map[string]struct {
		created time.Time
		claimed time.Time
	}{
		"older than the claim": {created: testClaimedAt.Add(-time.Hour), claimed: testClaimedAt},
		"no claim time":        {created: testClaimedAt.Add(time.Minute), claimed: time.Time{}},
		"no creation time":     {created: time.Time{}, claimed: testClaimedAt},
	} {
		t.Run(name, func(t *testing.T) {
			mrs := &fakeMRReader{fact: fixloop.MergeFact{
				State: fixloop.MROpen, SourceBranch: "job/job-1", CreatedAt: tc.created,
			}}
			r := newFailedRig(mrs, jobOpened(testMRURL))
			ref := r.known["f-1"]
			ref.claimedAt = tc.claimed
			r.known["f-1"] = ref
			r.l.JobFailed(context.Background(), failedJob([]string{"f-1"}))
			if len(mrs.closes) != 1 || len(r.waitEvents()) != 0 {
				t.Errorf("closes = %v waits = %+v", mrs.closes, r.waitEvents())
			}
		})
	}
}

// A refusal that leaves a merge request open shows a wait, and the daemon does not
// close it. A merge request that is closed or merged needs neither.
func TestJobGraphLink_ARefusalThatLeavesTheMergeRequestOpenShowsAWait(t *testing.T) {
	refused := map[string]fixloop.MergeFact{
		"another branch": {State: fixloop.MROpen, SourceBranch: "feature/x"},
		"no branch":      {State: fixloop.MROpen, SourceBranchReason: "the branch is in a fork"},
		"old connector":  {State: fixloop.MROpen},
	}
	for name, fact := range refused {
		t.Run(name, func(t *testing.T) {
			mrs := &fakeMRReader{fact: fact}
			r := newFailedRig(mrs, jobOpened(testMRURL))
			r.l.JobFailed(context.Background(), failedJob([]string{"f-1"}))
			if len(mrs.closes) != 0 {
				t.Errorf("closed %v", mrs.closes)
			}
			w := r.waitEvents()
			if len(w) != 1 || !w[0].Waiting || w[0].MergeRequest != testMRURL || w[0].Reason == "" {
				t.Errorf("waits = %+v, want one that names the merge request", w)
			}
		})
	}
	for name, state := range map[string]string{"closed": fixloop.MRClosed, "merged": fixloop.MRMerged} {
		t.Run(name, func(t *testing.T) {
			mrs := &fakeMRReader{fact: fixloop.MergeFact{State: state, SourceBranch: "job/job-1"}}
			r := newFailedRig(mrs, jobOpened(testMRURL))
			r.l.JobFailed(context.Background(), failedJob([]string{"f-1"}))
			if len(mrs.closes) != 0 || len(r.waitEvents()) != 0 {
				t.Errorf("closes = %v waits = %+v", mrs.closes, r.waitEvents())
			}
		})
	}
}

// The wait shows on the findings of the job even when the claim is gone.
func TestJobGraphLink_AWaitShowsWhenTheClaimIsGone(t *testing.T) {
	mrs := jobMR()
	mrs.closeFailures = 1
	r := newFailedRig(mrs, jobOpened(testMRURL))
	ref := r.known["f-1"]
	ref.claim = ""
	r.known["f-1"] = ref
	r.l.JobFailed(context.Background(), failedJob([]string{"f-1"}))
	if w := r.waitEvents(); len(w) != 1 || w[0].ID != "f-1" {
		t.Fatalf("waits = %+v", w)
	}
}

// Two failed jobs whose closes both fail leave two waits. Each ends on its own
// success, and the retry waits for its back off.
func TestJobGraphLink_TwoFailedClosesLeaveTwoWaitsThatEndOnTheirOwn(t *testing.T) {
	mrs := jobMR()
	mrs.closeFailures = 1
	opened := mapHeads{}
	for k, v := range jobOpened(testMRURL) {
		opened[k] = v
	}
	opened["acme\x00g/r!9\x00job-2"] = openedHead{sha: testHeadSHA, sourceBranch: "job/job-2", jobID: "job-2"}
	r := newFailedRig(mrs, opened)

	r.l.JobFailed(context.Background(), failedJob([]string{"f-1"}))
	second := failedJob([]string{"f-1"})
	second.JobID = "job-2"
	r.l.JobFailed(context.Background(), second)
	// job-2 opened a merge request from its own branch. The host answers job-1's
	// branch, so the second close is refused: that is a second wait as well.
	if n := len(r.known["f-1"].closeWaits); n != 2 {
		t.Fatalf("waits = %v, want two", r.known["f-1"].closeWaits)
	}

	// Before the back off nothing is tried. After it, the closes run.
	r.l.RetryPending(context.Background())
	if len(mrs.closes) != 0 {
		t.Fatalf("a retry ran before the back off: %v", mrs.closes)
	}
	r.now = r.now.Add(closeFirstDelay + time.Second)
	r.l.RetryPending(context.Background())
	if len(mrs.closes) == 0 {
		t.Fatal("no retry after the back off")
	}
	// The job-1 close succeeded and ended its own wait. The job-2 wait stands.
	if _, still := r.known["f-1"].closeWaits[closeKey("job-1", testMRURL)]; still {
		t.Error("the wait of job-1 did not end")
	}
	if _, still := r.known["f-1"].closeWaits[closeKey("job-2", "g/r!9")]; !still {
		t.Error("the wait of job-2 ended with the other")
	}
}

// A close that always fails backs off, stops at closeMaxTries, and leaves the wait
// with the reason and the mark that the daemon gave up. No later pass tries it.
func TestJobGraphLink_ACloseBacksOffAndGivesUp(t *testing.T) {
	mrs := jobMR()
	mrs.closeFailures = 1000
	r := newFailedRig(mrs, jobOpened(testMRURL))
	r.l.JobFailed(context.Background(), failedJob([]string{"f-1"}))
	for range closeMaxTries + 3 {
		r.now = r.now.Add(closeMaxDelay + time.Second)
		r.l.RetryPending(context.Background())
	}
	w := r.waitEvents()
	last := w[len(w)-1]
	if !last.GaveUp || last.Attempts != closeMaxTries || !strings.Contains(last.Reason, "stopped") {
		t.Fatalf("last wait = %+v, want the give up after %d tries", last, closeMaxTries)
	}
	if len(w) != closeMaxTries {
		t.Errorf("%d wait events, want %d", len(w), closeMaxTries)
	}
	if closeDelay(1) != closeFirstDelay || closeDelay(2) != 2*closeFirstDelay || closeDelay(40) != closeMaxDelay {
		t.Errorf("delays = %v %v %v", closeDelay(1), closeDelay(2), closeDelay(40))
	}
	// The wait stays on the finding.
	if len(r.known["f-1"].closeWaits) != 1 {
		t.Errorf("waits = %v, want the wait to stay", r.known["f-1"].closeWaits)
	}
	r.l.mu.Lock()
	left := len(r.l.closes)
	r.l.mu.Unlock()
	if left != 0 {
		t.Errorf("%d closes stay pending after the give up", left)
	}
}

// After a restart the retry posts the comment of the first try, whatever the new
// code would say, so the duplicate check of the connector finds it.
func TestJobGraphLink_ARestartReusesTheCommentOfTheFirstTry(t *testing.T) {
	mrs := jobMR()
	mrs.closeFailures = 1
	r := newFailedRig(mrs, jobOpened(testMRURL))
	r.l.JobFailed(context.Background(), failedJob([]string{"f-1"}))
	w := r.waitEvents()
	if len(w) != 1 || w[0].Comment == "" {
		t.Fatalf("waits = %+v, want the comment in the wait", w)
	}
	first := w[0].Comment

	// The World keeps the wait. A new link adopts it. Its code knows no class.
	fresh := newFailedRig(mrs, nil)
	fresh.known["f-1"] = findingRef{scope: "s", status: brain.FindingStatusOpen,
		closeWaits: map[string]bool{closeKey("job-1", testMRURL): true}}
	fresh.l.Adopt("acme", []brain.FindingSnapshot{{
		ID: "f-1", Status: brain.FindingStatusOpen,
		FixFacts: brain.FixFacts{FixCloseWaits: []brain.FixCloseWait{{
			JobID: "job-1", MissionRunID: "run-1", MergeRequest: testMRURL, Comment: first, Attempts: 1,
		}}},
	}})
	fresh.l.RetryPending(context.Background())
	if len(mrs.closes) != 1 || mrs.closes[0] != testMRURL+": "+first {
		t.Fatalf("closes = %v, want the first comment %q", mrs.closes, first)
	}
	// A wait that the daemon gave up is not adopted.
	again := newFailedRig(jobMR(), nil)
	again.l.Adopt("acme", []brain.FindingSnapshot{{
		ID: "f-1", Status: brain.FindingStatusOpen,
		FixFacts: brain.FixFacts{FixCloseWaits: []brain.FixCloseWait{{
			JobID: "job-1", MergeRequest: testMRURL, GaveUp: true,
		}}},
	}})
	again.l.mu.Lock()
	n := len(again.l.closes)
	again.l.mu.Unlock()
	if n != 0 {
		t.Errorf("%d closes adopted after a give up", n)
	}
}

// A job that delivered nothing and has no record only records the attempt.
func TestJobGraphLink_AFailedJobWithNoRecordOnlyRecordsTheAttempt(t *testing.T) {
	mrs := jobMR()
	r := newFailedRig(mrs, jobOpened())
	r.l.JobFailed(context.Background(), failedJob([]string{"f-1"}))
	if len(mrs.closes) != 0 || len(mrs.calls) != 0 {
		t.Errorf("the Git host was called: %v %v", mrs.calls, mrs.closes)
	}
	if len(r.evs) != 1 {
		t.Errorf("events = %+v", r.evs)
	}
}

// An abandoned job counts as a failed attempt and its merge request is closed. A
// job that a cancel ended records no attempt, and its merge request is still
// closed.
func TestJobGraphLink_AnAbandonedJobIsAnAttemptUnlessCancelled(t *testing.T) {
	for name, tc := range map[string]struct {
		cancelled bool
		attempts  int
	}{"abandoned": {false, 1}, "cancelled": {true, 0}} {
		t.Run(name, func(t *testing.T) {
			mrs := jobMR()
			r := newFailedRig(mrs, jobOpened(testMRURL))
			f := failedJob([]string{"f-1"})
			f.Verdict, f.Class, f.Cancelled = "abandoned", jobnode.ReasonVerifierError, tc.cancelled
			r.l.JobFailed(context.Background(), f)
			if len(mrs.closes) != 1 || !strings.Contains(mrs.closes[0], "ended as abandoned") ||
				!strings.Contains(mrs.closes[0], "could not run") {
				t.Errorf("closes = %v", mrs.closes)
			}
			var got []brain.FixAttemptFailed
			for _, ev := range r.evs {
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

// The comment is fixed words for each class and each verdict, with no free text.
func TestFailedJobComment_IsAClosedSet(t *testing.T) {
	for _, class := range []string{
		jobnode.ReasonAcceptanceFailed, jobnode.ReasonVerifierError, jobnode.ReasonTimeLimit,
		jobnode.ReasonCancelled, jobnode.ReasonJobError, "something @alice made up",
	} {
		c := failedJobComment("job-1", "failed", class)
		const prefix = "Gibson closed this merge request. Fix job job-1 ended as failed."
		if strings.Contains(c, "@") || !strings.HasPrefix(c, prefix) {
			t.Errorf("class %q: %q", class, c)
		}
	}
	if c := failedJobComment("@alice evil", "x@y", jobnode.ReasonJobError); strings.Contains(c, "@") {
		t.Errorf("an id and a verdict that are not plain reached the comment: %q", c)
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
