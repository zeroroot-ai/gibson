// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"
	"unicode/utf8"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/fixloop"
	"github.com/zeroroot-ai/gibson/internal/engine/jobnode"
	"github.com/zeroroot-ai/gibson/internal/platform/job"
)

// fix_failed_job.go handles a fix job that closes as failed or abandoned
// (gibson#1674). An abandoned job counts as a failed attempt: it also spends
// budget and model time, and three abandoned jobs in a row (for example a
// verifier that is down) deserve a person as much as three refused fixes. A
// job that a cancel ended counts as no attempt.
//
// The job can still have opened merge requests. The daemon links nothing to the
// finding, so no slot, no close and no revert would ever reach them, and a person
// could merge a fix that the verifier refused. The daemon closes each merge
// request that its own record holds for the job, through the governed
// close_merge_request tool. The deliverable of the agent is never read: an agent
// names the merge request there, and could name one that is not its own. Only the
// daemon decides. An agent claim never moves a finding.

const (
	// maxFailReason bounds the reason that the daemon records.
	maxFailReason = 500
	// closeFirstDelay is the wait before the first retry of a close. The delay
	// doubles with each try, up to closeMaxDelay.
	closeFirstDelay = 30 * time.Second
	closeMaxDelay   = 30 * time.Minute
	// closeMaxTries is the number of tries after which the daemon stops. The wait
	// on the finding stays, with the reason, until a person acts.
	closeMaxTries = 8
)

// pendingClose is a merge request of a failed job that the daemon has not closed.
type pendingClose struct {
	tenant       string
	missionRunID string
	jobID        string
	mrKey        string
	// comment is the text of the first try. Each retry posts the same text, so the
	// duplicate check of the connector finds it, also after a restart.
	comment string
	// findings are the findings that show the wait.
	findings []string
	attempts int
	next     time.Time
}

// closeKey names one close: the job and the merge request.
func closeKey(jobID, mergeRequest string) string { return jobID + "\x00" + mergeRequest }

// JobFailed implements jobnode.CloseObserver. It records the failed attempt on
// each finding that the job held, then it closes the merge requests of the job.
// It runs before the node ends the claims, so the held findings are known.
func (l *jobGraphLink) JobFailed(ctx context.Context, f jobnode.FailedJob) {
	known := l.findings(f.TenantID)
	claim := jobnode.ClaimName(f.MissionRunID, f.NodeID)
	c := jobnode.ClosedJob{
		TenantID: f.TenantID, MissionRunID: f.MissionRunID, NodeID: f.NodeID, JobID: f.JobID, Inputs: f.Inputs,
	}
	now := l.clock()
	verdict := string(f.Verdict)
	if verdict == "" {
		verdict = string(job.VerdictFailed)
	}
	for _, id := range heldFindings(c, known, claim) {
		// A job that a cancel ended is no attempt at the fix. Its merge requests are
		// still closed below.
		if f.Cancelled || known[id].status != brain.FindingStatusOpen {
			continue
		}
		l.submit(f.TenantID, brain.FixAttemptFailed{
			ID: id, JobID: f.JobID, Verdict: verdict, Reason: clipReason(f.Reason), MissionID: f.MissionRunID, At: now,
		})
	}
	if l.opened == nil {
		l.logger.Warn("the daemon keeps no record of the merge requests of a failed fix job, so it closes none",
			"job_id", f.JobID)
		return
	}
	// The findings of the inputs show the wait, held or not: the claim can be gone.
	targets := inputFindings(f.Inputs, known)
	comment := failedJobComment(f.JobID, verdict, f.Class)
	for _, mr := range l.opened.OpenedBy(f.TenantID, f.JobID) {
		p := &pendingClose{
			tenant: f.TenantID, missionRunID: f.MissionRunID, jobID: f.JobID, mrKey: mr, comment: comment, findings: targets,
		}
		if err := l.closeOrphan(ctx, p); err != nil {
			l.closeFailed(p, err, now)
		}
	}
}

// inputFindings returns the inputs that are findings of the World, once each.
func inputFindings(inputs []string, known map[string]findingRef) []string {
	seen := map[string]bool{}
	var out []string
	for _, id := range inputs {
		if _, ok := known[id]; ok && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

// closeOrphan closes one merge request of a failed job. It does nothing for a
// merge request that is closed or merged already. A merge request that is open
// but not from the job branch is an error and stays open, so a wait shows it: the
// daemon never closes a merge request that it cannot tie to the job. The branch
// check is the only check of the age. The record of the daemon already proves that
// the job opened the merge request, so no time of the claim enters, and no clock
// skew or expired claim can refuse a close. A read or a close that fails is the
// error too.
func (l *jobGraphLink) closeOrphan(ctx context.Context, p *pendingClose) error {
	if l.mergeRequests == nil {
		return errors.New("the daemon has no connection to the Git host")
	}
	d := l.readTimeout
	if d == 0 {
		d = pendingReadTimeout
	}
	readCtx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	fact, err := l.mergeRequests.MergeRequest(readCtx, p.tenant, p.missionRunID, p.mrKey)
	if err != nil {
		return fmt.Errorf("the daemon could not read the merge request on the Git host: %w", err)
	}
	switch fact.State {
	case fixloop.MRClosed:
		return nil
	case fixloop.MRMerged:
		l.logger.Warn("the merge request of a failed fix job is merged, so the daemon does not close it",
			"job_id", p.jobID, "merge_request", p.mrKey)
		return nil
	}
	if why := closeRefusal(fact, jobnode.JobBranch(p.jobID)); why != "" {
		return errors.New(why)
	}
	closeCtx, cancelClose := context.WithTimeout(ctx, d)
	defer cancelClose()
	err = l.mergeRequests.CloseMergeRequest(closeCtx, p.tenant, p.missionRunID, p.mrKey, p.comment)
	if err != nil {
		return fmt.Errorf("the daemon could not close the merge request: %w", err)
	}
	return nil
}

// closeRefusal returns why an open merge request is not from the job branch, or
// "" when it is.
func closeRefusal(fact fixloop.MergeFact, branch string) string {
	switch {
	case fact.SourceBranch == "" && fact.SourceBranchReason != "":
		return "the Git host gave no source branch for the merge request: " + fact.SourceBranchReason
	case fact.SourceBranch == "":
		return errConnectorLacksMergeFields
	case fact.SourceBranch != branch:
		return fmt.Sprintf("the merge request comes from branch %q, not from the job branch %q", fact.SourceBranch, branch)
	}
	return ""
}

// The classes of a failed job, as the comment on the merge request says them. The
// set is closed. The comment never holds the text of a verifier report, because a
// report can hold an internal name, and an @name on a public repository notifies a
// person.
var failReasonText = map[string]string{
	jobnode.ReasonAcceptanceFailed: "the fix did not pass acceptance",
	jobnode.ReasonVerifierError:    "the check of the fix could not run",
	jobnode.ReasonTimeLimit:        "the job ran out of time",
	jobnode.ReasonCancelled:        "the mission was cancelled",
	jobnode.ReasonJobError:         "the job could not finish",
}

var plainID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// failedJobComment is the comment that the daemon posts on the merge request: the
// job id, the verdict and the class of the reason, in fixed words.
func failedJobComment(jobID, verdict, class string) string {
	reason, ok := failReasonText[class]
	if !ok {
		reason = "the job did not finish"
	}
	if !plainID.MatchString(jobID) {
		jobID = "unknown"
	}
	switch verdict {
	case string(job.VerdictFailed), string(job.VerdictAbandoned):
	default:
		verdict = "ended"
	}
	return fmt.Sprintf("Gibson closed this merge request. Fix job %s ended as %s. Reason: %s.", jobID, verdict, reason)
}

// closeDelay is the wait before the next try, after the given number of tries.
func closeDelay(tries int) time.Duration {
	d := closeFirstDelay
	for i := 1; i < tries && d < closeMaxDelay; i++ {
		d *= 2
	}
	return min(d, closeMaxDelay)
}

// closeFailed counts a failed try, shows the wait on each finding of the job and
// keeps the close for RetryPending. After closeMaxTries the daemon stops. The wait
// stays, with the reason, until a person acts.
func (l *jobGraphLink) closeFailed(p *pendingClose, cause error, now time.Time) {
	p.attempts++
	gaveUp := p.attempts >= closeMaxTries
	reason := clipReason(cause.Error())
	if gaveUp {
		reason = fmt.Sprintf("the daemon stopped after %d tries: %s", p.attempts, reason)
	}
	l.logger.Warn("the daemon could not close a merge request of a failed fix job",
		"job_id", p.jobID, "merge_request", p.mrKey, "attempts", p.attempts, "gave_up", gaveUp, "error", cause)
	l.mu.Lock()
	if l.closes == nil {
		l.closes = map[string]*pendingClose{}
	}
	if gaveUp {
		delete(l.closes, closeKey(p.jobID, p.mrKey))
	} else {
		p.next = now.Add(closeDelay(p.attempts))
		l.closes[closeKey(p.jobID, p.mrKey)] = p
	}
	l.mu.Unlock()
	if len(p.findings) == 0 {
		l.logger.Error("no finding shows the open merge request of a failed fix job",
			"job_id", p.jobID, "merge_request", p.mrKey)
	}
	for _, id := range p.findings {
		l.submit(p.tenant, brain.FixCloseWaiting{
			ID: id, JobID: p.jobID, MergeRequest: p.mrKey, Waiting: true, Reason: reason, Comment: p.comment,
			Attempts: p.attempts, GaveUp: gaveUp, MissionID: p.missionRunID, At: now,
		})
	}
}

// retryCloses tries each close again that is due. A close is safe to repeat,
// because the tool succeeds on a merge request that is closed already and it posts
// the same comment once.
func (l *jobGraphLink) retryCloses(ctx context.Context) {
	l.mu.Lock()
	list := make([]*pendingClose, 0, len(l.closes))
	for _, p := range l.closes {
		list = append(list, p)
	}
	l.mu.Unlock()
	for _, p := range list {
		now := l.clock()
		if now.Before(p.next) {
			continue
		}
		known := l.findings(p.tenant)
		var waiting []string
		for _, id := range p.findings {
			if known[id].closeWaits[closeKey(p.jobID, p.mrKey)] {
				waiting = append(waiting, id)
			}
		}
		if len(waiting) == 0 {
			// No finding shows the wait any more, so a person ended it.
			l.dropClose(p)
			continue
		}
		if err := l.closeOrphan(ctx, p); err != nil {
			p.findings = waiting
			l.closeFailed(p, err, now)
			continue
		}
		for _, id := range waiting {
			l.submit(p.tenant, brain.FixCloseWaiting{
				ID: id, JobID: p.jobID, MergeRequest: p.mrKey, MissionID: p.missionRunID, At: now,
			})
		}
		l.dropClose(p)
	}
}

func (l *jobGraphLink) dropClose(p *pendingClose) {
	l.mu.Lock()
	delete(l.closes, closeKey(p.jobID, p.mrKey))
	l.mu.Unlock()
}

// adoptCloses rebuilds the pending closes of a tenant after the engine hydrated
// its World, so a restart does not lose the retry of a close. A close that the
// daemon gave up stays a wait and is not tried again. The comment comes from the
// wait, so a retry posts the text of the first try.
func (l *jobGraphLink) adoptCloses(tenant string, findings []brain.FindingSnapshot) {
	rebuilt := map[string]*pendingClose{}
	for _, f := range findings {
		for _, w := range f.FixCloseWaits {
			if w.GaveUp {
				continue
			}
			k := closeKey(w.JobID, w.MergeRequest)
			p, ok := rebuilt[k]
			if !ok {
				p = &pendingClose{
					tenant: tenant, missionRunID: w.MissionRunID, jobID: w.JobID, mrKey: w.MergeRequest,
					comment: w.Comment, attempts: w.Attempts,
				}
				rebuilt[k] = p
			}
			p.findings = append(p.findings, f.ID)
		}
	}
	if len(rebuilt) == 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closes == nil {
		l.closes = map[string]*pendingClose{}
	}
	for k, p := range rebuilt {
		l.closes[k] = p
		l.logger.Info("a pending close of a failed fix job was rebuilt after the start of the daemon",
			"tenant", tenant, "job_id", p.jobID, "merge_request", p.mrKey)
	}
}

// clipReason cuts a reason at maxFailReason bytes, on a rune boundary.
func clipReason(s string) string {
	if len(s) <= maxFailReason {
		return s
	}
	cut := maxFailReason
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "..."
}
