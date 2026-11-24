// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/fixloop"
	"github.com/zeroroot-ai/gibson/internal/engine/jobnode"
	"github.com/zeroroot-ai/gibson/internal/platform/job"
)

// fix_failed_job.go handles a fix job that closes as failed (gibson#1674).
//
// The job can still have opened a merge request. The daemon links nothing to
// the finding, so no slot, no close and no revert would ever reach that merge
// request, and a person could merge a fix that the verifier refused. The daemon
// closes it through the governed close_merge_request tool. It also records the
// attempt on each finding that the job held. Only the daemon decides. An agent
// claim never moves a finding.

// maxFailReason bounds the reason that the daemon records and posts.
const maxFailReason = 500

// pendingClose is a failed job whose merge request the daemon could not close.
type pendingClose struct {
	tenant       string
	missionRunID string
	jobID        string
	mrKey        string
	reason       string
	claimedAt    time.Time
	findings     []string
}

// JobFailed implements jobnode.CloseObserver. It records the failed attempt on
// each finding that the job held, then it closes the merge request of the job.
// It runs before the node ends the claims, so the held findings are known.
func (l *jobGraphLink) JobFailed(ctx context.Context, f jobnode.FailedJob) {
	known := l.findings(f.TenantID)
	claim := jobnode.ClaimName(f.MissionRunID, f.NodeID)
	c := jobnode.ClosedJob{
		TenantID: f.TenantID, MissionRunID: f.MissionRunID, NodeID: f.NodeID, JobID: f.JobID,
		Inputs: f.Inputs, Deliverables: f.Deliverables,
	}
	held := heldFindings(c, known, claim)
	now := l.clock()
	reason := clipReason(f.Reason)
	for _, id := range held {
		if known[id].status != brain.FindingStatusOpen {
			continue
		}
		l.submit(f.TenantID, brain.FixAttemptFailed{
			ID: id, JobID: f.JobID, Verdict: string(job.VerdictFailed), Reason: reason, MissionID: f.MissionRunID, At: now,
		})
	}
	mrKey, _, _ := deliveredMergeRequest(c)
	if mrKey == "" {
		return
	}
	if len(held) == 0 {
		l.logger.Warn("a failed fix job opened a merge request and holds no finding, so its age cannot be checked",
			"job_id", f.JobID, "merge_request", mrKey, "claim", claim)
	}
	var claimedAt time.Time
	for _, id := range held {
		if t := known[id].claimedAt; t.After(claimedAt) {
			claimedAt = t
		}
	}
	p := &pendingClose{
		tenant: f.TenantID, missionRunID: f.MissionRunID, jobID: f.JobID, mrKey: mrKey,
		reason: reason, claimedAt: claimedAt, findings: held,
	}
	if err := l.closeOrphan(ctx, p); err != nil {
		l.markCloseWaiting(p, err, now)
	}
}

// closeOrphan closes the merge request of a failed job. It does nothing for a
// merge request that is closed or merged already. It also does nothing for a
// merge request that is not the work of the job: an agent names the merge
// request in its deliverable, so the daemon checks the branch and the age on
// the Git host first, as the link does (review B1). A read or a close that
// fails is the error.
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
	// A refused merge request is open on the host. The check below needs the open state.
	fact.State = fixloop.MROpen
	if why := mergeRequestRefusal(fact, jobnode.JobBranch(p.jobID), p.claimedAt); why != "" {
		l.logger.Warn("the merge request of a failed fix job is not the work of the job, so the daemon does not close it",
			"job_id", p.jobID, "merge_request", p.mrKey, "reason", why)
		return nil
	}
	closeCtx, cancelClose := context.WithTimeout(ctx, d)
	defer cancelClose()
	err = l.mergeRequests.CloseMergeRequest(closeCtx, p.tenant, p.missionRunID, p.mrKey, failedJobComment(p))
	if err != nil {
		return fmt.Errorf("the daemon could not close the merge request: %w", err)
	}
	return nil
}

// failedJobComment is the comment that the daemon posts on the merge request.
// It names the job and the reason.
func failedJobComment(p *pendingClose) string {
	return fmt.Sprintf("Gibson closed this merge request. Fix job %s failed. Reason: %s", p.jobID, p.reason)
}

// markCloseWaiting keeps the failed job for RetryPending and records the wait
// on each finding that the job held. The wait names the merge request.
func (l *jobGraphLink) markCloseWaiting(p *pendingClose, cause error, now time.Time) {
	l.logger.Warn("the daemon could not close the merge request of a failed fix job",
		"job_id", p.jobID, "merge_request", p.mrKey, "error", cause)
	l.mu.Lock()
	if l.closes == nil {
		l.closes = map[string]*pendingClose{}
	}
	l.closes[p.jobID] = p
	l.mu.Unlock()
	for _, id := range p.findings {
		l.submit(p.tenant, brain.FixCloseWaiting{
			ID: id, JobID: p.jobID, MergeRequest: p.mrKey, Waiting: true, Reason: clipReason(cause.Error()),
			ClaimedAt: p.claimedAt, MissionID: p.missionRunID, At: now,
		})
	}
}

// retryCloses tries the close of each failed job again. A close is safe to
// repeat, because the tool succeeds on a merge request that is closed already.
func (l *jobGraphLink) retryCloses(ctx context.Context) {
	l.mu.Lock()
	list := make([]*pendingClose, 0, len(l.closes))
	for _, p := range l.closes {
		list = append(list, p)
	}
	l.mu.Unlock()
	for _, p := range list {
		known := l.findings(p.tenant)
		var waiting []string
		for _, id := range p.findings {
			if known[id].closeWaitJob == p.jobID {
				waiting = append(waiting, id)
			}
		}
		if len(waiting) == 0 {
			// No finding shows the wait any more, so nothing needs the close.
			l.dropClose(p.jobID)
			continue
		}
		if err := l.closeOrphan(ctx, p); err != nil {
			l.logger.Warn("the close of the merge request of a failed fix job failed again",
				"job_id", p.jobID, "merge_request", p.mrKey, "error", err)
			continue
		}
		now := l.clock()
		for _, id := range waiting {
			l.submit(p.tenant, brain.FixCloseWaiting{
				ID: id, JobID: p.jobID, MergeRequest: p.mrKey, MissionID: p.missionRunID, At: now,
			})
		}
		l.dropClose(p.jobID)
	}
}

func (l *jobGraphLink) dropClose(jobID string) {
	l.mu.Lock()
	delete(l.closes, jobID)
	l.mu.Unlock()
}

// adoptCloses rebuilds the pending closes of a tenant after the engine hydrated
// its World, so a restart does not lose the retry of a close.
func (l *jobGraphLink) adoptCloses(tenant string, findings []brain.FindingSnapshot) {
	rebuilt := map[string]*pendingClose{}
	for _, f := range findings {
		w := f.FixCloseWait
		if w.JobID == "" {
			continue
		}
		p, ok := rebuilt[w.JobID]
		if !ok {
			reason := w.Reason
			for _, a := range f.FixAttempts {
				if a.JobID == w.JobID {
					reason = a.Reason
				}
			}
			p = &pendingClose{
				tenant: tenant, missionRunID: w.MissionRunID, jobID: w.JobID, mrKey: w.MergeRequest,
				reason: reason, claimedAt: w.ClaimedAt,
			}
			rebuilt[w.JobID] = p
		}
		p.findings = append(p.findings, f.ID)
	}
	if len(rebuilt) == 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closes == nil {
		l.closes = map[string]*pendingClose{}
	}
	for id, p := range rebuilt {
		l.closes[id] = p
		l.logger.Info("a pending close of a failed fix job was rebuilt after the start of the daemon",
			"tenant", tenant, "job_id", id, "merge_request", p.mrKey)
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
