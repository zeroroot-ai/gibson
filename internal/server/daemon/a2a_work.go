// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/jobnode"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/platform/job"
	"github.com/zeroroot-ai/gibson/internal/server/a2aserver"
	jobpb "github.com/zeroroot-ai/sdk/api/gen/gibson/job/v1"
)

// The work kinds that an A2A message adds to a mission, next to the agent kind.
// A message aimed at a bank opens a job on it. A message that names a job of a
// bank sends the next turn to that job. The old DelegateToAgent target selector
// did the same (ADR-0119).
const (
	workKindBank    = "bank"
	workKindJobTurn = "jobturn"
)

// a2aTurnTimeout bounds a bank or job turn that the work item gives no bound.
// A turn is a model's worth of work, not a mission's.
const a2aTurnTimeout = time.Hour

// a2aTurnPoll is how often the wait reads the events of the job.
const a2aTurnPoll = 2 * time.Second

// a2aTaskID returns the task id for a dispatch. A work item that an A2A message
// started gets the id from its work id. A mission node keeps a fresh id.
func a2aTaskID(req brain.DispatchRequest) types.ID {
	if req.ParentID == "" {
		return types.NewID()
	}
	return types.ID(a2aserver.TaskIDOf(req.WorkID))
}

// trackWork returns the context of one dispatch. For A2A work the context can
// be canceled by CancelWork. The release function ends the context and drops
// the entry.
func (b *brainExecutor) trackWork(parent context.Context, req brain.DispatchRequest) (context.Context, func()) {
	if req.ParentID == "" {
		return parent, func() {}
	}
	ctx, cancel := context.WithCancel(parent)
	b.cancelMu.Lock()
	if b.cancels == nil {
		b.cancels = map[string]context.CancelFunc{}
	}
	b.cancels[req.WorkID] = cancel
	b.cancelMu.Unlock()
	return ctx, func() {
		cancel()
		b.cancelMu.Lock()
		delete(b.cancels, req.WorkID)
		b.cancelMu.Unlock()
	}
}

// CancelWork stops the run of one A2A work item. It reports whether the item
// was running here.
func (b *brainExecutor) CancelWork(workID string) bool {
	b.cancelMu.Lock()
	cancel, ok := b.cancels[workID]
	b.cancelMu.Unlock()
	if ok {
		cancel()
	}
	return ok
}

// bankTurnInput is the input of a bank or job work item.
type bankTurnInput struct {
	// Goal is the goal of a new job, or the message of the next turn.
	Goal string `json:"goal"`
	// Sender is the subject of the caller. The job records it as its opener.
	Sender string `json:"sender"`
}

// dispatchBankTurn opens a job on a bank, or sends the next turn to a job, and
// waits for the turn to end. It returns the outcome as JSON text. A bank job
// that is waiting for the next message has not failed, so the work is done and
// its result names the job id.
func (b *brainExecutor) dispatchBankTurn(ctx context.Context, bind *missionBinding, req brain.DispatchRequest) (string, error) {
	if b.jobs == nil {
		return "", errors.New("this daemon serves no jobs")
	}
	store, err := b.jobs()
	if err != nil {
		return "", fmt.Errorf("job store: %w", err)
	}
	var in bankTurnInput
	if err := json.Unmarshal([]byte(req.Input), &in); err != nil {
		return "", fmt.Errorf("read the input of the turn: %w", err)
	}
	if in.Goal == "" || in.Sender == "" {
		return "", errors.New("a turn needs a message and a sender")
	}
	sender := job.Principal{Kind: job.PrincipalComponent, ID: in.Sender}
	var jobID string
	var since int64
	switch req.Kind {
	case workKindBank:
		opened, err := store.Open(ctx, bind.tenant, job.OpenInput{
			BankID: req.Target, Spec: &jobpb.JobSpec{Goal: in.Goal}, OpenedBy: sender,
		})
		if err != nil {
			return "", fmt.Errorf("open a job on bank %s: %w", req.Target, err)
		}
		jobID = opened.ID
	case workKindJobTurn:
		jobID = req.Target
		// The wait starts after the input that we send, so the end of an
		// earlier turn is not read as the end of this one.
		before, err := store.Events(ctx, bind.tenant, jobID, 0, 1000)
		if err != nil {
			return "", fmt.Errorf("read the events of job %s: %w", jobID, err)
		}
		for _, ev := range before {
			since = ev.Seq
		}
		if _, err := store.Send(ctx, bind.tenant, job.SendInput{
			JobID: jobID, Kind: job.InputTurn, Message: in.Goal, Sender: sender,
		}); err != nil {
			return "", fmt.Errorf("send a turn to job %s: %w", jobID, err)
		}
	default:
		return "", fmt.Errorf("unknown turn kind %q", req.Kind)
	}
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = a2aTurnTimeout
	}
	wctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if _, err := jobnode.WaitForTurn(wctx, store, bind.tenant, jobID, since, a2aTurnPoll); err != nil {
		return "", fmt.Errorf("wait for the turn of job %s: %w", jobID, err)
	}
	j, err := store.Get(ctx, bind.tenant, jobID)
	if err != nil {
		return "", fmt.Errorf("read job %s: %w", jobID, err)
	}
	refs := make([]map[string]string, 0, len(j.Deliverables))
	for _, d := range j.Deliverables {
		refs = append(refs, map[string]string{"kind": d.GetKind().String(), "ref": d.GetRef(), "url": d.GetUrl()})
	}
	out, err := json.Marshal(map[string]any{
		"job_id": j.ID, "member_id": j.MemberID, "state": string(j.State), "verdict": string(j.Verdict),
		"score": j.Score, "claude_session_id": j.ClaudeSessionID, "deliverables": refs,
	})
	if err != nil {
		return "", fmt.Errorf("render the outcome of job %s: %w", jobID, err)
	}
	return string(out), nil
}
