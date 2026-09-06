// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"errors"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/jobnode"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/platform/job"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	jobpb "github.com/zeroroot-ai/sdk/api/gen/gibson/job/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// The DelegateToAgent target selector (ADR-0019 decision 15, gibson#1713).
//
// A caller may aim a delegation at three places: an ephemeral sandbox (the
// path that existed before banks), a bank (open a job on it and wait for the
// first turn), or an open job (send the next turn and wait for it). The last
// two are one wait, shared with the job node executor.

// delegateTurnTimeout bounds a bank or job delegation whose task names no
// timeout. A turn is a model's worth of work, not a mission's.
const delegateTurnTimeout = time.Hour

// delegateTurnPoll is how often the wait reads the job's events.
const delegateTurnPoll = 2 * time.Second

// delegateToTarget routes a delegation that names a bank or a job. It answers
// (nil, nil) for the ephemeral target, which the caller serves as before.
func (s *HarnessCallbackService) delegateToTarget(ctx context.Context, req *harnesspb.DelegateToAgentRequest) (*harnesspb.DelegateToAgentResponse, error) {
	switch t := req.GetTarget().(type) {
	case *harnesspb.DelegateToAgentRequest_BankId:
		return s.delegateToBank(ctx, req, t.BankId)
	case *harnesspb.DelegateToAgentRequest_JobId:
		return s.delegateToJob(ctx, req, t.JobId)
	default:
		return nil, nil //nolint:nilnil // the ephemeral target is the caller's own path
	}
}

// delegateToBank opens a job on the bank as the calling component and waits
// for its first turn. The caller needs can_send on the bank, which is the
// same right JobService.OpenJob asks for.
func (s *HarnessCallbackService) delegateToBank(ctx context.Context, req *harnesspb.DelegateToAgentRequest, bankID string) (*harnesspb.DelegateToAgentResponse, error) {
	tenant, caller, err := s.delegatingCaller(ctx)
	if err != nil {
		return nil, err
	}
	if bankID == "" {
		return nil, status.Error(codes.InvalidArgument, "bank_id is required")
	}
	if err := s.authorizeDelegateTarget(ctx, caller, "can_send", "bank:"+bankID); err != nil {
		return nil, err
	}
	task := protoTaskToTask(req.GetTask())
	goal := task.Goal
	if goal == "" {
		goal = task.Description
	}
	if goal == "" {
		return nil, status.Error(codes.InvalidArgument, "a job needs a goal: set task.goal")
	}
	opened, err := s.jobs.Open(ctx, tenant, job.OpenInput{
		BankID: bankID, Spec: &jobpb.JobSpec{Goal: goal},
		OpenedBy: job.Principal{Kind: job.PrincipalComponent, ID: caller},
	})
	if err != nil {
		return nil, jobCallbackError(err)
	}
	return s.waitAndAnswer(ctx, tenant, opened.ID, 0, task.Timeout)
}

// delegateToJob sends the next turn to an open job and waits for it. The
// caller needs can_send on the job.
func (s *HarnessCallbackService) delegateToJob(ctx context.Context, req *harnesspb.DelegateToAgentRequest, jobID string) (*harnesspb.DelegateToAgentResponse, error) {
	tenant, caller, err := s.delegatingCaller(ctx)
	if err != nil {
		return nil, err
	}
	if jobID == "" {
		return nil, status.Error(codes.InvalidArgument, "job_id is required")
	}
	if err := s.authorizeDelegateTarget(ctx, caller, "can_send", "job:"+jobID); err != nil {
		return nil, err
	}
	task := protoTaskToTask(req.GetTask())
	message := task.Goal
	if message == "" {
		message = task.Description
	}
	if message == "" {
		return nil, status.Error(codes.InvalidArgument, "a turn needs a message: set task.goal")
	}
	// The wait starts after the input we send, so an earlier turn's end is
	// not read as this one's.
	before, err := s.jobs.Events(ctx, tenant, jobID, 0, 1000)
	if err != nil {
		return nil, jobCallbackError(err)
	}
	var since int64
	for _, ev := range before {
		since = ev.Seq
	}
	if _, err := s.jobs.Send(ctx, tenant, job.SendInput{
		JobID: jobID, Kind: job.InputTurn, Message: message,
		Sender: job.Principal{Kind: job.PrincipalComponent, ID: caller},
	}); err != nil {
		return nil, jobCallbackError(err)
	}
	return s.waitAndAnswer(ctx, tenant, jobID, since, task.Timeout)
}

// waitAndAnswer waits for the turn to end and renders the job as the result.
func (s *HarnessCallbackService) waitAndAnswer(ctx context.Context, tenant, jobID string, since int64, timeout time.Duration) (*harnesspb.DelegateToAgentResponse, error) {
	if timeout <= 0 {
		timeout = delegateTurnTimeout
	}
	wctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if _, err := jobnode.WaitForTurn(wctx, s.jobs, tenant, jobID, since, delegateTurnPoll); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, status.Errorf(codes.DeadlineExceeded, "job %s: the turn did not end within %s", jobID, timeout)
		}
		return nil, status.Errorf(codes.Unavailable, "job %s: %v", jobID, err)
	}
	j, err := s.jobs.Get(ctx, tenant, jobID)
	if err != nil {
		return nil, jobCallbackError(err)
	}
	taskID := types.NewID()
	if parsed, perr := types.ParseID(jobID); perr == nil {
		taskID = parsed
	}
	result := agent.NewResult(taskID)
	result.Status = agent.ResultStatusCompleted
	result.CompletedAt = time.Now()
	result.Output = map[string]any{
		"job_id": j.ID, "state": string(j.State), "verdict": string(j.Verdict), "score": j.Score,
		"claude_session_id": j.ClaudeSessionID, "deliverables": deliverableRefs(j.Deliverables),
	}
	return &harnesspb.DelegateToAgentResponse{
		Result:   resultToProtoResult(result),
		JobId:    j.ID,
		MemberId: j.MemberID,
	}, nil
}

func deliverableRefs(ds []*jobpb.Deliverable) []map[string]string {
	out := make([]map[string]string, 0, len(ds))
	for _, d := range ds {
		out = append(out, map[string]string{"kind": deliverableKindName(d.GetKind()), "ref": d.GetRef(), "url": d.GetUrl()})
	}
	return out
}

// delegatingCaller reads the tenant and the component behind a delegation.
func (s *HarnessCallbackService) delegatingCaller(ctx context.Context) (tenant, caller string, err error) {
	tenant = auth.TenantStringFromContext(ctx)
	if tenant == "" || tenant == auth.SystemTenantString {
		return "", "", status.Error(codes.PermissionDenied, "no tenant in context")
	}
	identity, err := auth.IdentityFromContext(ctx)
	if err != nil || identity.Subject == "" {
		return "", "", status.Error(codes.PermissionDenied, "no caller identity")
	}
	return tenant, identity.Subject, nil
}

// authorizeDelegateTarget asks FGA whether the caller holds the relation on
// the bank or the job. No authorizer is a deny: an undecidable question is
// not a yes.
func (s *HarnessCallbackService) authorizeDelegateTarget(ctx context.Context, caller, relation, object string) error {
	if s.componentAuthorizer == nil {
		return status.Error(codes.PermissionDenied, "delegation denied: authorization unavailable")
	}
	allowed, err := s.componentAuthorizer.Check(ctx, callbackFGAUser(caller), relation, object)
	if err != nil {
		return status.Errorf(codes.Unavailable, "delegation: authorization check failed: %v", err)
	}
	if !allowed {
		// Not found rather than denied: a caller that may not send to a bank
		// or a job does not get to learn that it exists.
		return status.Errorf(codes.NotFound, "no such target %s", object)
	}
	return nil
}
