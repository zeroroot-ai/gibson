// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package harness — callback_job_driver.go
//
// The half of the job surface that a DISPATCHED AGENT calls to drive a bank
// (ADR-0119): open a job, send it the next input, and close it with a verdict.
//
// The three handlers mirror gibson.job.v1.JobService. They do not copy its
// checks. They hand the call to the same server that serves JobService, with
// the verified identity of the caller on the context, so one implementation
// makes each authorization decision and writes each record.
//
// One rule is checked here before the hand-off, because only this service can
// see it: the worker of a job never closes its own job. A member runs a turn
// with the grant of the sender of that turn, and the sender is often the
// opener, who may close the job. The grant and the run on the verified
// context say which job the caller works on, so CloseJob refuses that job.
package harness

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	jobpb "github.com/zeroroot-ai/sdk/api/gen/gibson/job/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// JobDriver is the part of JobService that a dispatched agent drives over the
// callback service. The daemon backs it with the server that serves
// JobService, so the two entry points apply the same checks.
type JobDriver interface {
	OpenJob(ctx context.Context, req *jobpb.OpenJobRequest) (*jobpb.OpenJobResponse, error)
	SendInput(ctx context.Context, req *jobpb.SendInputRequest) (*jobpb.SendInputResponse, error)
	CloseJob(ctx context.Context, req *jobpb.CloseJobRequest) (*jobpb.CloseJobResponse, error)
}

// WithJobDriver wires the JobService implementation that the three driver
// callbacks hand their calls to.
func WithJobDriver(d JobDriver) CallbackServiceOption {
	return func(c *HarnessCallbackService) {
		if d != nil {
			c.jobDriver = d
		}
	}
}

func (noBankSurface) OpenJob(context.Context, *jobpb.OpenJobRequest) (*jobpb.OpenJobResponse, error) {
	return nil, ErrNoBankSurface
}

func (noBankSurface) SendInput(context.Context, *jobpb.SendInputRequest) (*jobpb.SendInputResponse, error) {
	return nil, ErrNoBankSurface
}

func (noBankSurface) CloseJob(context.Context, *jobpb.CloseJobRequest) (*jobpb.CloseJobResponse, error) {
	return nil, ErrNoBankSurface
}

// jobDriverError maps an error of the job driver for the caller. The driver
// already answers with gRPC status errors, and they pass through unchanged.
func jobDriverError(err error) error {
	if errors.Is(err, ErrNoBankSurface) {
		return status.Error(codes.FailedPrecondition, "this daemon serves no jobs")
	}
	return err
}

// OpenJob opens a job on a bank from a dispatched agent. The caller needs
// can_send on the bank, as for JobService.OpenJob.
func (s *HarnessCallbackService) OpenJob(ctx context.Context, req *harnesspb.OpenJobRequest) (*harnesspb.OpenJobResponse, error) {
	resp, err := s.jobDriver.OpenJob(ctx, &jobpb.OpenJobRequest{
		BankId: req.GetBankId(), MemberId: req.GetMemberId(), Spec: req.GetSpec(),
	})
	if err != nil {
		return nil, jobDriverError(err)
	}
	return &harnesspb.OpenJobResponse{Job: resp.GetJob()}, nil
}

// SendInput sends the next message to an open job from a dispatched agent.
// The caller needs can_send on the job, as for JobService.SendInput.
func (s *HarnessCallbackService) SendInput(ctx context.Context, req *harnesspb.SendInputRequest) (*harnesspb.SendInputResponse, error) {
	resp, err := s.jobDriver.SendInput(ctx, &jobpb.SendInputRequest{
		JobId: req.GetJobId(), Message: req.GetMessage(), Kind: req.GetKind(),
	})
	if err != nil {
		return nil, jobDriverError(err)
	}
	return &harnesspb.SendInputResponse{Input: resp.GetInput()}, nil
}

// CloseJob closes a job with a verdict and a score from a dispatched agent.
// The caller needs can_close on the job, as for JobService.CloseJob, and the
// caller must not be the worker of that job.
func (s *HarnessCallbackService) CloseJob(ctx context.Context, req *harnesspb.CloseJobRequest) (*harnesspb.CloseJobResponse, error) {
	if err := s.refuseWorkerClose(ctx, req.GetContext(), req.GetJobId()); err != nil {
		return nil, err
	}
	resp, err := s.jobDriver.CloseJob(ctx, &jobpb.CloseJobRequest{
		JobId: req.GetJobId(), Verdict: req.GetVerdict(), Score: req.GetScore(),
	})
	if err != nil {
		return nil, jobDriverError(err)
	}
	return &harnesspb.CloseJobResponse{Job: resp.GetJob()}, nil
}

// errWorkerClosesOwnJob is the refusal for a worker that tries to close the
// job that it works on.
var errWorkerClosesOwnJob = status.Error(codes.PermissionDenied,
	"the worker of a job cannot close it: a scorer, the opener or the bank owner closes a job")

// refuseWorkerClose refuses a close that comes from the worker of the job.
//
// Two facts on the verified context name the worker, and neither comes from
// the request body:
//
//   - A turn grant has the job id as its task id. A close of that job under
//     that grant comes from inside a turn of the job.
//   - The run of the caller backs a bank member, and that member holds the
//     job.
//
// A lookup that cannot answer refuses. "We could not tell" is not "not the
// worker".
func (s *HarnessCallbackService) refuseWorkerClose(ctx context.Context, info *harnesspb.ContextInfo, jobID string) error {
	if jobID == "" {
		return status.Error(codes.InvalidArgument, "job_id is required")
	}
	if claims, ok := TaskGrantClaimsFromContext(ctx); ok && claims.TaskID == jobID {
		return errWorkerClosesOwnJob
	}

	tenantID := auth.TenantStringFromContext(ctx)
	if tenantID == "" || tenantID == auth.SystemTenantString {
		return status.Error(codes.PermissionDenied, "no tenant in context")
	}
	runID := info.GetMissionRunId()
	if runID == "" {
		runID = info.GetTaskId()
	}
	if runID == "" {
		// A caller with no run backs no member.
		return nil
	}
	memberID, _, err := s.members.MemberByRun(ctx, tenantID, runID)
	switch {
	case errors.Is(err, ErrNotAMember):
		return nil
	case errors.Is(err, ErrNoBankSurface):
		return status.Error(codes.FailedPrecondition, "this daemon serves no banks")
	case err != nil:
		return status.Errorf(codes.Unavailable, "close refused: cannot resolve the calling member: %v", err)
	}
	j, err := s.jobs.Get(ctx, tenantID, jobID)
	if err != nil {
		return jobCallbackError(err)
	}
	if j.MemberID == memberID {
		return errWorkerClosesOwnJob
	}
	return nil
}
