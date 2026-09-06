// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/job"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	typespb "github.com/zeroroot-ai/sdk/api/gen/gibson/types/v1"
)

func delegateService(t *testing.T, jobs *fakeJobs, allow bool) (*HarnessCallbackService, *recordingAuthorizer) {
	t.Helper()
	az := &recordingAuthorizer{allow: allow}
	s := NewHarnessCallbackService(nil, WithJobSurface(jobs))
	s.componentAuthorizer = az
	return s, az
}

func bankTarget(goal, bankID string) *harnesspb.DelegateToAgentRequest {
	return &harnesspb.DelegateToAgentRequest{
		Name: "claude", Task: &typespb.Task{Goal: goal},
		Target: &harnesspb.DelegateToAgentRequest_BankId{BankId: bankID},
	}
}

func jobTarget(goal, jobID string) *harnesspb.DelegateToAgentRequest {
	return &harnesspb.DelegateToAgentRequest{
		Name: "claude", Task: &typespb.Task{Goal: goal},
		Target: &harnesspb.DelegateToAgentRequest_JobId{JobId: jobID},
	}
}

// TestDelegateToAgent_BankTargetOpensAJobAndWaitsForTheFirstTurn asserts the
// bank target opens the job as the calling component, needs can_send on the
// bank, and answers with the job and its member once the turn ends.
func TestDelegateToAgent_BankTargetOpensAJobAndWaitsForTheFirstTurn(t *testing.T) {
	jobs := newFakeJobs()
	jobs.events["job-new"] = []*job.Event{{Seq: 1, Kind: job.EventState, State: job.StateWaiting}}
	s, az := delegateService(t, jobs, true)

	resp, err := s.DelegateToAgent(callerCtx(t, "agent_principal:zerocool", "acme"), bankTarget("fix the build", "bank-1"))
	if err != nil {
		t.Fatalf("DelegateToAgent: %v", err)
	}
	if resp.GetJobId() != "job-new" || resp.GetMemberId() != "m-1" || resp.GetResult() == nil {
		t.Fatalf("resp = %+v", resp)
	}
	if az.gotRelation != "can_send" || az.gotObject != "bank:bank-1" {
		t.Errorf("asked FGA %s on %s", az.gotRelation, az.gotObject)
	}
	if len(jobs.opened) != 1 || jobs.opened[0].OpenedBy.Kind != job.PrincipalComponent || jobs.opened[0].Spec.GetGoal() != "fix the build" {
		t.Errorf("opened = %+v", jobs.opened)
	}
}

// TestDelegateToAgent_JobTargetSendsTheNextTurn asserts the job target sends
// the message as a turn from the caller and waits for that turn, not an
// earlier one.
func TestDelegateToAgent_JobTargetSendsTheNextTurn(t *testing.T) {
	jobs := newFakeJobs()
	jobs.jobs["job-1"] = openJob("job-1")
	// An earlier turn already ended. The wait must not read it as this one.
	jobs.events["job-1"] = []*job.Event{{Seq: 1, Kind: job.EventState, State: job.StateWaiting}}
	jobs.answerTurns = true
	s, az := delegateService(t, jobs, true)

	resp, err := s.DelegateToAgent(callerCtx(t, "agent_principal:zerocool", "acme"), jobTarget("now add a test", "job-1"))
	if err != nil {
		t.Fatalf("DelegateToAgent: %v", err)
	}
	if resp.GetJobId() != "job-1" || len(jobs.sent) != 1 || jobs.sent[0].Message != "now add a test" || jobs.sent[0].Kind != job.InputTurn {
		t.Fatalf("resp = %+v, sent = %+v", resp, jobs.sent)
	}
	if az.gotObject != "job:job-1" {
		t.Errorf("asked FGA on %s", az.gotObject)
	}
}

// TestDelegateToAgent_TargetsAreRefusedByName covers every refusal: no
// tenant, no can_send (not found, so the target's existence is not learned),
// no authorizer, an empty id, an empty goal, and an unknown job.
func TestDelegateToAgent_TargetsAreRefusedByName(t *testing.T) {
	jobs := newFakeJobs()
	jobs.jobs["job-1"] = openJob("job-1")
	ok := callerCtx(t, "agent_principal:zerocool", "acme")

	s, _ := delegateService(t, jobs, false)
	if _, err := s.DelegateToAgent(ok, bankTarget("fix", "bank-1")); status.Code(err) != codes.NotFound {
		t.Errorf("without can_send: %v", err)
	}
	if _, err := s.DelegateToAgent(ok, jobTarget("fix", "job-1")); status.Code(err) != codes.NotFound {
		t.Errorf("without can_send on the job: %v", err)
	}

	s, _ = delegateService(t, jobs, true)
	if _, err := s.DelegateToAgent(context.Background(), bankTarget("fix", "bank-1")); status.Code(err) != codes.PermissionDenied {
		t.Errorf("no tenant: %v", err)
	}
	if _, err := s.DelegateToAgent(ok, bankTarget("fix", "")); status.Code(err) != codes.InvalidArgument {
		t.Errorf("empty bank: %v", err)
	}
	if _, err := s.DelegateToAgent(ok, jobTarget("fix", "")); status.Code(err) != codes.InvalidArgument {
		t.Errorf("empty job: %v", err)
	}
	if _, err := s.DelegateToAgent(ok, bankTarget("", "bank-1")); status.Code(err) != codes.InvalidArgument {
		t.Errorf("no goal: %v", err)
	}
	if _, err := s.DelegateToAgent(ok, jobTarget("", "job-1")); status.Code(err) != codes.InvalidArgument {
		t.Errorf("no message: %v", err)
	}
	if _, err := s.DelegateToAgent(ok, jobTarget("fix", "job-9")); status.Code(err) != codes.NotFound {
		t.Errorf("unknown job: %v", err)
	}

	noAuthz := NewHarnessCallbackService(nil, WithJobSurface(jobs))
	if _, err := noAuthz.DelegateToAgent(ok, bankTarget("fix", "bank-1")); status.Code(err) != codes.PermissionDenied {
		t.Errorf("no authorizer: %v", err)
	}

	// The ephemeral target is not this path's to answer.
	if resp, err := s.delegateToTarget(ok, &harnesspb.DelegateToAgentRequest{Target: &harnesspb.DelegateToAgentRequest_Ephemeral{}}); resp != nil || err != nil {
		t.Errorf("ephemeral must fall through, got %v %v", resp, err)
	}
}

// TestDelegateToAgent_ABoundThatEndsIsDeadlineExceeded asserts a turn that
// does not end within the task's timeout answers DeadlineExceeded.
func TestDelegateToAgent_ABoundThatEndsIsDeadlineExceeded(t *testing.T) {
	jobs := newFakeJobs()
	jobs.jobs["job-1"] = openJob("job-1")
	s, _ := delegateService(t, jobs, true)
	ctx, cancel := context.WithTimeout(callerCtx(t, "agent_principal:zerocool", "acme"), 20*time.Millisecond)
	defer cancel()
	_, err := s.DelegateToAgent(ctx, jobTarget("fix", "job-1"))
	if status.Code(err) != codes.DeadlineExceeded {
		t.Fatalf("err = %v, want DeadlineExceeded", err)
	}
}

// TestDelegateToAgent_StoreFailuresAreReported: an open, a send, an events
// read and a job read that fail each reach the caller with a code.
func TestDelegateToAgent_StoreFailuresAreReported(t *testing.T) {
	boom := errors.New("postgres is down")
	ok := callerCtx(t, "agent_principal:zerocool", "acme")

	jobs := newFakeJobs()
	jobs.openErr = boom
	s, _ := delegateService(t, jobs, true)
	if _, err := s.DelegateToAgent(ok, bankTarget("fix", "bank-1")); status.Code(err) != codes.Internal {
		t.Errorf("open: %v", err)
	}

	jobs = newFakeJobs()
	jobs.jobs["job-1"] = openJob("job-1")
	jobs.sendErr = boom
	s, _ = delegateService(t, jobs, true)
	if _, err := s.DelegateToAgent(ok, jobTarget("fix", "job-1")); status.Code(err) != codes.Internal {
		t.Errorf("send: %v", err)
	}

	jobs = newFakeJobs()
	jobs.jobs["job-1"] = openJob("job-1")
	jobs.events["job-1"] = []*job.Event{{Seq: 1, Kind: job.EventState, State: job.StateWaiting}}
	jobs.answerTurns = true
	jobs.getErr = boom
	s, _ = delegateService(t, jobs, true)
	if _, err := s.DelegateToAgent(ok, jobTarget("fix", "job-1")); status.Code(err) != codes.Internal {
		t.Errorf("get after the turn: %v", err)
	}

	az := &recordingAuthorizer{allow: true, err: boom}
	s = NewHarnessCallbackService(nil, WithJobSurface(newFakeJobs()))
	s.componentAuthorizer = az
	if _, err := s.DelegateToAgent(ok, bankTarget("fix", "bank-1")); status.Code(err) != codes.Unavailable {
		t.Errorf("an authorization outage: %v", err)
	}
}
