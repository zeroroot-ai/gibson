// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	sdkcg "github.com/zeroroot-ai/sdk/capabilitygrant"

	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	jobpb "github.com/zeroroot-ai/sdk/api/gen/gibson/job/v1"
)

// fakeJobDriver records the JobService calls that the driver callbacks hand
// over, and answers with a canned error when one is set.
type fakeJobDriver struct {
	opened []*jobpb.OpenJobRequest
	sent   []*jobpb.SendInputRequest
	closed []*jobpb.CloseJobRequest
	err    error
}

func (f *fakeJobDriver) OpenJob(_ context.Context, req *jobpb.OpenJobRequest) (*jobpb.OpenJobResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.opened = append(f.opened, req)
	return &jobpb.OpenJobResponse{Job: &jobpb.Job{Id: "job-new", BankId: req.GetBankId()}}, nil
}

func (f *fakeJobDriver) SendInput(_ context.Context, req *jobpb.SendInputRequest) (*jobpb.SendInputResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.sent = append(f.sent, req)
	return &jobpb.SendInputResponse{Input: &jobpb.Input{Id: "in-new", JobId: req.GetJobId()}}, nil
}

func (f *fakeJobDriver) CloseJob(_ context.Context, req *jobpb.CloseJobRequest) (*jobpb.CloseJobResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.closed = append(f.closed, req)
	return &jobpb.CloseJobResponse{Job: &jobpb.Job{Id: req.GetJobId()}}, nil
}

func driverService(t *testing.T, driver JobDriver, jobs JobSurface, members MemberLookup) *HarnessCallbackService {
	t.Helper()
	return NewHarnessCallbackService(nil,
		WithJobDriver(driver), WithJobSurface(jobs), WithMemberLookup(members))
}

// notAMember is the lookup answer for a dispatched agent: its run backs no
// bank member.
func notAMember() *fakeMembers { return &fakeMembers{err: ErrNotAMember} }

func scorerInfo() *harnesspb.ContextInfo {
	return &harnesspb.ContextInfo{MissionRunId: "run-scorer", MissionId: "mission-1", AgentName: "scorer"}
}

func TestOpenJob_HandsTheCallToJobService(t *testing.T) {
	driver := &fakeJobDriver{}
	s := driverService(t, driver, newFakeJobs(), notAMember())

	resp, err := s.OpenJob(memberCtx("acme"), &harnesspb.OpenJobRequest{
		Context: scorerInfo(), BankId: "bank-1", MemberId: "m-2", Spec: &jobpb.JobSpec{Goal: "fix it"},
	})
	if err != nil {
		t.Fatalf("OpenJob: %v", err)
	}
	if resp.GetJob().GetId() != "job-new" {
		t.Fatalf("job = %+v", resp.GetJob())
	}
	if len(driver.opened) != 1 {
		t.Fatalf("JobService.OpenJob calls = %d; want 1", len(driver.opened))
	}
	got := driver.opened[0]
	if got.GetBankId() != "bank-1" || got.GetMemberId() != "m-2" || got.GetSpec().GetGoal() != "fix it" {
		t.Errorf("handed over %+v; want the bank, the member and the spec of the request", got)
	}
}

func TestSendInput_HandsTheCallToJobService(t *testing.T) {
	driver := &fakeJobDriver{}
	s := driverService(t, driver, newFakeJobs(), notAMember())

	resp, err := s.SendInput(memberCtx("acme"), &harnesspb.SendInputRequest{
		Context: scorerInfo(), JobId: "job-1", Message: "try again", Kind: jobpb.InputKind_INPUT_KIND_TURN,
	})
	if err != nil {
		t.Fatalf("SendInput: %v", err)
	}
	if resp.GetInput().GetJobId() != "job-1" {
		t.Fatalf("input = %+v", resp.GetInput())
	}
	if len(driver.sent) != 1 || driver.sent[0].GetMessage() != "try again" ||
		driver.sent[0].GetKind() != jobpb.InputKind_INPUT_KIND_TURN {
		t.Errorf("handed over %+v; want the message and the kind of the request", driver.sent)
	}
}

func TestCloseJob_AScorerClosesAJob(t *testing.T) {
	driver := &fakeJobDriver{}
	jobs := newFakeJobs()
	jobs.jobs["job-1"] = openJob("job-1")
	s := driverService(t, driver, jobs, notAMember())

	resp, err := s.CloseJob(memberCtx("acme"), &harnesspb.CloseJobRequest{
		Context: scorerInfo(), JobId: "job-1",
		Verdict: jobpb.JobVerdict_JOB_VERDICT_ACCOMPLISHED, Score: 0.9,
	})
	if err != nil {
		t.Fatalf("CloseJob: %v", err)
	}
	if resp.GetJob().GetId() != "job-1" {
		t.Fatalf("job = %+v", resp.GetJob())
	}
	if len(driver.closed) != 1 || driver.closed[0].GetVerdict() != jobpb.JobVerdict_JOB_VERDICT_ACCOMPLISHED ||
		driver.closed[0].GetScore() != 0.9 {
		t.Errorf("handed over %+v; want the verdict and the score of the request", driver.closed)
	}
}

// TestCloseJob_TheWorkerCannotCloseItsOwnJob is the rule of ADR-0119: the
// member that holds a job gets a refusal, and JobService is never called.
func TestCloseJob_TheWorkerCannotCloseItsOwnJob(t *testing.T) {
	driver := &fakeJobDriver{}
	jobs := newFakeJobs()
	jobs.jobs["job-1"] = openJob("job-1") // held by member m-1
	s := driverService(t, driver, jobs, liveMembers())

	_, err := s.CloseJob(memberCtx("acme"), &harnesspb.CloseJobRequest{
		Context: memberInfo("run-1"), JobId: "job-1",
		Verdict: jobpb.JobVerdict_JOB_VERDICT_ACCOMPLISHED, Score: 1,
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("err = %v; want PermissionDenied", err)
	}
	if len(driver.closed) != 0 {
		t.Fatal("the worker closed its own job")
	}
}

// TestCloseJob_ATurnOfTheJobCannotCloseIt covers the turn grant: a member
// runs a turn with the authority of the sender, who may close the job. The
// grant names the job of the turn, and a close of that job is refused.
func TestCloseJob_ATurnOfTheJobCannotCloseIt(t *testing.T) {
	driver := &fakeJobDriver{}
	jobs := newFakeJobs()
	jobs.jobs["job-1"] = openJob("job-1")
	s := driverService(t, driver, jobs, notAMember())

	ctx := withTaskGrantClaims(memberCtx("acme"), sdkcg.Claims{MissionID: "bank-1", TaskID: "job-1"})
	_, err := s.CloseJob(ctx, &harnesspb.CloseJobRequest{
		Context: scorerInfo(), JobId: "job-1",
		Verdict: jobpb.JobVerdict_JOB_VERDICT_ACCOMPLISHED, Score: 1,
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("err = %v; want PermissionDenied", err)
	}
	if len(driver.closed) != 0 {
		t.Fatal("a turn of the job closed the job")
	}
}

// A member that is a scorer can close a job that a different member holds.
func TestCloseJob_AMemberClosesTheJobOfADifferentMember(t *testing.T) {
	driver := &fakeJobDriver{}
	jobs := newFakeJobs()
	other := openJob("job-2")
	other.MemberID = "m-9"
	jobs.jobs["job-2"] = other
	s := driverService(t, driver, jobs, liveMembers())

	if _, err := s.CloseJob(memberCtx("acme"), &harnesspb.CloseJobRequest{
		Context: memberInfo("run-1"), JobId: "job-2",
		Verdict: jobpb.JobVerdict_JOB_VERDICT_FAILED,
	}); err != nil {
		t.Fatalf("CloseJob: %v", err)
	}
	if len(driver.closed) != 1 {
		t.Fatalf("JobService.CloseJob calls = %d; want 1", len(driver.closed))
	}
}

// A member lookup that cannot answer refuses the close.
func TestCloseJob_AnOutageOfTheMemberLookupRefuses(t *testing.T) {
	driver := &fakeJobDriver{}
	s := driverService(t, driver, newFakeJobs(), &fakeMembers{err: errors.New("bank store down")})

	_, err := s.CloseJob(memberCtx("acme"), &harnesspb.CloseJobRequest{Context: scorerInfo(), JobId: "job-1"})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("err = %v; want Unavailable", err)
	}
	if len(driver.closed) != 0 {
		t.Fatal("a close passed while the member lookup was down")
	}
}

// The refusals of JobService reach the caller unchanged.
func TestJobDriver_TheRefusalOfJobServicePassesThrough(t *testing.T) {
	driver := &fakeJobDriver{err: status.Error(codes.NotFound, "no such job")}
	jobs := newFakeJobs()
	jobs.jobs["job-1"] = openJob("job-1")
	s := driverService(t, driver, jobs, notAMember())

	if _, err := s.OpenJob(memberCtx("acme"), &harnesspb.OpenJobRequest{Context: scorerInfo(), BankId: "bank-1"}); status.Code(err) != codes.NotFound {
		t.Errorf("OpenJob err = %v; want NotFound", err)
	}
	if _, err := s.SendInput(memberCtx("acme"), &harnesspb.SendInputRequest{Context: scorerInfo(), JobId: "job-1"}); status.Code(err) != codes.NotFound {
		t.Errorf("SendInput err = %v; want NotFound", err)
	}
	if _, err := s.CloseJob(memberCtx("acme"), &harnesspb.CloseJobRequest{Context: scorerInfo(), JobId: "job-1"}); status.Code(err) != codes.NotFound {
		t.Errorf("CloseJob err = %v; want NotFound", err)
	}
}

// A daemon with no job service wired fails closed on each of the three.
func TestJobDriver_NoJobServiceFailsClosed(t *testing.T) {
	s := NewHarnessCallbackService(nil, WithMemberLookup(notAMember()))

	if _, err := s.OpenJob(memberCtx("acme"), &harnesspb.OpenJobRequest{Context: scorerInfo(), BankId: "bank-1"}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("OpenJob err = %v; want FailedPrecondition", err)
	}
	if _, err := s.SendInput(memberCtx("acme"), &harnesspb.SendInputRequest{Context: scorerInfo(), JobId: "job-1"}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("SendInput err = %v; want FailedPrecondition", err)
	}
	if _, err := s.CloseJob(memberCtx("acme"), &harnesspb.CloseJobRequest{Context: scorerInfo(), JobId: "job-1"}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("CloseJob err = %v; want FailedPrecondition", err)
	}
}
