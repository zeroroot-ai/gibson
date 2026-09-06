// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/internal/platform/bank"
	"github.com/zeroroot-ai/gibson/internal/platform/job"
	commonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/common/v1"
	jobpb "github.com/zeroroot-ai/sdk/api/gen/gibson/job/v1"
)

// fakeJobStore is an in-memory job.Store that keeps the real validation by
// calling through to the input validators, so a test cannot pass something the
// production store would refuse.
type fakeJobStore struct {
	jobs    map[string]*job.Job
	inputs  map[string][]*job.Input
	events  map[string][]*job.Event
	openErr error
	seq     int
	// onOpen and onSend are what the member does with a job: a job node test
	// scripts the member's answer here.
	onOpen func(*job.Job)
	onSend func(id string)
}

func newFakeJobStore() *fakeJobStore {
	return &fakeJobStore{
		jobs: map[string]*job.Job{}, inputs: map[string][]*job.Input{}, events: map[string][]*job.Event{},
	}
}

func (f *fakeJobStore) Open(_ context.Context, _ string, in job.OpenInput) (*job.Job, error) {
	if err := in.Validate(); err != nil {
		return nil, fmt.Errorf("fake job store: %w", err)
	}
	if f.openErr != nil {
		return nil, f.openErr
	}
	f.seq++
	id := "job-" + string(rune('a'+f.seq-1))
	now := time.Now().UTC()
	j := &job.Job{
		ID: id, BankID: in.BankID, MemberID: in.MemberID, State: job.StateOpen,
		Spec: in.Spec, OpenedBy: in.OpenedBy, OpenedAt: now, LastInputAt: now,
	}
	f.jobs[id] = j
	f.appendEvent(id, job.EventOpened, job.StateOpen, "", 0)
	if f.onOpen != nil {
		f.onOpen(j)
	}
	return j, nil
}

func (f *fakeJobStore) appendEvent(id string, kind job.EventKind, state job.State, verdict job.Verdict, score float64) {
	f.events[id] = append(f.events[id], &job.Event{
		JobID: id, Seq: int64(len(f.events[id]) + 1), Kind: kind,
		OccurredAt: time.Now().UTC(), State: state, Verdict: verdict, Score: score,
	})
}

func (f *fakeJobStore) Get(_ context.Context, _, id string) (*job.Job, error) {
	j, ok := f.jobs[id]
	if !ok {
		return nil, job.ErrNotFound
	}
	return j, nil
}

func (f *fakeJobStore) List(_ context.Context, _ string, filter job.ListFilter, _ job.Page) ([]*job.Job, string, error) {
	out := []*job.Job{}
	for _, j := range f.jobs {
		if filter.BankID != "" && j.BankID != filter.BankID {
			continue
		}
		if filter.MemberID != "" && j.MemberID != filter.MemberID {
			continue
		}
		if filter.State != "" && j.State != filter.State {
			continue
		}
		out = append(out, j)
	}
	return out, "", nil
}

func (f *fakeJobStore) Send(_ context.Context, _ string, in job.SendInput) (*job.Input, error) {
	if err := in.Validate(); err != nil {
		return nil, fmt.Errorf("fake job store: %w", err)
	}
	j, ok := f.jobs[in.JobID]
	if !ok {
		return nil, job.ErrNotFound
	}
	if j.State == job.StateClosed && in.Kind != job.InputWrapUp {
		return nil, job.ErrClosed
	}
	input := &job.Input{
		ID: "in-1", JobID: in.JobID, Seq: int64(len(f.inputs[in.JobID]) + 1),
		Kind: in.Kind, Message: in.Message, Sender: in.Sender, SentAt: time.Now().UTC(),
	}
	f.inputs[in.JobID] = append(f.inputs[in.JobID], input)
	if j.State != job.StateClosed {
		j.State = job.StateWorking
	}
	if f.onSend != nil {
		f.onSend(in.JobID)
	}
	return input, nil
}

func (f *fakeJobStore) Close(_ context.Context, _ string, in job.CloseInput) (*job.Job, error) {
	if err := in.Validate(); err != nil {
		return nil, fmt.Errorf("fake job store: %w", err)
	}
	j, ok := f.jobs[in.JobID]
	if !ok {
		return nil, job.ErrNotFound
	}
	if j.State == job.StateClosed {
		return nil, job.ErrClosed
	}
	j.State = job.StateClosed
	j.Verdict = in.Verdict
	j.Score = in.Score
	j.ClosedAt = time.Now().UTC()
	f.inputs[in.JobID] = append(f.inputs[in.JobID], &job.Input{
		ID: "wrap", JobID: in.JobID, Kind: job.InputWrapUp, Sender: in.Closer,
	})
	f.appendEvent(in.JobID, job.EventClosed, job.StateClosed, in.Verdict, in.Score)
	return j, nil
}

func (f *fakeJobStore) Claim(context.Context, string, string, string) (*job.Job, error) {
	return nil, nil
}
func (f *fakeJobStore) PendingInputs(context.Context, string, string, int32) ([]*job.Input, error) {
	return nil, nil
}
func (f *fakeJobStore) Acknowledge(context.Context, string, string) error { return nil }
func (f *fakeJobStore) SetState(context.Context, string, string, job.State, string) (*job.Job, error) {
	return nil, nil
}
func (f *fakeJobStore) ReleaseMember(_ context.Context, _, memberID string) (int64, error) {
	var n int64
	for _, j := range f.jobs {
		if j.MemberID == memberID && j.State != job.StateClosed {
			j.MemberID = ""
			n++
		}
	}
	return n, nil
}

func (f *fakeJobStore) AddDeliverable(context.Context, string, string, *jobpb.Deliverable) (*job.Job, error) {
	return nil, nil
}
func (f *fakeJobStore) Events(_ context.Context, _, jobID string, since int64, _ int32) ([]*job.Event, error) {
	out := []*job.Event{}
	for _, e := range f.events[jobID] {
		if e.Seq > since {
			out = append(out, e)
		}
	}
	return out, nil
}
func (f *fakeJobStore) Stale(context.Context, string, string, int64, int32) ([]*job.Job, error) {
	return nil, nil
}

// jobTestServer wires a JobService over fakes, with one bank already stored.
func jobTestServer(t *testing.T) (jobpb.JobServiceServer, *fakeJobStore, *fakeBankStore, *fakeAuthorizer) {
	t.Helper()
	jobs := newFakeJobStore()
	banks := newFakeBankStore()
	if _, err := banks.Create(context.Background(), "acme", bank.CreateInput{
		Name: "nightly", OwnerKind: bank.OwnerUser, OwnerID: "alice",
		LoginShape: bank.LoginShapeAPIKey, ProviderConfigName: "p",
	}); err != nil {
		t.Fatalf("seed bank: %v", err)
	}
	az := &fakeAuthorizer{}
	srv, err := NewJobServer(JobServerConfig{Jobs: jobs, Banks: banks, Authorizer: az, MemberEvents: &recordingMemberEvents{}, Sessions: &recordingSessions{}})
	if err != nil {
		t.Fatalf("NewJobServer: %v", err)
	}
	return srv, jobs, banks, az
}

func seededBankID(t *testing.T, banks *fakeBankStore) string {
	t.Helper()
	for id := range banks.banks {
		return id
	}
	t.Fatal("no seeded bank")
	return ""
}

func goodSpec() *jobpb.JobSpec {
	return &jobpb.JobSpec{
		Goal: "fix the CVE",
		Repositories: []*jobpb.RepositorySpec{{
			Name: "app", ConnectorRef: "connector/gitlab", Project: "group/app",
			Deliverable: jobpb.DeliverableKind_DELIVERABLE_KIND_MERGE_REQUEST,
		}},
		CredentialNames: []string{"gitlab-token"},
	}
}

func TestNewJobServer_RequiresItsSources(t *testing.T) {
	for name, cfg := range map[string]JobServerConfig{
		"no jobs store":  {Banks: newFakeBankStore(), Authorizer: &fakeAuthorizer{}},
		"no banks store": {Jobs: newFakeJobStore(), Authorizer: &fakeAuthorizer{}},
		"no authorizer":  {Jobs: newFakeJobStore(), Banks: newFakeBankStore()},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewJobServer(cfg); err == nil {
				t.Fatal("must not be constructible")
			}
		})
	}
}

func TestOpenJob_OpensAndWritesItsTuples(t *testing.T) {
	srv, _, banks, az := jobTestServer(t)
	ctx := bankCtx(t, "acme", "alice")
	bankID := seededBankID(t, banks)

	resp, err := srv.OpenJob(ctx, &jobpb.OpenJobRequest{BankId: bankID, Spec: goodSpec()})
	if err != nil {
		t.Fatalf("OpenJob: %v", err)
	}
	got := resp.GetJob()
	if got.GetState() != jobpb.JobState_JOB_STATE_OPEN {
		t.Errorf("state = %v, want open", got.GetState())
	}
	if got.GetSpec().GetGoal() != "fix the CVE" {
		t.Errorf("the spec must reach the member unchanged, got %+v", got.GetSpec())
	}
	var parent, opener bool
	for _, tp := range az.written {
		if tp.Relation == "parent" && tp.User == "bank:"+bankID {
			parent = true
		}
		if tp.Relation == "opened_by" && tp.User == "user:alice" {
			opener = true
		}
	}
	if !parent || !opener {
		t.Fatalf("tuples = %+v, want a bank parent and the opener", az.written)
	}
}

func TestOpenJob_UnknownBankIsNotFound(t *testing.T) {
	srv, _, _, _ := jobTestServer(t)
	_, err := srv.OpenJob(bankCtx(t, "acme", "alice"),
		&jobpb.OpenJobRequest{BankId: "nope", Spec: goodSpec()})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("err = %v, want NotFound", err)
	}
}

func TestOpenJob_WithoutCanSendIsNotFound(t *testing.T) {
	srv, _, banks, az := jobTestServer(t)
	az.deny = true
	_, err := srv.OpenJob(bankCtx(t, "acme", "alice"),
		&jobpb.OpenJobRequest{BankId: seededBankID(t, banks), Spec: goodSpec()})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("err = %v, want NotFound: a caller with no right must not learn the bank exists", err)
	}
}

func TestOpenJob_RefusesASpecThatCannotRun(t *testing.T) {
	srv, _, banks, _ := jobTestServer(t)
	ctx := bankCtx(t, "acme", "alice")
	bankID := seededBankID(t, banks)

	for name, spec := range map[string]*jobpb.JobSpec{
		"no goal and no repository": {},
		"repository with no connector": {Goal: "x", Repositories: []*jobpb.RepositorySpec{{
			Name: "app", Project: "g/a", Deliverable: jobpb.DeliverableKind_DELIVERABLE_KIND_NONE,
		}}},
		"repository with no deliverable": {Goal: "x", Repositories: []*jobpb.RepositorySpec{{
			Name: "app", ConnectorRef: "connector/gitlab", Project: "g/a",
		}}},
		"acceptance score out of range": {Goal: "x", Acceptance: &jobpb.Acceptance{PassingScore: 1.5}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := srv.OpenJob(ctx, &jobpb.OpenJobRequest{BankId: bankID, Spec: spec})
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("err = %v, want InvalidArgument", err)
			}
		})
	}
}

func TestOpenJob_ClosesTheJobWhenItsTuplesCannotBeWritten(t *testing.T) {
	srv, jobs, banks, az := jobTestServer(t)
	az.writeErr = errors.New("fga down")

	_, err := srv.OpenJob(bankCtx(t, "acme", "alice"),
		&jobpb.OpenJobRequest{BankId: seededBankID(t, banks), Spec: goodSpec()})
	if status.Code(err) != codes.Internal {
		t.Fatalf("err = %v, want Internal", err)
	}
	for _, j := range jobs.jobs {
		if j.State != job.StateClosed || j.Verdict != job.VerdictAbandoned {
			t.Fatalf("a job nobody can send to or close must not stay open, got %+v", j)
		}
	}
}

func TestSendInput_AppendsATurn(t *testing.T) {
	srv, jobs, banks, _ := jobTestServer(t)
	ctx := bankCtx(t, "acme", "alice")
	opened, err := srv.OpenJob(ctx, &jobpb.OpenJobRequest{BankId: seededBankID(t, banks), Spec: goodSpec()})
	if err != nil {
		t.Fatal(err)
	}
	id := opened.GetJob().GetId()

	resp, err := srv.SendInput(ctx, &jobpb.SendInputRequest{JobId: id, Message: "try again"})
	if err != nil {
		t.Fatalf("SendInput: %v", err)
	}
	if resp.GetInput().GetKind() != jobpb.InputKind_INPUT_KIND_TURN {
		t.Errorf("kind = %v, want turn by default", resp.GetInput().GetKind())
	}
	if resp.GetInput().GetGrant() != "" {
		t.Error("the per-turn grant is minted at delivery and must never be returned to a sender")
	}
	if jobs.jobs[id].State != job.StateWorking {
		t.Errorf("an input puts the job back to work, got %q", jobs.jobs[id].State)
	}
}

func TestSendInput_RefusesAClientWrapUp(t *testing.T) {
	srv, _, banks, _ := jobTestServer(t)
	ctx := bankCtx(t, "acme", "alice")
	opened, err := srv.OpenJob(ctx, &jobpb.OpenJobRequest{BankId: seededBankID(t, banks), Spec: goodSpec()})
	if err != nil {
		t.Fatal(err)
	}
	_, err = srv.SendInput(ctx, &jobpb.SendInputRequest{
		JobId: opened.GetJob().GetId(), Message: "wrap it", Kind: jobpb.InputKind_INPUT_KIND_WRAP_UP,
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("err = %v, want InvalidArgument: a wrap-up is the daemon's, sent after a close", err)
	}
}

func TestSendInput_ToAClosedJobIsFailedPrecondition(t *testing.T) {
	srv, _, banks, _ := jobTestServer(t)
	ctx := bankCtx(t, "acme", "alice")
	opened, err := srv.OpenJob(ctx, &jobpb.OpenJobRequest{BankId: seededBankID(t, banks), Spec: goodSpec()})
	if err != nil {
		t.Fatal(err)
	}
	id := opened.GetJob().GetId()
	if _, err := srv.CloseJob(ctx, &jobpb.CloseJobRequest{
		JobId: id, Verdict: jobpb.JobVerdict_JOB_VERDICT_ACCOMPLISHED, Score: 1,
	}); err != nil {
		t.Fatal(err)
	}
	_, err = srv.SendInput(ctx, &jobpb.SendInputRequest{JobId: id, Message: "one more"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("err = %v, want FailedPrecondition", err)
	}
}

func TestCloseJob_RecordsTheVerdictAndTheWrapUp(t *testing.T) {
	srv, jobs, banks, _ := jobTestServer(t)
	ctx := bankCtx(t, "acme", "alice")
	opened, err := srv.OpenJob(ctx, &jobpb.OpenJobRequest{BankId: seededBankID(t, banks), Spec: goodSpec()})
	if err != nil {
		t.Fatal(err)
	}
	id := opened.GetJob().GetId()

	resp, err := srv.CloseJob(ctx, &jobpb.CloseJobRequest{
		JobId: id, Verdict: jobpb.JobVerdict_JOB_VERDICT_ACCOMPLISHED, Score: 0.9,
	})
	if err != nil {
		t.Fatalf("CloseJob: %v", err)
	}
	if resp.GetJob().GetVerdict() != jobpb.JobVerdict_JOB_VERDICT_ACCOMPLISHED || resp.GetJob().GetScore() != 0.9 {
		t.Fatalf("job = %+v", resp.GetJob())
	}
	last := jobs.inputs[id][len(jobs.inputs[id])-1]
	if last.Kind != job.InputWrapUp {
		t.Errorf("a close appends the wrap-up turn, got %q", last.Kind)
	}
}

// TestCloseJob_WithoutCanCloseIsNotFound is the rule the whole scorer design
// rests on: a member with can_send cannot close the job it is working on.
func TestCloseJob_WithoutCanCloseIsNotFound(t *testing.T) {
	srv, _, banks, az := jobTestServer(t)
	ctx := bankCtx(t, "acme", "alice")
	opened, err := srv.OpenJob(ctx, &jobpb.OpenJobRequest{BankId: seededBankID(t, banks), Spec: goodSpec()})
	if err != nil {
		t.Fatal(err)
	}
	az.deny = true

	_, err = srv.CloseJob(ctx, &jobpb.CloseJobRequest{
		JobId: opened.GetJob().GetId(), Verdict: jobpb.JobVerdict_JOB_VERDICT_ACCOMPLISHED,
	})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("err = %v, want NotFound", err)
	}
	var sawCanClose bool
	for _, c := range az.checks {
		if c != "" && contains(c, "|can_close|job:") {
			sawCanClose = true
		}
	}
	if !sawCanClose {
		t.Fatalf("checks = %v, want a can_close question", az.checks)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestCloseJob_TwiceIsFailedPrecondition(t *testing.T) {
	srv, _, banks, _ := jobTestServer(t)
	ctx := bankCtx(t, "acme", "alice")
	opened, err := srv.OpenJob(ctx, &jobpb.OpenJobRequest{BankId: seededBankID(t, banks), Spec: goodSpec()})
	if err != nil {
		t.Fatal(err)
	}
	id := opened.GetJob().GetId()
	req := &jobpb.CloseJobRequest{JobId: id, Verdict: jobpb.JobVerdict_JOB_VERDICT_FAILED}
	if _, err := srv.CloseJob(ctx, req); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.CloseJob(ctx, req); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("err = %v, want FailedPrecondition: one job, one verdict", err)
	}
}

func TestCloseJob_UnspecifiedVerdictIsInvalid(t *testing.T) {
	srv, _, banks, _ := jobTestServer(t)
	ctx := bankCtx(t, "acme", "alice")
	opened, err := srv.OpenJob(ctx, &jobpb.OpenJobRequest{BankId: seededBankID(t, banks), Spec: goodSpec()})
	if err != nil {
		t.Fatal(err)
	}
	_, err = srv.CloseJob(ctx, &jobpb.CloseJobRequest{JobId: opened.GetJob().GetId()})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("err = %v, want InvalidArgument", err)
	}
}

func TestGetJob_ReturnsTheJob(t *testing.T) {
	srv, _, banks, _ := jobTestServer(t)
	ctx := bankCtx(t, "acme", "alice")
	opened, err := srv.OpenJob(ctx, &jobpb.OpenJobRequest{BankId: seededBankID(t, banks), Spec: goodSpec()})
	if err != nil {
		t.Fatal(err)
	}
	got, err := srv.GetJob(ctx, &jobpb.GetJobRequest{JobId: opened.GetJob().GetId()})
	if err != nil {
		t.Fatalf("GetJob: %v", err)
	}
	if got.GetJob().GetId() != opened.GetJob().GetId() {
		t.Fatalf("job = %+v", got.GetJob())
	}
}

func TestGetJob_UnknownIsNotFound(t *testing.T) {
	srv, _, _, _ := jobTestServer(t)
	_, err := srv.GetJob(bankCtx(t, "acme", "alice"), &jobpb.GetJobRequest{JobId: "nope"})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("err = %v, want NotFound", err)
	}
}

func TestListJobs_FiltersByBankAndState(t *testing.T) {
	srv, _, banks, _ := jobTestServer(t)
	ctx := bankCtx(t, "acme", "alice")
	bankID := seededBankID(t, banks)
	for range 2 {
		if _, err := srv.OpenJob(ctx, &jobpb.OpenJobRequest{BankId: bankID, Spec: goodSpec()}); err != nil {
			t.Fatal(err)
		}
	}
	resp, err := srv.ListJobs(ctx, &jobpb.ListJobsRequest{BankId: bankID, State: jobpb.JobState_JOB_STATE_OPEN})
	if err != nil {
		t.Fatalf("ListJobs: %v", err)
	}
	if len(resp.GetJobs()) != 2 {
		t.Fatalf("jobs = %d, want 2", len(resp.GetJobs()))
	}
	empty, err := srv.ListJobs(ctx, &jobpb.ListJobsRequest{BankId: "other-bank"})
	if err != nil || len(empty.GetJobs()) != 0 {
		t.Fatalf("a filter on another bank returns nothing: %d %v", len(empty.GetJobs()), err)
	}
}

// recordingEventStream captures what StreamJobEvents sends.
type recordingEventStream struct {
	grpc.ServerStream
	ctx  context.Context
	sent []*jobpb.JobEvent
}

func (s *recordingEventStream) Context() context.Context { return s.ctx }
func (s *recordingEventStream) Send(m *jobpb.StreamJobEventsResponse) error {
	s.sent = append(s.sent, m.GetEvent())
	return nil
}

func TestStreamJobEvents_ReplaysTheBacklogAndEndsAtTheClose(t *testing.T) {
	srv, _, banks, _ := jobTestServer(t)
	ctx := bankCtx(t, "acme", "alice")
	opened, err := srv.OpenJob(ctx, &jobpb.OpenJobRequest{BankId: seededBankID(t, banks), Spec: goodSpec()})
	if err != nil {
		t.Fatal(err)
	}
	id := opened.GetJob().GetId()
	if _, err := srv.CloseJob(ctx, &jobpb.CloseJobRequest{
		JobId: id, Verdict: jobpb.JobVerdict_JOB_VERDICT_ACCOMPLISHED, Score: 1,
	}); err != nil {
		t.Fatal(err)
	}

	stream := &recordingEventStream{ctx: ctx}
	if err := srv.StreamJobEvents(&jobpb.StreamJobEventsRequest{JobId: id}, stream); err != nil {
		t.Fatalf("StreamJobEvents: %v", err)
	}
	if len(stream.sent) != 2 {
		t.Fatalf("sent %d events, want the opening and the close", len(stream.sent))
	}
	if stream.sent[0].GetKind() != jobpb.JobEventKind_JOB_EVENT_KIND_OPENED {
		t.Errorf("first event = %v, want opened", stream.sent[0].GetKind())
	}
	last := stream.sent[len(stream.sent)-1]
	if last.GetKind() != jobpb.JobEventKind_JOB_EVENT_KIND_CLOSED || last.GetVerdict() != jobpb.JobVerdict_JOB_VERDICT_ACCOMPLISHED {
		t.Errorf("last event = %+v, want the close with its verdict", last)
	}
}

func TestStreamJobEvents_ResumesAfterSinceSeq(t *testing.T) {
	srv, _, banks, _ := jobTestServer(t)
	ctx := bankCtx(t, "acme", "alice")
	opened, err := srv.OpenJob(ctx, &jobpb.OpenJobRequest{BankId: seededBankID(t, banks), Spec: goodSpec()})
	if err != nil {
		t.Fatal(err)
	}
	id := opened.GetJob().GetId()
	if _, err := srv.CloseJob(ctx, &jobpb.CloseJobRequest{
		JobId: id, Verdict: jobpb.JobVerdict_JOB_VERDICT_FAILED,
	}); err != nil {
		t.Fatal(err)
	}

	stream := &recordingEventStream{ctx: ctx}
	if err := srv.StreamJobEvents(&jobpb.StreamJobEventsRequest{JobId: id, SinceSeq: 1}, stream); err != nil {
		t.Fatalf("StreamJobEvents: %v", err)
	}
	if len(stream.sent) != 1 || stream.sent[0].GetSeq() != 2 {
		t.Fatalf("sent = %+v, want only the events after seq 1", stream.sent)
	}
}

func TestStreamJobEvents_WithoutCanReadIsNotFound(t *testing.T) {
	srv, _, banks, az := jobTestServer(t)
	ctx := bankCtx(t, "acme", "alice")
	opened, err := srv.OpenJob(ctx, &jobpb.OpenJobRequest{BankId: seededBankID(t, banks), Spec: goodSpec()})
	if err != nil {
		t.Fatal(err)
	}
	az.deny = true
	err = srv.StreamJobEvents(&jobpb.StreamJobEventsRequest{JobId: opened.GetJob().GetId()},
		&recordingEventStream{ctx: ctx})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("err = %v, want NotFound", err)
	}
}

func TestJobService_NeedsATenantAndACaller(t *testing.T) {
	srv, _, banks, _ := jobTestServer(t)
	bankID := seededBankID(t, banks)
	if _, err := srv.OpenJob(context.Background(), &jobpb.OpenJobRequest{BankId: bankID, Spec: goodSpec()}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("no tenant must be PermissionDenied, got %v", err)
	}
	if _, err := srv.ListJobs(context.Background(), &jobpb.ListJobsRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("no tenant must be PermissionDenied, got %v", err)
	}
}

func TestPrincipalKindOf(t *testing.T) {
	for subject, want := range map[string]job.PrincipalKind{
		"agent_principal:claude": job.PrincipalComponent,
		"tool_principal:nmap":    job.PrincipalComponent,
		"plugin_principal:gh":    job.PrincipalComponent,
		"alice":                  job.PrincipalUser,
	} {
		if got := principalKindOf(subject); got != want {
			t.Errorf("principalKindOf(%q) = %q, want %q", subject, got, want)
		}
	}
}

func TestFgaUserForPrincipal(t *testing.T) {
	if got := fgaUserForPrincipal(job.Principal{Kind: job.PrincipalComponent, ID: "agent_principal:x"}); got != "agent_principal:x" {
		t.Errorf("a component is already a typed principal, got %q", got)
	}
	if got := fgaUserForPrincipal(job.Principal{Kind: job.PrincipalUser, ID: "alice"}); got != "user:alice" {
		t.Errorf("got %q", got)
	}
}

func TestJobStoreError_Mapping(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want codes.Code
	}{
		{job.ErrNotFound, codes.NotFound},
		{job.ErrClosed, codes.FailedPrecondition},
		{job.ErrNoFreeSlot, codes.ResourceExhausted},
		{job.ErrInvalid, codes.InvalidArgument},
		{errors.New("boom"), codes.Internal},
	} {
		if got := status.Code(jobStoreError(tc.err)); got != tc.want {
			t.Errorf("jobStoreError(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
}

var _ authz.Authorizer = (*fakeAuthorizer)(nil)

// TestJobEnums_StatesRoundTrip asserts that every job state survives the wire
// mapping, and that an unspecified state is no filter.
func TestJobEnums_StatesRoundTrip(t *testing.T) {
	states := map[jobpb.JobState]job.State{
		jobpb.JobState_JOB_STATE_OPEN:    job.StateOpen,
		jobpb.JobState_JOB_STATE_WORKING: job.StateWorking,
		jobpb.JobState_JOB_STATE_WAITING: job.StateWaiting,
		jobpb.JobState_JOB_STATE_CLOSED:  job.StateClosed,
	}
	for wire, domain := range states {
		if got := stateFromProto(wire); got != domain {
			t.Errorf("stateFromProto(%v) = %q, want %q", wire, got, domain)
		}
		if got := stateToProto(domain); got != wire {
			t.Errorf("stateToProto(%q) = %v, want %v", domain, got, wire)
		}
	}
	if got := stateFromProto(jobpb.JobState_JOB_STATE_UNSPECIFIED); got != "" {
		t.Errorf("an unspecified state is no filter, got %q", got)
	}
	if got := stateFromProto(jobpb.JobState(99)); got != "" {
		t.Errorf("an unknown state is no filter, got %q", got)
	}
	if got := stateToProto(job.State("")); got != jobpb.JobState_JOB_STATE_UNSPECIFIED {
		t.Errorf("the empty state must map to unspecified, got %v", got)
	}
}

// TestJobEnums_VerdictsRoundTrip asserts that every verdict survives the wire
// mapping, and that an unspecified verdict is the empty one Validate refuses.
func TestJobEnums_VerdictsRoundTrip(t *testing.T) {
	verdicts := map[jobpb.JobVerdict]job.Verdict{
		jobpb.JobVerdict_JOB_VERDICT_ACCOMPLISHED: job.VerdictAccomplished,
		jobpb.JobVerdict_JOB_VERDICT_FAILED:       job.VerdictFailed,
		jobpb.JobVerdict_JOB_VERDICT_ABANDONED:    job.VerdictAbandoned,
	}
	for wire, domain := range verdicts {
		if got := verdictFromProto(wire); got != domain {
			t.Errorf("verdictFromProto(%v) = %q, want %q", wire, got, domain)
		}
		if got := verdictToProto(domain); got != wire {
			t.Errorf("verdictToProto(%q) = %v, want %v", domain, got, wire)
		}
	}
	if got := verdictFromProto(jobpb.JobVerdict_JOB_VERDICT_UNSPECIFIED); got != "" {
		t.Errorf("an unspecified verdict must map to the empty verdict, got %q", got)
	}
	if got := verdictFromProto(jobpb.JobVerdict(99)); got != "" {
		t.Errorf("an unknown verdict must map to the empty verdict, got %q", got)
	}
	if got := verdictToProto(job.Verdict("")); got != jobpb.JobVerdict_JOB_VERDICT_UNSPECIFIED {
		t.Errorf("the empty verdict must map to unspecified, got %v", got)
	}
}

// TestJobEnums_InputKindsRoundTrip asserts that every input kind survives the
// wire mapping, and that an unspecified kind is a turn.
func TestJobEnums_InputKindsRoundTrip(t *testing.T) {
	kinds := map[jobpb.InputKind]job.InputKind{
		jobpb.InputKind_INPUT_KIND_TURN:    job.InputTurn,
		jobpb.InputKind_INPUT_KIND_ANSWER:  job.InputAnswer,
		jobpb.InputKind_INPUT_KIND_WRAP_UP: job.InputWrapUp,
	}
	for wire, domain := range kinds {
		if got := inputKindFromProto(wire); got != domain {
			t.Errorf("inputKindFromProto(%v) = %q, want %q", wire, got, domain)
		}
		if got := inputKindToProto(domain); got != wire {
			t.Errorf("inputKindToProto(%q) = %v, want %v", domain, got, wire)
		}
	}
	if got := inputKindFromProto(jobpb.InputKind_INPUT_KIND_UNSPECIFIED); got != job.InputTurn {
		t.Errorf("an unspecified input kind is a turn, got %q", got)
	}
	if got := inputKindFromProto(jobpb.InputKind(99)); got != job.InputTurn {
		t.Errorf("an unknown input kind is a turn, got %q", got)
	}
	if got := inputKindToProto(job.InputKind("")); got != jobpb.InputKind_INPUT_KIND_TURN {
		t.Errorf("the empty input kind is a turn, got %v", got)
	}
}

// TestJobEnums_EventAndPrincipalKindsToProto asserts that every event kind and
// principal kind renders as its own wire value.
func TestJobEnums_EventAndPrincipalKindsToProto(t *testing.T) {
	events := map[job.EventKind]jobpb.JobEventKind{
		job.EventOpened:      jobpb.JobEventKind_JOB_EVENT_KIND_OPENED,
		job.EventInput:       jobpb.JobEventKind_JOB_EVENT_KIND_INPUT,
		job.EventState:       jobpb.JobEventKind_JOB_EVENT_KIND_STATE,
		job.EventDeliverable: jobpb.JobEventKind_JOB_EVENT_KIND_DELIVERABLE,
		job.EventClosed:      jobpb.JobEventKind_JOB_EVENT_KIND_CLOSED,
	}
	for domain, wire := range events {
		if got := eventKindToProto(domain); got != wire {
			t.Errorf("eventKindToProto(%q) = %v, want %v", domain, got, wire)
		}
	}
	if got := eventKindToProto(job.EventKind("")); got != jobpb.JobEventKind_JOB_EVENT_KIND_UNSPECIFIED {
		t.Errorf("an unknown event kind must map to unspecified, got %v", got)
	}

	principals := map[job.PrincipalKind]commonpb.Principal_Kind{
		job.PrincipalUser:      commonpb.Principal_KIND_USER,
		job.PrincipalTenant:    commonpb.Principal_KIND_TENANT,
		job.PrincipalComponent: commonpb.Principal_KIND_COMPONENT,
		job.PrincipalService:   commonpb.Principal_KIND_SERVICE,
	}
	for domain, wire := range principals {
		got := principalToProto(job.Principal{Kind: domain, ID: "p-1"})
		if got.GetKind() != wire || got.GetId() != "p-1" {
			t.Errorf("principalToProto(%q) = %v/%q, want %v/p-1", domain, got.GetKind(), got.GetId(), wire)
		}
	}
}

// recordingMemberEvents captures the console lines a service emitted.
type recordingMemberEvents struct {
	lines []string
}

func (r *recordingMemberEvents) PublishMemberEvent(_ context.Context, _, memberID string, line []byte) {
	r.lines = append(r.lines, memberID+" "+string(line))
}

// TestCloseJob_PutsTheCloseOnTheMembersStream asserts that closing a job a
// member holds emits job_closed with the verdict and the score, and that a
// job nobody holds emits nothing.
func TestCloseJob_PutsTheCloseOnTheMembersStream(t *testing.T) {
	jobs := newFakeJobStore()
	banks := newFakeBankStore()
	if _, err := banks.Create(context.Background(), "acme", bank.CreateInput{
		Name: "nightly", OwnerKind: bank.OwnerUser, OwnerID: "alice",
		LoginShape: bank.LoginShapeAPIKey, ProviderConfigName: "p",
	}); err != nil {
		t.Fatalf("seed bank: %v", err)
	}
	events := &recordingMemberEvents{}
	sessions := &recordingSessions{}
	srv, err := NewJobServer(JobServerConfig{Jobs: jobs, Banks: banks, Authorizer: &fakeAuthorizer{}, MemberEvents: events, Sessions: sessions})
	if err != nil {
		t.Fatal(err)
	}
	ctx := bankCtx(t, "acme", "alice")
	bankID := seededBankID(t, banks)
	opened, err := srv.OpenJob(ctx, &jobpb.OpenJobRequest{BankId: bankID, Spec: goodSpec()})
	if err != nil {
		t.Fatal(err)
	}
	jobs.jobs[opened.GetJob().GetId()].MemberID = "m-1"

	if _, err := srv.CloseJob(ctx, &jobpb.CloseJobRequest{JobId: opened.GetJob().GetId(), Verdict: jobpb.JobVerdict_JOB_VERDICT_ACCOMPLISHED, Score: 0.9}); err != nil {
		t.Fatalf("CloseJob: %v", err)
	}
	if len(events.lines) != 1 || !strings.HasPrefix(events.lines[0], "m-1 ") ||
		!strings.Contains(events.lines[0], `"type":"job_closed"`) || !strings.Contains(events.lines[0], `"verdict":"accomplished"`) {
		t.Fatalf("lines = %v", events.lines)
	}

	if _, err := NewJobServer(JobServerConfig{Jobs: jobs, Banks: banks, Authorizer: &fakeAuthorizer{}, Sessions: sessions}); err == nil {
		t.Error("a job service with no member event sink must be refused")
	}
	if _, err := NewJobServer(JobServerConfig{Jobs: jobs, Banks: banks, Authorizer: &fakeAuthorizer{}, MemberEvents: events}); err == nil {
		t.Error("a job service with no session store must be refused")
	}

	// The result record is under the job's own key, and it carries the close.
	key := job.ResultKey(opened.GetJob().GetId())
	data, ok := sessions.blobs[key]
	if !ok {
		t.Fatalf("no result under %q, have %v", key, sessions.keys())
	}
	var result job.Result
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if result.Verdict != job.VerdictAccomplished || result.Score != 0.9 || result.MemberID != "m-1" {
		t.Errorf("result = %+v", result)
	}
}

// recordingSessions is an in-memory session store.
type recordingSessions struct {
	blobs  map[string][]byte
	putErr error
}

func (r *recordingSessions) keys() []string {
	out := make([]string, 0, len(r.blobs))
	for k := range r.blobs {
		out = append(out, k)
	}
	return out
}

func (r *recordingSessions) Put(_ context.Context, _, sessionID string, data []byte, _ string) (string, error) {
	if r.putErr != nil {
		return "", r.putErr
	}
	if r.blobs == nil {
		r.blobs = map[string][]byte{}
	}
	r.blobs[sessionID] = data
	return "v1", nil
}

func (r *recordingSessions) Get(_ context.Context, _, sessionID string) (blob []byte, version string, err error) {
	return r.blobs[sessionID], "v1", nil
}

func (r *recordingSessions) Delete(_ context.Context, _, sessionID string) error {
	delete(r.blobs, sessionID)
	return nil
}

// TestCloseJob_ARecordWriteFailureDoesNotUndoTheClose asserts the jobs table
// is the source of truth: a session-store failure is logged and the close
// stands.
func TestCloseJob_ARecordWriteFailureDoesNotUndoTheClose(t *testing.T) {
	jobs := newFakeJobStore()
	banks := newFakeBankStore()
	if _, err := banks.Create(context.Background(), "acme", bank.CreateInput{
		Name: "nightly", OwnerKind: bank.OwnerUser, OwnerID: "alice",
		LoginShape: bank.LoginShapeAPIKey, ProviderConfigName: "p",
	}); err != nil {
		t.Fatal(err)
	}
	srv, err := NewJobServer(JobServerConfig{Jobs: jobs, Banks: banks, Authorizer: &fakeAuthorizer{},
		MemberEvents: &recordingMemberEvents{}, Sessions: &recordingSessions{putErr: errors.New("postgres is down")}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := bankCtx(t, "acme", "alice")
	opened, err := srv.OpenJob(ctx, &jobpb.OpenJobRequest{BankId: seededBankID(t, banks), Spec: goodSpec()})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := srv.CloseJob(ctx, &jobpb.CloseJobRequest{JobId: opened.GetJob().GetId(), Verdict: jobpb.JobVerdict_JOB_VERDICT_FAILED})
	if err != nil || resp.GetJob().GetState() != jobpb.JobState_JOB_STATE_CLOSED {
		t.Fatalf("CloseJob = %v, %v", resp, err)
	}
}

// TestRecordResult_OnlyAClosedJobIsRecorded asserts a job that is not closed
// leaves no record: the result is the close, and there is none yet.
func TestRecordResult_OnlyAClosedJobIsRecorded(t *testing.T) {
	sessions := &recordingSessions{}
	srv := &jobServer{sessions: sessions, logger: slog.Default()}
	srv.recordResult(context.Background(), "acme", &job.Job{ID: "job-1", State: job.StateWorking})
	if len(sessions.blobs) != 0 {
		t.Fatalf("an open job must leave no record, have %v", sessions.keys())
	}
}
