// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/capabilitygrant"
	"github.com/zeroroot-ai/gibson/internal/platform/job"
	"github.com/zeroroot-ai/gibson/internal/platform/principal"
	commonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/common/v1"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	jobpb "github.com/zeroroot-ai/sdk/api/gen/gibson/job/v1"
	"github.com/zeroroot-ai/sdk/auth"
	sdkcg "github.com/zeroroot-ai/sdk/capabilitygrant"
)

// fakeJobs is an in-memory JobSurface.
type fakeJobs struct {
	claim      *job.Job
	claimErr   error
	jobs       map[string]*job.Job
	pending    []*job.Input
	pendingErr error
	acked      []string
	ackErr     error
	states     []string
	delivered  []string
	deliverErr error
	getErr     error
	setErr     error
	openErr    error
	sendErr    error
	turnErr    error
	released   []string
	claims     int
	releaseErr error
	opened     []job.OpenInput
	sent       []job.SendInput
	events     map[string][]*job.Event
	// answerTurns makes every Send end its turn at once.
	answerTurns bool
}

func newFakeJobs() *fakeJobs {
	return &fakeJobs{jobs: map[string]*job.Job{}, events: map[string][]*job.Event{}}
}

func (f *fakeJobs) Open(_ context.Context, _ string, in job.OpenInput) (*job.Job, error) {
	if f.openErr != nil {
		return nil, f.openErr
	}
	j := &job.Job{ID: "job-new", BankID: in.BankID, MemberID: "m-1", State: job.StateOpen, Spec: in.Spec, OpenedBy: in.OpenedBy}
	f.jobs[j.ID] = j
	f.opened = append(f.opened, in)
	return j, nil
}

func (f *fakeJobs) Send(_ context.Context, _ string, in job.SendInput) (*job.Input, error) {
	if f.sendErr != nil {
		return nil, f.sendErr
	}
	if _, ok := f.jobs[in.JobID]; !ok {
		return nil, job.ErrNotFound
	}
	f.sent = append(f.sent, in)
	if f.answerTurns {
		// The member answers at once: the turn ends as soon as it is sent.
		f.events[in.JobID] = append(f.events[in.JobID], &job.Event{
			Seq: int64(len(f.events[in.JobID]) + 1), Kind: job.EventState, State: job.StateWaiting,
		})
	}
	return &job.Input{ID: "in-new", JobID: in.JobID, Message: in.Message}, nil
}

func (f *fakeJobs) Events(_ context.Context, _, jobID string, since int64, _ int32) ([]*job.Event, error) {
	var out []*job.Event
	for _, ev := range f.events[jobID] {
		if ev.Seq > since {
			out = append(out, ev)
		}
	}
	return out, nil
}

func (f *fakeJobs) Claim(context.Context, string, string, string) (*job.Job, error) {
	f.claims++
	return f.claim, f.claimErr
}

func (f *fakeJobs) Get(_ context.Context, _, id string) (*job.Job, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	j, ok := f.jobs[id]
	if !ok {
		return nil, job.ErrNotFound
	}
	return j, nil
}

func (f *fakeJobs) PendingInputs(context.Context, string, string, int32) ([]*job.Input, error) {
	if f.pendingErr != nil {
		return nil, f.pendingErr
	}
	return f.pending, nil
}

func (f *fakeJobs) Acknowledge(_ context.Context, _, inputID string) error {
	if f.ackErr != nil {
		return f.ackErr
	}
	f.acked = append(f.acked, inputID)
	return nil
}

func (f *fakeJobs) SetTurn(_ context.Context, _, jobID string, sender job.Principal, inputID string) error {
	if f.turnErr != nil {
		return f.turnErr
	}
	j, ok := f.jobs[jobID]
	if !ok {
		return job.ErrNotFound
	}
	j.TurnSender, j.TurnInputID = sender, inputID
	return nil
}

func (f *fakeJobs) ReleaseJob(_ context.Context, _, jobID, memberID string) error {
	f.released = append(f.released, jobID+"/"+memberID)
	return f.releaseErr
}

func (f *fakeJobs) SetState(_ context.Context, _, jobID string, state job.State, session string) (*job.Job, error) {
	if f.setErr != nil {
		return nil, f.setErr
	}
	f.states = append(f.states, jobID+"="+string(state)+"/"+session)
	return f.jobs[jobID], nil
}

func (f *fakeJobs) AddDeliverable(_ context.Context, _, jobID string, d *jobpb.Deliverable) (*job.Job, error) {
	if f.deliverErr != nil {
		return nil, f.deliverErr
	}
	f.delivered = append(f.delivered, jobID+"="+d.GetRef())
	return f.jobs[jobID], nil
}

// fakeMembers resolves one run to one member.
type fakeMembers struct {
	runID, memberID, bankID string
	err                     error
}

func (f *fakeMembers) MemberByRun(_ context.Context, _, runID string) (memberID, bankID string, err error) {
	if f.err != nil {
		return "", "", f.err
	}
	if runID != f.runID {
		return "", "", ErrNotAMember
	}
	return f.memberID, f.bankID, nil
}

// recordingMinter records what a turn grant was minted for.
type recordingMinter struct {
	reqs     []capabilitygrant.MintRequest
	err      error
	notReady error
}

// Ready is the check before a claim. notReady makes it fail.
func (m *recordingMinter) Ready() error { return m.notReady }

func (m *recordingMinter) Mint(req capabilitygrant.MintRequest) (string, error) {
	if m.err != nil {
		return "", m.err
	}
	m.reqs = append(m.reqs, req)
	return "turn-grant-for-" + req.TaskID, nil
}

func memberService(t *testing.T, jobs JobSurface, members MemberLookup, minter TurnGrantMinter) *HarnessCallbackService {
	t.Helper()
	return NewHarnessCallbackService(nil,
		WithJobSurface(jobs), WithMemberLookup(members), WithTurnGrantMinter(minter), testEventBus())
}

func memberCtx(tenant string) context.Context {
	return metadata.NewIncomingContext(
		auth.ContextWithTenantString(context.Background(), tenant), metadata.MD{})
}

func memberInfo(runID string) *harnesspb.ContextInfo {
	return &harnesspb.ContextInfo{MissionRunId: runID, MissionId: "bank-1", AgentName: "claude"}
}

func liveMembers() *fakeMembers {
	return &fakeMembers{runID: "run-1", memberID: "m-1", bankID: "bank-1"}
}

func openJob(id string) *job.Job {
	return &job.Job{
		ID: id, BankID: "bank-1", MemberID: "m-1", State: job.StateWorking,
		Spec: &jobpb.JobSpec{Goal: "fix it", CredentialNames: []string{"gitlab-token"}},
		// A job always records the sender of its current turn: Open sets the opener.
		TurnSender: job.Principal{Kind: job.PrincipalUser, ID: "alice"},
	}
}

func TestPullJob_TakesTheNextJobOfTheMembersOwnBank(t *testing.T) {
	jobs := newFakeJobs()
	jobs.claim = openJob("job-1")
	s := memberService(t, jobs, liveMembers(), &recordingMinter{})

	resp, err := s.PullJob(memberCtx("acme"), &harnesspb.PullJobRequest{Context: memberInfo("run-1")})
	if err != nil {
		t.Fatalf("PullJob: %v", err)
	}
	if resp.GetJob().GetId() != "job-1" {
		t.Fatalf("job = %+v", resp.GetJob())
	}
	if resp.GetJob().GetSpec().GetGoal() != "fix it" {
		t.Error("the member must see the spec the opener declared")
	}
}

func TestPullJob_AnEmptyQueueIsNotAnError(t *testing.T) {
	s := memberService(t, newFakeJobs(), liveMembers(), &recordingMinter{})
	resp, err := s.PullJob(memberCtx("acme"), &harnesspb.PullJobRequest{Context: memberInfo("run-1")})
	if err != nil {
		t.Fatalf("an empty queue is the ordinary case: %v", err)
	}
	if resp.GetJob() != nil {
		t.Fatalf("job = %+v, want none", resp.GetJob())
	}
}

func TestPullJob_AMemberWithNoRoomGetsNothing(t *testing.T) {
	jobs := newFakeJobs()
	jobs.claimErr = job.ErrNoFreeSlot
	s := memberService(t, jobs, liveMembers(), &recordingMinter{})

	resp, err := s.PullJob(memberCtx("acme"), &harnesspb.PullJobRequest{Context: memberInfo("run-1")})
	if err != nil {
		t.Fatalf("a member whose bookkeeping is behind is not a failure: %v", err)
	}
	if resp.GetJob() != nil {
		t.Fatal("a member with no room takes no job")
	}
}

// TestPullJob_ARunThatIsNotAMembersIsRefused: the member is resolved from the
// run on the verified context, so a caller that is not a member gets nothing
// and learns nothing.
func TestPullJob_ARunThatIsNotAMembersIsRefused(t *testing.T) {
	s := memberService(t, newFakeJobs(), liveMembers(), &recordingMinter{})
	_, err := s.PullJob(memberCtx("acme"), &harnesspb.PullJobRequest{Context: memberInfo("run-other")})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("err = %v, want PermissionDenied", err)
	}
}

func TestPullJob_NeedsATenantAndARun(t *testing.T) {
	s := memberService(t, newFakeJobs(), liveMembers(), &recordingMinter{})
	if _, err := s.PullJob(context.Background(), &harnesspb.PullJobRequest{Context: memberInfo("run-1")}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("no tenant must be PermissionDenied, got %v", err)
	}
	if _, err := s.PullJob(memberCtx("acme"), &harnesspb.PullJobRequest{}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("no mission run must be InvalidArgument, got %v", err)
	}
}

func TestPullJob_ADaemonThatServesNoBanksSaysSo(t *testing.T) {
	s := NewHarnessCallbackService(nil, testEventBus())
	_, err := s.PullJob(memberCtx("acme"), &harnesspb.PullJobRequest{Context: memberInfo("run-1")})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("err = %v, want FailedPrecondition", err)
	}
}

// recordingInputStream captures the inputs SubscribeInput delivers and ends the
// stream after the first poll.
type recordingInputStream struct {
	grpc.ServerStream
	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.Mutex
	sent   []*jobpb.Input
}

func (s *recordingInputStream) Context() context.Context { return s.ctx }
func (s *recordingInputStream) Send(m *harnesspb.SubscribeInputResponse) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sent = append(s.sent, m.GetInput())
	return nil
}

// snapshot copies what the stream delivered so far. SubscribeInput sends from
// its own goroutine, so a test must never read the slice directly.
func (s *recordingInputStream) snapshot() []*jobpb.Input {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*jobpb.Input(nil), s.sent...)
}

// TestSubscribeInput_DeliversEachInputWithItsOwnTurnGrant is the property the
// whole design turns on: one sandbox serves many senders, and each turn carries
// the authority of the sender who asked for it.
func TestSubscribeInput_DeliversEachInputWithItsOwnTurnGrant(t *testing.T) {
	jobs := newFakeJobs()
	jobs.jobs["job-1"] = openJob("job-1")
	jobs.jobs["job-2"] = openJob("job-2")
	jobs.pending = []*job.Input{
		{ID: "in-1", JobID: "job-1", Message: "one", Kind: job.InputTurn, SentAt: time.Now(),
			Sender: job.Principal{Kind: job.PrincipalUser, ID: "alice"}},
		{ID: "in-2", JobID: "job-2", Message: "two", Kind: job.InputAnswer, SentAt: time.Now(),
			Sender: job.Principal{Kind: job.PrincipalComponent, ID: "agent_principal:node"}},
	}
	minter := &recordingMinter{}
	s := memberService(t, jobs, liveMembers(), minter)

	ctx, cancel := context.WithCancel(memberCtx("acme"))
	stream := &recordingInputStream{ctx: ctx, cancel: cancel}
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()
	if err := s.SubscribeInput(&harnesspb.SubscribeInputRequest{Context: memberInfo("run-1")}, stream); err != nil { //nolint:contextcheck // the stream carries the context
		t.Fatalf("SubscribeInput: %v", err)
	}

	sent := stream.snapshot()
	if len(sent) != 2 {
		t.Fatalf("delivered %d inputs, want both", len(sent))
	}
	if sent[0].GetGrant() != "turn-grant-for-job-1" || sent[1].GetGrant() != "turn-grant-for-job-2" {
		t.Fatalf("each input must carry its own turn grant: %q %q",
			sent[0].GetGrant(), sent[1].GetGrant())
	}
	if len(minter.reqs) != 2 {
		t.Fatalf("minted %d grants, want one per input", len(minter.reqs))
	}
	for i, req := range minter.reqs {
		if req.MissionRunID != "run-1" {
			t.Errorf("turn grant %d carries run %q, want the run of the member (run-1)", i, req.MissionRunID)
		}
	}
	// The delivery starts the turn of the sender: the grant renews for that sender only.
	if got := jobs.jobs["job-1"]; got.TurnSender.ID != "alice" || got.TurnInputID != "in-1" {
		t.Errorf("turn of job-1 = %+v / %q, want alice / in-1", got.TurnSender, got.TurnInputID)
	}
	if got := jobs.jobs["job-2"]; got.TurnSender.ID != "agent_principal:node" || got.TurnInputID != "in-2" {
		t.Errorf("turn of job-2 = %+v / %q, want the component / in-2", got.TurnSender, got.TurnInputID)
	}
	if minter.reqs[0].Subject != "user:alice" {
		t.Errorf("subject = %q; a turn carries the SENDER's authority, not the member's", minter.reqs[0].Subject)
	}
	if minter.reqs[1].Subject != "agent_principal:node" {
		t.Errorf("subject = %q; a component sender is already a typed principal", minter.reqs[1].Subject)
	}
	for _, req := range minter.reqs {
		for _, rpc := range req.AllowedRPCs {
			if methodName(rpc) == "PullJob" {
				t.Error("a turn grant must not carry the member's own surface")
			}
		}
	}
}

// TestSubscribeInput_DoesNotResendWhatItAlreadyDelivered: the poll re-reads
// everything unacknowledged, so the stream has to remember what it sent.
func TestSubscribeInput_DoesNotResendWhatItAlreadyDelivered(t *testing.T) {
	jobs := newFakeJobs()
	jobs.jobs["job-1"] = openJob("job-1")
	jobs.pending = []*job.Input{{
		ID: "in-1", JobID: "job-1", Message: "one", Kind: job.InputTurn, SentAt: time.Now(),
		Sender: job.Principal{Kind: job.PrincipalUser, ID: "alice"},
	}}
	s := memberService(t, jobs, liveMembers(), &recordingMinter{})

	ctx, cancel := context.WithCancel(memberCtx("acme"))
	stream := &recordingInputStream{ctx: ctx}
	// Long enough for several polls at the two-second interval would be slow;
	// the first poll plus the cancel is what proves the memory, because the
	// second poll would otherwise resend before the context ends.
	go func() { time.Sleep(2500 * time.Millisecond); cancel() }()
	if err := s.SubscribeInput(&harnesspb.SubscribeInputRequest{Context: memberInfo("run-1")}, stream); err != nil { //nolint:contextcheck // the stream carries the context
		t.Fatalf("SubscribeInput: %v", err)
	}
	if len(stream.snapshot()) != 1 {
		t.Fatalf("delivered %d, want the input once", len(stream.snapshot()))
	}
}

func TestSubscribeInput_ADaemonThatCannotMintRefuses(t *testing.T) {
	jobs := newFakeJobs()
	jobs.jobs["job-1"] = openJob("job-1")
	jobs.pending = []*job.Input{{ID: "in-1", JobID: "job-1", Kind: job.InputTurn,
		Sender: job.Principal{Kind: job.PrincipalUser, ID: "alice"}}}
	s := NewHarnessCallbackService(nil, WithJobSurface(jobs), WithMemberLookup(liveMembers()), testEventBus())

	ctx, cancel := context.WithCancel(memberCtx("acme"))
	defer cancel()
	err := s.SubscribeInput(&harnesspb.SubscribeInputRequest{Context: memberInfo("run-1")}, //nolint:contextcheck // the stream carries the context
		&recordingInputStream{ctx: ctx})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("err = %v, want FailedPrecondition: an input without its grant is not deliverable", err)
	}
}

func TestReportJobState_RecordsAndAcknowledges(t *testing.T) {
	jobs := newFakeJobs()
	jobs.jobs["job-1"] = openJob("job-1")
	jobs.pending = []*job.Input{
		{ID: "in-1", JobID: "job-1"},
		{ID: "in-other", JobID: "job-2"},
	}
	s := memberService(t, jobs, liveMembers(), &recordingMinter{})

	if _, err := s.ReportJobState(memberCtx("acme"), &harnesspb.ReportJobStateRequest{
		Context: memberInfo("run-1"), JobId: "job-1",
		State: jobpb.JobState_JOB_STATE_WORKING, ClaudeSessionId: "sess-1",
	}); err != nil {
		t.Fatalf("ReportJobState: %v", err)
	}
	if len(jobs.states) != 1 || jobs.states[0] != "job-1=working/sess-1" {
		t.Fatalf("states = %v", jobs.states)
	}
	if len(jobs.acked) != 1 || jobs.acked[0] != "in-1" {
		t.Fatalf("acked = %v, want only this job's input; a turn already run must not replay", jobs.acked)
	}
}

// TestReportJobState_AMemberNeverClosesItsOwnJob is the rule the scorer design
// rests on, enforced at the callback as well as in the store.
func TestReportJobState_AMemberNeverClosesItsOwnJob(t *testing.T) {
	jobs := newFakeJobs()
	jobs.jobs["job-1"] = openJob("job-1")
	s := memberService(t, jobs, liveMembers(), &recordingMinter{})

	_, err := s.ReportJobState(memberCtx("acme"), &harnesspb.ReportJobStateRequest{
		Context: memberInfo("run-1"), JobId: "job-1", State: jobpb.JobState_JOB_STATE_CLOSED,
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("err = %v, want InvalidArgument", err)
	}
	if len(jobs.states) != 0 {
		t.Error("nothing may be recorded for a state a member cannot report")
	}
}

// TestReportJobState_AnotherMembersJobIsNotFound: a job id is not a capability.
func TestReportJobState_AnotherMembersJobIsNotFound(t *testing.T) {
	jobs := newFakeJobs()
	other := openJob("job-9")
	other.MemberID = "m-2"
	jobs.jobs["job-9"] = other
	s := memberService(t, jobs, liveMembers(), &recordingMinter{})

	_, err := s.ReportJobState(memberCtx("acme"), &harnesspb.ReportJobStateRequest{
		Context: memberInfo("run-1"), JobId: "job-9", State: jobpb.JobState_JOB_STATE_WORKING,
	})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("err = %v, want NotFound; a member must not learn another member's job exists", err)
	}
}

func TestReportJobState_NeedsAJobId(t *testing.T) {
	s := memberService(t, newFakeJobs(), liveMembers(), &recordingMinter{})
	_, err := s.ReportJobState(memberCtx("acme"), &harnesspb.ReportJobStateRequest{
		Context: memberInfo("run-1"), State: jobpb.JobState_JOB_STATE_WORKING,
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("err = %v, want InvalidArgument", err)
	}
}

func TestReportDeliverable_RecordsWhatTheDriverDid(t *testing.T) {
	jobs := newFakeJobs()
	jobs.jobs["job-1"] = openJob("job-1")
	s := memberService(t, jobs, liveMembers(), &recordingMinter{})

	if _, err := s.ReportDeliverable(memberCtx("acme"), &harnesspb.ReportDeliverableRequest{
		Context: memberInfo("run-1"), JobId: "job-1",
		Deliverable: &jobpb.Deliverable{
			Kind: jobpb.DeliverableKind_DELIVERABLE_KIND_MERGE_REQUEST, Ref: "mr-7",
		},
	}); err != nil {
		t.Fatalf("ReportDeliverable: %v", err)
	}
	if len(jobs.delivered) != 1 || jobs.delivered[0] != "job-1=mr-7" {
		t.Fatalf("delivered = %v", jobs.delivered)
	}
}

func TestReportDeliverable_NeedsADeliverableAndTheMembersOwnJob(t *testing.T) {
	jobs := newFakeJobs()
	jobs.jobs["job-1"] = openJob("job-1")
	other := openJob("job-9")
	other.MemberID = "m-2"
	jobs.jobs["job-9"] = other
	s := memberService(t, jobs, liveMembers(), &recordingMinter{})

	if _, err := s.ReportDeliverable(memberCtx("acme"), &harnesspb.ReportDeliverableRequest{
		Context: memberInfo("run-1"), JobId: "job-1",
	}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("no deliverable must be InvalidArgument, got %v", err)
	}
	if _, err := s.ReportDeliverable(memberCtx("acme"), &harnesspb.ReportDeliverableRequest{
		Context: memberInfo("run-1"), JobId: "job-9",
		Deliverable: &jobpb.Deliverable{Ref: "mr-1"},
	}); status.Code(err) != codes.NotFound {
		t.Errorf("another member's job must be NotFound, got %v", err)
	}
}

func TestTurnGrantSubject(t *testing.T) {
	if got := TurnGrantSubject(job.Principal{Kind: job.PrincipalComponent, ID: "agent_principal:x"}); got != "agent_principal:x" {
		t.Errorf("a component is already a typed principal, got %q", got)
	}
	if got := TurnGrantSubject(job.Principal{Kind: job.PrincipalUser, ID: "alice"}); got != "user:alice" {
		t.Errorf("got %q", got)
	}
}

func TestJobCallbackError_Mapping(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want codes.Code
	}{
		{job.ErrNotFound, codes.NotFound},
		{job.ErrClosed, codes.FailedPrecondition},
		{job.ErrInvalid, codes.InvalidArgument},
		{ErrNoBankSurface, codes.FailedPrecondition},
		{errors.New("boom"), codes.Internal},
	} {
		if got := status.Code(jobCallbackError(tc.err)); got != tc.want {
			t.Errorf("jobCallbackError(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
}

// TestCallerMember_AnOutageIsNotReadAsNotAMember asserts that a bank store
// outage answers Unavailable, never the "not a member" refusal, so a member
// retries rather than concludes it was evicted.
func TestCallerMember_AnOutageIsNotReadAsNotAMember(t *testing.T) {
	s := memberService(t, newFakeJobs(), &fakeMembers{err: errors.New("postgres is down")}, &recordingMinter{})
	_, err := s.PullJob(memberCtx("acme"), &harnesspb.PullJobRequest{Context: memberInfo("run-1")})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("err = %v, want Unavailable", err)
	}
}

// TestNoBankSurface_EverySeamRefuses asserts the default behind the member
// seams: every call answers ErrNoBankSurface, so nothing is ever nil.
func TestNoBankSurface_EverySeamRefuses(t *testing.T) {
	var n noBankSurface
	ctx := context.Background()
	calls := map[string]func() error{
		"Claim":         func() error { _, err := n.Claim(ctx, "t", "b", "m"); return err },
		"Get":           func() error { _, err := n.Get(ctx, "t", "j"); return err },
		"PendingInputs": func() error { _, err := n.PendingInputs(ctx, "t", "m", 1); return err },
		"Acknowledge":   func() error { return n.Acknowledge(ctx, "t", "i") },
		"SetTurn":       func() error { return n.SetTurn(ctx, "t", "j", job.Principal{}, "i") },
		"ReleaseJob":    func() error { return n.ReleaseJob(ctx, "t", "j", "m") },
		"Ready":         n.Ready,
		"SetState":      func() error { _, err := n.SetState(ctx, "t", "j", job.StateWorking, ""); return err },
		"AddDeliverable": func() error {
			_, err := n.AddDeliverable(ctx, "t", "j", &jobpb.Deliverable{})
			return err
		},
		"MemberByRun": func() error { _, _, err := n.MemberByRun(ctx, "t", "r"); return err },
		"Mint":        func() error { _, err := n.Mint(capabilitygrant.MintRequest{}); return err },
	}
	for name, call := range calls {
		if err := call(); !errors.Is(err, ErrNoBankSurface) {
			t.Errorf("%s: err = %v, want ErrNoBankSurface", name, err)
		}
	}
}

// TestSubscribeInput_OneSubscriberPerMember asserts the contract the member
// driver builds on: one process reads the inbox. A second concurrent stream
// for the same member is refused with AlreadyExists, and the slot is free
// again once the first stream ends.
func TestSubscribeInput_OneSubscriberPerMember(t *testing.T) {
	s := memberService(t, newFakeJobs(), liveMembers(), &recordingMinter{})

	first, cancelFirst := context.WithCancel(memberCtx("acme"))
	firstDone := make(chan error, 1)
	go func() {
		// The stream carries the context, as every gRPC server stream does.
		firstDone <- s.SubscribeInput(&harnesspb.SubscribeInputRequest{Context: memberInfo("run-1")}, //nolint:contextcheck // the stream's Context() is the request context
			&recordingInputStream{ctx: first})
	}()
	waitFor(t, func() bool { _, live := s.memberInboxes.Load("acme/m-1"); return live })

	second, cancelSecond := context.WithCancel(memberCtx("acme"))
	defer cancelSecond()
	err := s.SubscribeInput(&harnesspb.SubscribeInputRequest{Context: memberInfo("run-1")}, //nolint:contextcheck // the stream carries the context
		&recordingInputStream{ctx: second})
	if status.Code(err) != codes.AlreadyExists {
		t.Fatalf("second subscriber: err = %v, want AlreadyExists", err)
	}

	cancelFirst()
	if err := <-firstDone; err != nil {
		t.Fatalf("first subscriber: %v", err)
	}
	if _, live := s.memberInboxes.Load("acme/m-1"); live {
		t.Fatal("the slot must be free once the stream ends")
	}
}

// waitFor polls a condition so a test never sleeps a fixed time.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestJobWire_EveryNamedValueRoundTrips asserts that every job state, input
// kind and principal kind the member sees on the wire is its own value, and
// that an unknown value renders as the documented default.
func TestJobWire_EveryNamedValueRoundTrips(t *testing.T) {
	states := map[job.State]jobpb.JobState{
		job.StateOpen:    jobpb.JobState_JOB_STATE_OPEN,
		job.StateWorking: jobpb.JobState_JOB_STATE_WORKING,
		job.StateWaiting: jobpb.JobState_JOB_STATE_WAITING,
		job.StateClosed:  jobpb.JobState_JOB_STATE_CLOSED,
	}
	for domain, wire := range states {
		if got := jobStateToWire(domain); got != wire {
			t.Errorf("jobStateToWire(%q) = %v, want %v", domain, got, wire)
		}
		if got := wireToJobState(wire); got != domain {
			t.Errorf("wireToJobState(%v) = %q, want %q", wire, got, domain)
		}
	}
	if got := jobStateToWire(job.State("")); got != jobpb.JobState_JOB_STATE_UNSPECIFIED {
		t.Errorf("an unknown state must render as unspecified, got %v", got)
	}
	if got := wireToJobState(jobpb.JobState_JOB_STATE_UNSPECIFIED); got != "" {
		t.Errorf("an unspecified wire state must read as empty, got %q", got)
	}

	kinds := map[job.InputKind]jobpb.InputKind{
		job.InputTurn:   jobpb.InputKind_INPUT_KIND_TURN,
		job.InputAnswer: jobpb.InputKind_INPUT_KIND_ANSWER,
		job.InputWrapUp: jobpb.InputKind_INPUT_KIND_WRAP_UP,
	}
	for domain, wire := range kinds {
		if got := inputKindToWire(domain); got != wire {
			t.Errorf("inputKindToWire(%q) = %v, want %v", domain, got, wire)
		}
	}

	principals := map[job.PrincipalKind]commonpb.Principal_Kind{
		job.PrincipalUser:      commonpb.Principal_KIND_USER,
		job.PrincipalTenant:    commonpb.Principal_KIND_TENANT,
		job.PrincipalComponent: commonpb.Principal_KIND_COMPONENT,
		job.PrincipalService:   commonpb.Principal_KIND_SERVICE,
	}
	for domain, wire := range principals {
		got := principal.ToProto(job.Principal{Kind: domain, ID: "p-1"})
		if got.GetKind() != wire || got.GetId() != "p-1" {
			t.Errorf("principal.ToProto(%q) = %v/%q, want %v/p-1", domain, got.GetKind(), got.GetId(), wire)
		}
	}
}

// failingInputStream refuses every Send.
type failingInputStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *failingInputStream) Context() context.Context { return s.ctx }
func (s *failingInputStream) Send(*harnesspb.SubscribeInputResponse) error {
	return errors.New("the member went away")
}

func pendingTurn() []*job.Input {
	return []*job.Input{{ID: "in-1", JobID: "job-1", Kind: job.InputTurn,
		Sender: job.Principal{Kind: job.PrincipalUser, ID: "alice"}}}
}

// TestMemberCallbacks_EveryStoreFailureIsReported asserts the callbacks report
// a store or transport failure with the right code, never hide it: a member
// that cannot read its inbox or record its state must know.
func TestMemberCallbacks_EveryStoreFailureIsReported(t *testing.T) {
	boom := errors.New("postgres is down")
	ctx := memberCtx("acme")
	info := memberInfo("run-1")
	stranger := memberInfo("run-stranger")

	t.Run("a stranger is refused on every callback", func(t *testing.T) {
		s := memberService(t, newFakeJobs(), liveMembers(), &recordingMinter{})
		sctx, cancel := context.WithCancel(ctx)
		defer cancel()
		if err := s.SubscribeInput(&harnesspb.SubscribeInputRequest{Context: stranger}, &recordingInputStream{ctx: sctx}); status.Code(err) != codes.PermissionDenied { //nolint:contextcheck // the stream carries the context
			t.Errorf("SubscribeInput: %v", err)
		}
		if _, err := s.ReportJobState(ctx, &harnesspb.ReportJobStateRequest{Context: stranger, JobId: "job-1", State: jobpb.JobState_JOB_STATE_WORKING}); status.Code(err) != codes.PermissionDenied {
			t.Errorf("ReportJobState: %v", err)
		}
		if _, err := s.ReportDeliverable(ctx, &harnesspb.ReportDeliverableRequest{Context: stranger, JobId: "job-1", Deliverable: &jobpb.Deliverable{Ref: "x"}}); status.Code(err) != codes.PermissionDenied {
			t.Errorf("ReportDeliverable: %v", err)
		}
	})
	t.Run("the inbox cannot be read", func(t *testing.T) {
		jobs := newFakeJobs()
		jobs.pendingErr = boom
		s := memberService(t, jobs, liveMembers(), &recordingMinter{})
		sctx, cancel := context.WithCancel(ctx)
		defer cancel()
		if err := s.SubscribeInput(&harnesspb.SubscribeInputRequest{Context: info}, &recordingInputStream{ctx: sctx}); status.Code(err) != codes.Internal { //nolint:contextcheck // the stream carries the context
			t.Errorf("SubscribeInput: %v", err)
		}
		jobs.jobs["job-1"] = openJob("job-1")
		if _, err := s.ReportJobState(ctx, &harnesspb.ReportJobStateRequest{Context: info, JobId: "job-1", State: jobpb.JobState_JOB_STATE_WORKING}); status.Code(err) != codes.Internal {
			t.Errorf("ReportJobState must report an inbox it cannot acknowledge: %v", err)
		}
	})
	t.Run("the member went away mid-delivery", func(t *testing.T) {
		jobs := newFakeJobs()
		jobs.jobs["job-1"] = openJob("job-1")
		jobs.pending = pendingTurn()
		s := memberService(t, jobs, liveMembers(), &recordingMinter{})
		sctx, cancel := context.WithCancel(ctx)
		defer cancel()
		if err := s.SubscribeInput(&harnesspb.SubscribeInputRequest{Context: info}, &failingInputStream{ctx: sctx}); status.Code(err) != codes.Unavailable { //nolint:contextcheck // the stream carries the context
			t.Errorf("SubscribeInput: %v", err)
		}
	})
	t.Run("the input's job cannot be read", func(t *testing.T) {
		jobs := newFakeJobs()
		jobs.pending = pendingTurn()
		jobs.getErr = boom
		s := memberService(t, jobs, liveMembers(), &recordingMinter{})
		sctx, cancel := context.WithCancel(ctx)
		defer cancel()
		if err := s.SubscribeInput(&harnesspb.SubscribeInputRequest{Context: info}, &recordingInputStream{ctx: sctx}); status.Code(err) != codes.Internal { //nolint:contextcheck // the stream carries the context
			t.Errorf("SubscribeInput: %v", err)
		}
		if _, err := s.ReportJobState(ctx, &harnesspb.ReportJobStateRequest{Context: info, JobId: "job-1", State: jobpb.JobState_JOB_STATE_WORKING}); status.Code(err) != codes.Internal {
			t.Errorf("ReportJobState: %v", err)
		}
	})
	t.Run("the minter fails", func(t *testing.T) {
		jobs := newFakeJobs()
		jobs.jobs["job-1"] = openJob("job-1")
		jobs.pending = pendingTurn()
		s := memberService(t, jobs, liveMembers(), &recordingMinter{err: errors.New("no key")})
		sctx, cancel := context.WithCancel(ctx)
		defer cancel()
		if err := s.SubscribeInput(&harnesspb.SubscribeInputRequest{Context: info}, &recordingInputStream{ctx: sctx}); status.Code(err) != codes.Internal { //nolint:contextcheck // the stream carries the context
			t.Errorf("SubscribeInput: %v", err)
		}
	})
	t.Run("the state and the deliverable cannot be written", func(t *testing.T) {
		jobs := newFakeJobs()
		jobs.jobs["job-1"] = openJob("job-1")
		jobs.setErr = boom
		jobs.deliverErr = boom
		s := memberService(t, jobs, liveMembers(), &recordingMinter{})
		if _, err := s.ReportJobState(ctx, &harnesspb.ReportJobStateRequest{Context: info, JobId: "job-1", State: jobpb.JobState_JOB_STATE_WORKING}); status.Code(err) != codes.Internal {
			t.Errorf("ReportJobState: %v", err)
		}
		if _, err := s.ReportDeliverable(ctx, &harnesspb.ReportDeliverableRequest{Context: info, JobId: "job-1", Deliverable: &jobpb.Deliverable{Ref: "x"}}); status.Code(err) != codes.Internal {
			t.Errorf("ReportDeliverable: %v", err)
		}
	})
	t.Run("an acknowledgment fails", func(t *testing.T) {
		jobs := newFakeJobs()
		jobs.jobs["job-1"] = openJob("job-1")
		jobs.pending = pendingTurn()
		jobs.ackErr = boom
		s := memberService(t, jobs, liveMembers(), &recordingMinter{})
		if _, err := s.ReportJobState(ctx, &harnesspb.ReportJobStateRequest{Context: info, JobId: "job-1", State: jobpb.JobState_JOB_STATE_WORKING}); status.Code(err) != codes.Internal {
			t.Errorf("ReportJobState: %v", err)
		}
	})
	t.Run("a claim fails", func(t *testing.T) {
		jobs := newFakeJobs()
		jobs.claimErr = boom
		s := memberService(t, jobs, liveMembers(), &recordingMinter{})
		if _, err := s.PullJob(ctx, &harnesspb.PullJobRequest{Context: info}); status.Code(err) != codes.Internal {
			t.Errorf("PullJob: %v", err)
		}
	})
}

// TestJobWire_UnnamedValuesTakeTheDocumentedDefault covers the wire defaults
// for values no name maps to.
func TestJobWire_UnnamedValuesTakeTheDocumentedDefault(t *testing.T) {
	if got := wireToJobState(jobpb.JobState(99)); got != "" {
		t.Errorf("an unknown wire state must read as empty, got %q", got)
	}
	if got := inputKindToWire(job.InputKind("")); got != jobpb.InputKind_INPUT_KIND_TURN {
		t.Errorf("an unnamed input kind renders as a turn, got %v", got)
	}
}

// recordingMemberEvents captures the console lines the callbacks emitted. The
// stream publishes from its own goroutine, so the recorder locks.
type recordingMemberEvents struct {
	mu    sync.Mutex
	lines []string
}

func (r *recordingMemberEvents) PublishMemberEvent(_ context.Context, _, memberID string, line []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lines = append(r.lines, memberID+" "+string(line))
}

// snapshot copies the lines recorded so far.
func (r *recordingMemberEvents) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.lines...)
}

// TestMemberCallbacks_PutTheJobLinesOnTheMembersStream asserts each member
// callback emits the line the console renders (dashboard#1170): job_opened
// on a claim, job_input on delivery, job_state on a report, job_deliverable
// on a deliverable, each naming the member and the job.
func TestMemberCallbacks_PutTheJobLinesOnTheMembersStream(t *testing.T) {
	jobs := newFakeJobs()
	jobs.jobs["job-1"] = openJob("job-1")
	jobs.claim = jobs.jobs["job-1"]
	jobs.pending = []*job.Input{{ID: "in-1", JobID: "job-1", Kind: job.InputTurn, Message: "please fix the build",
		Sender: job.Principal{Kind: job.PrincipalUser, ID: "alice"}}}
	events := &recordingMemberEvents{}
	s := NewHarnessCallbackService(nil, WithJobSurface(jobs), WithMemberLookup(liveMembers()),
		WithTurnGrantMinter(&recordingMinter{}), WithMemberEventSink(events), testEventBus())
	ctx := memberCtx("acme")

	if _, err := s.PullJob(ctx, &harnesspb.PullJobRequest{Context: memberInfo("run-1")}); err != nil {
		t.Fatal(err)
	}
	sctx, cancel := context.WithCancel(ctx)
	stream := &recordingInputStream{ctx: sctx, cancel: cancel}
	go func() { _ = s.SubscribeInput(&harnesspb.SubscribeInputRequest{Context: memberInfo("run-1")}, stream) }()
	waitFor(t, func() bool { return len(events.snapshot()) >= 2 })
	cancel()
	if _, err := s.ReportJobState(ctx, &harnesspb.ReportJobStateRequest{Context: memberInfo("run-1"), JobId: "job-1",
		State: jobpb.JobState_JOB_STATE_WORKING, ClaudeSessionId: "sess-1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReportDeliverable(ctx, &harnesspb.ReportDeliverableRequest{Context: memberInfo("run-1"), JobId: "job-1",
		Deliverable: &jobpb.Deliverable{Kind: jobpb.DeliverableKind_DELIVERABLE_KIND_PUSH_BRANCH, Ref: "fix/build", Url: "https://x/mr/1"}}); err != nil {
		t.Fatal(err)
	}

	want := []string{
		`m-1 {"goal":"fix it","job_id":"job-1","type":"job_opened"}`,
		`m-1 {"job_id":"job-1","kind":"turn","message":"please fix the build","sender":"user:alice","type":"job_input"}`,
		`m-1 {"job_id":"job-1","state":"working","type":"job_state"}`,
		`m-1 {"job_id":"job-1","kind":"push_branch","ref":"fix/build","type":"job_deliverable","url":"https://x/mr/1"}`,
	}
	got := events.snapshot()
	if len(got) != len(want) {
		t.Fatalf("lines = %q", got)
	}
	for i, w := range want {
		if strings.TrimSpace(got[i]) != w {
			t.Errorf("line %d = %q, want %q", i, strings.TrimSpace(got[i]), w)
		}
	}
}

// TestFirstRunes_AndDeliverableKindName cover the two small renderers.
func TestFirstRunes_AndDeliverableKindName(t *testing.T) {
	if got := firstRunes("héllo wörld", 5); got != "héllo" {
		t.Errorf("firstRunes = %q", got)
	}
	if got := firstRunes("short", 200); got != "short" {
		t.Errorf("firstRunes = %q", got)
	}
	for k, want := range map[jobpb.DeliverableKind]string{
		jobpb.DeliverableKind_DELIVERABLE_KIND_PUSH_BRANCH:   "push_branch",
		jobpb.DeliverableKind_DELIVERABLE_KIND_MERGE_REQUEST: "merge_request",
		jobpb.DeliverableKind_DELIVERABLE_KIND_NONE:          "none",
		jobpb.DeliverableKind_DELIVERABLE_KIND_UNSPECIFIED:   "unspecified",
		jobpb.DeliverableKind(99):                            "unspecified",
	} {
		if got := deliverableKindName(k); got != want {
			t.Errorf("deliverableKindName(%v) = %q, want %q", k, got, want)
		}
	}
}

// TestSubscribeInput_ControlInputsComeFirstAndCarryNoGrant asserts a sign-in
// word queued for the member is delivered ahead of its jobs, without a grant
// and without an acknowledgment, and is delivered once.
func TestSubscribeInput_ControlInputsComeFirstAndCarryNoGrant(t *testing.T) {
	jobs := newFakeJobs()
	jobs.jobs["job-1"] = openJob("job-1")
	jobs.pending = pendingTurn()
	control := NewMemberControl()
	control.StartSignIn("acme", "m-1", "alice")
	control.SubmitSignInCode("acme", "m-1", "CODE-1", "alice")
	s := NewHarnessCallbackService(nil, WithJobSurface(jobs), WithMemberLookup(liveMembers()),
		WithTurnGrantMinter(&recordingMinter{}), WithMemberControl(control), testEventBus())

	ctx, cancel := context.WithCancel(memberCtx("acme"))
	stream := &recordingInputStream{ctx: ctx, cancel: cancel}
	done := make(chan error, 1)
	go func() {
		done <- s.SubscribeInput(&harnesspb.SubscribeInputRequest{Context: memberInfo("run-1")}, stream)
	}()
	waitFor(t, func() bool { return len(stream.snapshot()) >= 3 })
	cancel()
	<-done

	sent := stream.snapshot()
	if sent[0].GetJobId() != SignInJobID || sent[0].GetMessage() != SignInStart || sent[0].GetGrant() != "" {
		t.Errorf("first = %+v, want the start word with no grant", sent[0])
	}
	if sent[1].GetMessage() != "CODE-1" || sent[1].GetGrant() != "" {
		t.Errorf("second = %+v, want the code with no grant", sent[1])
	}
	if sent[2].GetJobId() != "job-1" || sent[2].GetGrant() == "" {
		t.Errorf("third = %+v, want the job's turn with its grant", sent[2])
	}
	if control.Pending("acme", "m-1") != 0 {
		t.Error("delivered control inputs must be forgotten")
	}
	if len(jobs.acked) != 0 {
		t.Error("a control input is never acknowledged: it was never stored")
	}
}

// TestMemberControl_DropsWhatNobodyTookInTime asserts a code that sat past
// the TTL is dropped unseen, and the queue is per member.
func TestMemberControl_DropsWhatNobodyTookInTime(t *testing.T) {
	c := NewMemberControl()
	now := time.Now()
	c.now = func() time.Time { return now }
	c.SubmitSignInCode("acme", "m-1", "OLD", "alice")
	c.StartSignIn("acme", "m-2", "alice")
	now = now.Add(ControlInputTTL + time.Second)
	c.SubmitSignInCode("acme", "m-1", "NEW", "alice")
	got := c.Drain("acme", "m-1")
	if len(got) != 1 || got[0].GetMessage() != "NEW" {
		t.Fatalf("drained %+v, want only the fresh code", got)
	}
	if c.Pending("acme", "m-2") != 1 || c.Pending("acme", "m-1") != 0 {
		t.Error("queues are per member")
	}
	if got := c.Drain("globex", "m-1"); len(got) != 0 {
		t.Error("another tenant's member has nothing")
	}
}

// TestPullJob_TheGrantsRunNamesTheMember: the verified grant of a member names
// its run in the claim mrid, so a member that sends no mission_run_id is the
// member of that run. A request with no grant and no run is refused. When both
// name a run, the scope check has already made them equal (gibson#1235).
func TestPullJob_TheGrantsRunNamesTheMember(t *testing.T) {
	jobs := newFakeJobs()
	jobs.claim = openJob("j-1")
	s := memberService(t, jobs, liveMembers(), &recordingMinter{})
	info := &harnesspb.ContextInfo{MissionId: "bank-1", AgentName: "claude"}
	res, err := s.PullJob(withGrantMissionRun(memberCtx("acme"), "run-1"), &harnesspb.PullJobRequest{Context: info})
	if err != nil {
		t.Fatalf("PullJob with the run of the grant: %v", err)
	}
	if res.GetJob().GetId() != "j-1" {
		t.Fatalf("job = %v, want the member's queued job", res.GetJob())
	}
	_, err = s.PullJob(memberCtx("acme"), &harnesspb.PullJobRequest{Context: info})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("PullJob with no run: err = %v, want InvalidArgument", err)
	}
}

// The member acknowledges an input when its turn starts (it reports working), and a coding turn
// can run past the 30 minute life of the grant. The acknowledgement must not end the turn: the
// current turn of the job stays with its sender, so the renewal still works.
func TestReportJobState_TheAcknowledgementKeepsTheCurrentTurn(t *testing.T) {
	jobs := newFakeJobs()
	j := openJob("job-1")
	j.TurnSender, j.TurnInputID = job.Principal{Kind: job.PrincipalUser, ID: "alice"}, "in-1"
	jobs.jobs["job-1"] = j
	jobs.pending = []*job.Input{{ID: "in-1", JobID: "job-1"}}
	s := memberService(t, jobs, liveMembers(), &recordingMinter{})

	if _, err := s.ReportJobState(memberCtx("acme"), &harnesspb.ReportJobStateRequest{
		Context: memberInfo("run-1"), JobId: "job-1", State: jobpb.JobState_JOB_STATE_WORKING,
	}); err != nil {
		t.Fatalf("ReportJobState: %v", err)
	}
	if len(jobs.acked) != 1 {
		t.Fatalf("acked = %v, want the input of the turn", jobs.acked)
	}
	if got := jobs.jobs["job-1"]; got.TurnSender.ID != "alice" || got.TurnInputID != "in-1" {
		t.Errorf("the acknowledgement moved the turn to %+v / %q", got.TurnSender, got.TurnInputID)
	}
}

// A turn that cannot be recorded gets no grant: a grant for a turn that no row names would
// never renew.
func TestSubscribeInput_ATurnThatCannotBeRecordedIsNotDelivered(t *testing.T) {
	jobs := newFakeJobs()
	jobs.jobs["job-1"] = openJob("job-1")
	jobs.turnErr = errors.New("store down")
	jobs.pending = []*job.Input{{ID: "in-1", JobID: "job-1", Kind: job.InputTurn, SentAt: time.Now(),
		Sender: job.Principal{Kind: job.PrincipalUser, ID: "alice"}}}
	s := memberService(t, jobs, liveMembers(), &recordingMinter{})

	ctx, cancel := context.WithCancel(memberCtx("acme"))
	stream := &recordingInputStream{ctx: ctx, cancel: cancel}
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()
	_ = s.SubscribeInput(&harnesspb.SubscribeInputRequest{Context: memberInfo("run-1")}, stream) //nolint:contextcheck // the stream carries the context

	if n := len(stream.snapshot()); n != 0 {
		t.Fatalf("delivered %d inputs, want none", n)
	}
}

// A pulled job carries the grant of its first turn. The grant is a turn grant of the job: the
// task is the job id, the mission is the bank, the run is the run of the member, and the subject
// is the sender of the current turn that Claim recorded. For a job that never ran, that is the
// opener. The turn surface is the only surface.
func TestPullJob_CarriesTheTurnGrantOfTheFirstTurn(t *testing.T) {
	alice := job.Principal{Kind: job.PrincipalUser, ID: "alice"}
	bob := job.Principal{Kind: job.PrincipalUser, ID: "bob"}
	for name, tc := range map[string]struct {
		turn    job.Principal
		subject string
	}{
		"the turn sender that Claim recorded": {alice, "user:alice"},
		"another recorded sender":             {bob, "user:bob"},
	} {
		t.Run(name, func(t *testing.T) {
			jobs := newFakeJobs()
			claim := openJob("job-1")
			claim.OpenedBy, claim.TurnSender = alice, tc.turn
			jobs.claim = claim
			minter := &recordingMinter{}
			s := memberService(t, jobs, liveMembers(), minter)

			resp, err := s.PullJob(memberCtx("acme"), &harnesspb.PullJobRequest{Context: memberInfo("run-1")})

			if err != nil {
				t.Fatalf("PullJob: %v", err)
			}
			if resp.GetGrant() != "turn-grant-for-job-1" {
				t.Fatalf("grant = %q, want the turn grant of job-1", resp.GetGrant())
			}
			if len(minter.reqs) != 1 {
				t.Fatalf("minted %d grants, want one", len(minter.reqs))
			}
			req := minter.reqs[0]
			if req.TaskID != "job-1" || req.MissionID != "bank-1" || req.MissionRunID != "run-1" ||
				req.Subject != tc.subject || req.Tenant != "acme" || req.RecipientClass != "agent" {
				t.Errorf("mint request = %+v", req)
			}
			for _, rpc := range req.AllowedRPCs {
				if methodName(rpc) == "PullJob" {
					t.Error("a turn grant must not carry the member's own surface")
				}
			}
			if len(req.AllowedRPCs) != len(TurnGrantRPCs()) {
				t.Errorf("rpcs = %v, want the turn surface", req.AllowedRPCs)
			}
		})
	}
}

// A member that holds no job gets no grant: an empty queue, a member with no room, and a run that
// is no member's mint nothing. A daemon that cannot mint returns the job with an empty grant, so
// the claim is not lost.
func TestPullJob_NoJobMeansNoGrant(t *testing.T) {
	t.Run("an empty queue", func(t *testing.T) {
		minter := &recordingMinter{}
		s := memberService(t, newFakeJobs(), liveMembers(), minter)
		resp, err := s.PullJob(memberCtx("acme"), &harnesspb.PullJobRequest{Context: memberInfo("run-1")})
		if err != nil || resp.GetGrant() != "" || resp.GetJob() != nil || len(minter.reqs) != 0 {
			t.Fatalf("resp = %+v, err = %v, minted %d", resp, err, len(minter.reqs))
		}
	})
	t.Run("a member with no room", func(t *testing.T) {
		jobs := newFakeJobs()
		jobs.claim = openJob("job-1")
		jobs.claimErr = job.ErrNoFreeSlot
		minter := &recordingMinter{}
		s := memberService(t, jobs, liveMembers(), minter)
		resp, err := s.PullJob(memberCtx("acme"), &harnesspb.PullJobRequest{Context: memberInfo("run-1")})
		if err != nil || resp.GetGrant() != "" || len(minter.reqs) != 0 {
			t.Fatalf("resp = %+v, err = %v, minted %d", resp, err, len(minter.reqs))
		}
	})
	t.Run("a run that is no member's", func(t *testing.T) {
		jobs := newFakeJobs()
		jobs.claim = openJob("job-1")
		minter := &recordingMinter{}
		s := memberService(t, jobs, liveMembers(), minter)
		resp, err := s.PullJob(memberCtx("acme"), &harnesspb.PullJobRequest{Context: memberInfo("run-unknown")})
		if err == nil || resp != nil || len(minter.reqs) != 0 {
			t.Fatalf("resp = %+v, err = %v, minted %d, want a refusal and no grant", resp, err, len(minter.reqs))
		}
	})
}

// A daemon that cannot mint hands out no job. The check comes BEFORE the claim, so no job stays
// claimed by the member: a claimed job with no grant can hang, because the node sends no input
// before the first turn ends.
func TestPullJob_ADaemonThatCannotMintClaimsNothing(t *testing.T) {
	for name, notReady := range map[string]error{
		"no bank surface": ErrNoBankSurface,
		"no signing key":  status.Error(codes.Unavailable, "no signing key"),
	} {
		t.Run(name, func(t *testing.T) {
			jobs := newFakeJobs()
			jobs.claim = openJob("job-1")
			s := memberService(t, jobs, liveMembers(), &recordingMinter{notReady: notReady})

			resp, err := s.PullJob(memberCtx("acme"), &harnesspb.PullJobRequest{Context: memberInfo("run-1")})

			if status.Code(err) != codes.Unavailable || resp != nil {
				t.Fatalf("resp = %+v, err = %v, want Unavailable", resp, err)
			}
			if jobs.claims != 0 {
				t.Fatalf("claimed %d times, want the check before the claim", jobs.claims)
			}
			if len(jobs.released) != 0 {
				t.Errorf("released %v, want nothing to release", jobs.released)
			}
		})
	}
}

// A mint that fails after the claim sends the one job back to the queue and answers Unavailable.
// The job is released by id and by member, and it is never closed for a fault of the daemon.
func TestPullJob_AMintThatFailsAfterTheClaimReleasesTheJob(t *testing.T) {
	jobs := newFakeJobs()
	jobs.claim = openJob("job-1")
	s := memberService(t, jobs, liveMembers(), &recordingMinter{err: errors.New("signing key unavailable")})

	resp, err := s.PullJob(memberCtx("acme"), &harnesspb.PullJobRequest{Context: memberInfo("run-1")})

	if status.Code(err) != codes.Unavailable || resp != nil {
		t.Fatalf("resp = %+v, err = %v, want Unavailable and no job", resp, err)
	}
	if len(jobs.released) != 1 || jobs.released[0] != "job-1/m-1" {
		t.Fatalf("released = %v, want job-1 of member m-1", jobs.released)
	}
	if len(jobs.states) != 0 {
		t.Errorf("the job changed state %v: a daemon fault must not close it", jobs.states)
	}
}

// A job that a release re-queued in the middle of the turn of sender B keeps that turn. The
// grant of the new member is for B, and never for the opener A.
func TestPullJob_AReclaimedJobGetsTheGrantOfTheTurnThatWasRunning(t *testing.T) {
	jobs := newFakeJobs()
	claim := openJob("job-1")
	claim.OpenedBy = job.Principal{Kind: job.PrincipalUser, ID: "alice"}
	claim.TurnSender = job.Principal{Kind: job.PrincipalUser, ID: "bob"} // Claim kept the turn of B
	claim.TurnInputID = "in-9"
	jobs.claim = claim
	minter := &recordingMinter{}
	s := memberService(t, jobs, liveMembers(), minter)

	if _, err := s.PullJob(memberCtx("acme"), &harnesspb.PullJobRequest{Context: memberInfo("run-1")}); err != nil {
		t.Fatalf("PullJob: %v", err)
	}

	if len(minter.reqs) != 1 || minter.reqs[0].Subject != "user:bob" {
		t.Fatalf("mint requests = %+v, want one grant for user:bob", minter.reqs)
	}
	for _, req := range minter.reqs {
		if req.Subject == "user:alice" {
			t.Error("the grant of the opener must never go to the new member of B's turn")
		}
	}
}

// The first-turn grant binds an open to the job (the path of #1665). A member that uses the grant
// of a pulled job for open_merge_request makes a record whose task is the job id, taken from the
// verified grant and never from the body of the request.
func TestPullJob_TheFirstTurnGrantBindsAnOpenToTheJob(t *testing.T) {
	jobs := newFakeJobs()
	claim := openJob("job-1")
	claim.OpenedBy = job.Principal{Kind: job.PrincipalUser, ID: "alice"}
	jobs.claim = claim
	minter := &recordingMinter{}
	s := memberService(t, jobs, liveMembers(), minter)
	if _, err := s.PullJob(memberCtx("acme"), &harnesspb.PullJobRequest{Context: memberInfo("run-1")}); err != nil {
		t.Fatalf("PullJob: %v", err)
	}
	minted := minter.reqs[0]

	var got []ToolCallRecord
	svc := &HarnessCallbackService{logger: slog.Default()}
	WithToolCallSink(func(_ context.Context, _ string, call ToolCallRecord) { got = append(got, call) })(svc)
	info := &harnesspb.ContextInfo{MissionId: minted.MissionID, MissionRunId: minted.MissionRunID, TaskId: "job-forged"}
	verified := withTaskGrantClaims(testCtxWithTenant(), sdkcg.Claims{
		TaskID: minted.TaskID, MissionID: minted.MissionID, MissionRunID: minted.MissionRunID, Subject: minted.Subject,
	})

	svc.captureToolCall(verified, info, "tc1", "mcp:github-fixloop:open_merge_request", `{}`, `{}`, "")

	if len(got) != 1 || got[0].GrantTaskID != "job-1" || got[0].MissionRunID != "run-1" {
		t.Fatalf("record = %+v, want the task job-1 and the run of the member", got)
	}
}

// A claimed job that records no sender for its turn has no authority to act with, so it gets no
// grant. It takes the path of a failed mint: the job goes back to the queue and the pull answers
// Unavailable. The opener is not a fallback.
func TestPullJob_AJobWithNoTurnSenderGetsNoGrantAndGoesBack(t *testing.T) {
	jobs := newFakeJobs()
	claim := openJob("job-1")
	claim.TurnSender = job.Principal{}
	claim.OpenedBy = job.Principal{Kind: job.PrincipalUser, ID: "alice"}
	jobs.claim = claim
	minter := &recordingMinter{}
	s := memberService(t, jobs, liveMembers(), minter)

	resp, err := s.PullJob(memberCtx("acme"), &harnesspb.PullJobRequest{Context: memberInfo("run-1")})

	if status.Code(err) != codes.Unavailable || resp != nil {
		t.Fatalf("resp = %+v, err = %v, want Unavailable and no job", resp, err)
	}
	if len(minter.reqs) != 0 {
		t.Errorf("minted %d grants, want none: the opener must not stand in for the sender", len(minter.reqs))
	}
	if len(jobs.released) != 1 || jobs.released[0] != "job-1/m-1" {
		t.Errorf("released = %v, want job-1 of member m-1", jobs.released)
	}
}

// capturedLog is a log handler that keeps each record.
type capturedLog struct {
	mu   sync.Mutex
	logs []slog.Record
}

func (c *capturedLog) Enabled(context.Context, slog.Level) bool { return true }
func (c *capturedLog) Handle(_ context.Context, r slog.Record) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.logs = append(c.logs, r)
	return nil
}
func (c *capturedLog) WithAttrs([]slog.Attr) slog.Handler { return c }
func (c *capturedLog) WithGroup(string) slog.Handler      { return c }

// errorsFor returns the messages and the job ids of the error records.
func (c *capturedLog) errorsFor() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []string
	for _, r := range c.logs {
		if r.Level < slog.LevelError {
			continue
		}
		id := ""
		r.Attrs(func(a slog.Attr) bool {
			if a.Key == "job_id" {
				id = a.Value.String()
			}
			return true
		})
		out = append(out, r.Message+" job_id="+id)
	}
	return out
}

// flakyRelease fails the first n calls of ReleaseJob.
type flakyRelease struct {
	*fakeJobs
	failures int
	calls    int
}

func (f *flakyRelease) ReleaseJob(ctx context.Context, tenant, jobID, memberID string) error {
	f.calls++
	if f.calls <= f.failures {
		return errors.New("store down")
	}
	return f.fakeJobs.ReleaseJob(ctx, tenant, jobID, memberID)
}

// A release that fails is retried once with a short backoff on a context that does not cancel. A
// retry that works releases the job and logs no error. A second failure logs an error that names the
// job, so the stale limit or the node timeout is the visible end. The pull answers Unavailable in both.
func TestPullJob_AFailedReleaseIsRetriedOnceThenLoggedWithTheJob(t *testing.T) {
	old := releaseRetryBackoff
	releaseRetryBackoff = time.Millisecond
	t.Cleanup(func() { releaseRetryBackoff = old })

	for name, tc := range map[string]struct {
		failures   int
		wantCalls  int
		wantErrLog bool
		wantFreed  bool
	}{
		"the retry works":     {failures: 1, wantCalls: 2, wantErrLog: false, wantFreed: true},
		"both attempts fail":  {failures: 2, wantCalls: 2, wantErrLog: true, wantFreed: false},
		"the first one works": {failures: 0, wantCalls: 1, wantErrLog: false, wantFreed: true},
	} {
		t.Run(name, func(t *testing.T) {
			base := newFakeJobs()
			base.claim = openJob("job-1")
			jobs := &flakyRelease{fakeJobs: base, failures: tc.failures}
			s := memberService(t, jobs, liveMembers(), &recordingMinter{err: errors.New("signing key unavailable")})
			logs := &capturedLog{}
			s.logger = slog.New(logs)
			ctx, cancel := context.WithCancel(memberCtx("acme"))
			cancel() // the member dropped the pull: the release must still run

			_, err := s.PullJob(ctx, &harnesspb.PullJobRequest{Context: memberInfo("run-1")})

			if status.Code(err) != codes.Unavailable {
				t.Fatalf("err = %v, want Unavailable", err)
			}
			if jobs.calls != tc.wantCalls {
				t.Errorf("release calls = %d, want %d", jobs.calls, tc.wantCalls)
			}
			if freed := len(base.released) > 0; freed != tc.wantFreed {
				t.Errorf("released = %v, want freed = %v", base.released, tc.wantFreed)
			}
			errLogs := logs.errorsFor()
			if tc.wantErrLog && (len(errLogs) != 1 || !strings.Contains(errLogs[0], "job_id=job-1")) {
				t.Errorf("error logs = %v, want one that names job-1", errLogs)
			}
			if !tc.wantErrLog && len(errLogs) != 0 {
				t.Errorf("error logs = %v, want none", errLogs)
			}
		})
	}
}

// A ghost input is the input of a job that the member no longer holds, or of a closed job that is
// no wrap-up. The member can never acknowledge it, so the daemon sends nothing and mints no grant
// for it. A real input next to the ghosts is delivered with its grant.
func TestSubscribeInput_GhostInputsGetNoGrantAndAreNotSent(t *testing.T) {
	alice := job.Principal{Kind: job.PrincipalUser, ID: "alice"}
	jobs := newFakeJobs()
	jobs.jobs["live"] = openJob("live")
	released := openJob("released")
	released.MemberID = "" // a release put the job back in the queue
	jobs.jobs["released"] = released
	taken := openJob("taken")
	taken.MemberID = "m-2" // another member holds it now
	jobs.jobs["taken"] = taken
	closed := openJob("closed")
	closed.State = job.StateClosed
	jobs.jobs["closed"] = closed
	in := func(id, jobID string, kind job.InputKind) *job.Input {
		return &job.Input{ID: id, JobID: jobID, Kind: kind, Message: id, SentAt: time.Now(), Sender: alice}
	}
	for i := 0; i < 25; i++ {
		jobs.pending = append(jobs.pending, in(fmt.Sprintf("ghost-%d", i), "released", job.InputTurn))
	}
	jobs.pending = append(jobs.pending,
		in("taken-1", "taken", job.InputTurn),
		in("closed-turn", "closed", job.InputTurn),
		in("closed-wrap", "closed", job.InputWrapUp),
		in("live-1", "live", job.InputTurn),
	)
	minter := &recordingMinter{}
	s := memberService(t, jobs, liveMembers(), minter)

	ctx, cancel := context.WithCancel(memberCtx("acme"))
	stream := &recordingInputStream{ctx: ctx, cancel: cancel}
	go func() { time.Sleep(100 * time.Millisecond); cancel() }()
	if err := s.SubscribeInput(&harnesspb.SubscribeInputRequest{Context: memberInfo("run-1")}, stream); err != nil { //nolint:contextcheck // the stream carries the context
		t.Fatalf("SubscribeInput: %v", err)
	}

	var ids []string
	for _, w := range stream.snapshot() {
		ids = append(ids, w.GetId())
	}
	if len(ids) != 2 || ids[0] != "closed-wrap" || ids[1] != "live-1" {
		t.Fatalf("delivered %v, want the wrap-up of the closed job and the live input only", ids)
	}
	if len(minter.reqs) != 2 {
		t.Fatalf("minted %d grants, want one for each delivered input", len(minter.reqs))
	}
	for _, req := range minter.reqs {
		if req.TaskID == "released" || req.TaskID == "taken" {
			t.Errorf("a grant was minted for the ghost job %s", req.TaskID)
		}
	}
}
