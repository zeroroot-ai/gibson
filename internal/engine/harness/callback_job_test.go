// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"errors"
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
	commonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/common/v1"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	jobpb "github.com/zeroroot-ai/sdk/api/gen/gibson/job/v1"
	"github.com/zeroroot-ai/sdk/auth"
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
	reqs []capabilitygrant.MintRequest
	err  error
}

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
		WithJobSurface(jobs), WithMemberLookup(members), WithTurnGrantMinter(minter))
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
	s := NewHarnessCallbackService(nil)
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
	s := NewHarnessCallbackService(nil, WithJobSurface(jobs), WithMemberLookup(liveMembers()))

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
	if got := turnGrantSubject(job.Principal{Kind: job.PrincipalComponent, ID: "agent_principal:x"}); got != "agent_principal:x" {
		t.Errorf("a component is already a typed principal, got %q", got)
	}
	if got := turnGrantSubject(job.Principal{Kind: job.PrincipalUser, ID: "alice"}); got != "user:alice" {
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
		got := senderToWire(job.Principal{Kind: domain, ID: "p-1"})
		if got.GetKind() != wire || got.GetId() != "p-1" {
			t.Errorf("senderToWire(%q) = %v/%q, want %v/p-1", domain, got.GetKind(), got.GetId(), wire)
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
		WithTurnGrantMinter(&recordingMinter{}), WithMemberEventSink(events))
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
		WithTurnGrantMinter(&recordingMinter{}), WithMemberControl(control))

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
