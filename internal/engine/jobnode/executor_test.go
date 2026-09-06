// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package jobnode

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/platform/job"
	jobpb "github.com/zeroroot-ai/sdk/api/gen/gibson/job/v1"
)

// scriptedJobs is a job store whose members answer on cue: each Send or Open
// is followed by the states the test scripted.
type scriptedJobs struct {
	mu       sync.Mutex
	opened   []job.OpenInput
	sent     []job.SendInput
	closed   []job.CloseInput
	events   []*job.Event
	state    job.State
	openErr  error
	closeErr error
	sendErr  error
	eventErr error
	// onTurn is what the member does with each turn: the events it appends.
	onTurn func(turn int) []*job.Event
	turns  int
	// closedElsewhere makes the job read as closed by someone else.
	closedElsewhere bool
}

func (s *scriptedJobs) Open(_ context.Context, _ string, in job.OpenInput) (*job.Job, error) {
	if s.openErr != nil {
		return nil, s.openErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.opened = append(s.opened, in)
	s.state = job.StateOpen
	if s.closedElsewhere {
		s.state = job.StateClosed
	}
	s.turns++
	s.events = append(s.events, s.onTurn(s.turns)...)
	return &job.Job{ID: "job-1", BankID: in.BankID, State: job.StateOpen, Spec: in.Spec}, nil
}

func (s *scriptedJobs) Send(_ context.Context, _ string, in job.SendInput) (*job.Input, error) {
	if s.sendErr != nil {
		return nil, s.sendErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sent = append(s.sent, in)
	s.turns++
	s.events = append(s.events, s.onTurn(s.turns)...)
	return &job.Input{ID: "in", JobID: in.JobID}, nil
}

func (s *scriptedJobs) Close(_ context.Context, _ string, in job.CloseInput) (*job.Job, error) {
	if s.closeErr != nil {
		return nil, s.closeErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = append(s.closed, in)
	s.state = job.StateClosed
	return &job.Job{ID: in.JobID, BankID: "bank-1", MemberID: "m-1", State: job.StateClosed, Verdict: in.Verdict, Score: in.Score,
		Deliverables: []*jobpb.Deliverable{{Kind: jobpb.DeliverableKind_DELIVERABLE_KIND_PUSH_BRANCH, Ref: "fix"}}}, nil
}

func (s *scriptedJobs) Get(_ context.Context, _, id string) (*job.Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return &job.Job{ID: id, BankID: "bank-1", MemberID: "m-1", State: s.state, Verdict: job.VerdictAccomplished, Score: 0.7,
		Deliverables: []*jobpb.Deliverable{{Kind: jobpb.DeliverableKind_DELIVERABLE_KIND_PUSH_BRANCH, Ref: "fix"}}}, nil
}

func (s *scriptedJobs) Events(_ context.Context, _, _ string, since int64, _ int32) ([]*job.Event, error) {
	if s.eventErr != nil {
		return nil, s.eventErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*job.Event
	for _, ev := range s.events {
		if ev.Seq > since {
			out = append(out, ev)
		}
	}
	return out, nil
}

var seq int64

func waiting() []*job.Event {
	seq++
	return []*job.Event{{Seq: seq, Kind: job.EventState, State: job.StateWaiting}}
}

func closedByAPerson() []*job.Event {
	seq++
	return []*job.Event{{Seq: seq, Kind: job.EventClosed, Verdict: job.VerdictAccomplished}}
}

// scriptedVerifier answers one report per pass.
type scriptedVerifier struct {
	reports  []Report
	err      error
	payloads []VerifyPayload
}

func (v *scriptedVerifier) Verify(_ context.Context, _ string, p VerifyPayload) (Report, error) {
	if v.err != nil {
		return Report{}, v.err
	}
	v.payloads = append(v.payloads, p)
	i := len(v.payloads) - 1
	if i >= len(v.reports) {
		i = len(v.reports) - 1
	}
	return v.reports[i], nil
}

func spec(maxPasses int32, verifier string) *jobpb.JobSpec {
	return &jobpb.JobSpec{
		Goal: "fix the build", Inputs: []string{"the failing CI log"},
		Acceptance: &jobpb.Acceptance{VerifierComponent: verifier, PassingScore: 0.8, MaxPasses: maxPasses},
	}
}

func input(ops JobOps, v Verifier, s *jobpb.JobSpec) Input {
	return Input{
		TenantID: "acme", MissionRunID: "run-1", NodeID: "fix", BankID: "bank-1", Spec: s,
		Opener: job.Principal{Kind: job.PrincipalService, ID: "mission:run-1"},
		Ops:    ops, Verifier: v, PollInterval: time.Millisecond,
	}
}

// TestRun_VerifyFailsOnceThenPasses is the acceptance case: two passes, the
// first report sent back as the next turn, one close as accomplished with
// the verifier's score.
func TestRun_VerifyFailsOnceThenPasses(t *testing.T) {
	ops := &scriptedJobs{onTurn: func(int) []*job.Event { return waiting() }}
	v := &scriptedVerifier{reports: []Report{{Pass: false, Score: 0.4, Report: "tests still red"}, {Pass: true, Score: 0.9, Report: "green"}}}

	out, err := Run(context.Background(), input(ops, v, spec(3, "agent/reviewer")))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if out.Passes != 2 || out.Result.Verdict != job.VerdictAccomplished || out.Result.Score != 0.9 {
		t.Fatalf("outcome = %+v", out)
	}
	if len(ops.sent) != 1 || ops.sent[0].Message != "tests still red" || ops.sent[0].Kind != job.InputTurn || ops.sent[0].Sender.ID != "mission:run-1" {
		t.Fatalf("sent = %+v, want the first report as the next turn", ops.sent)
	}
	if len(ops.closed) != 1 || ops.closed[0].Verdict != job.VerdictAccomplished || ops.closed[0].Score != 0.9 {
		t.Fatalf("closed = %+v", ops.closed)
	}
	if v.payloads[0].Pass != 1 || v.payloads[1].Pass != 2 || v.payloads[0].Goal != "fix the build" || len(v.payloads[0].Deliverables) != 1 {
		t.Errorf("payloads = %+v", v.payloads)
	}
	ctx := ops.opened[0].Spec.GetContext()
	if ctx["mission_run_id"].GetStringValue() != "run-1" || ctx["node_id"].GetStringValue() != "fix" {
		t.Errorf("the spec must name the run and the node: %v", ctx)
	}
	if len(out.Result.Deliverables) != 1 || out.Result.Deliverables[0].Kind != "push_branch" {
		t.Errorf("result deliverables = %+v", out.Result.Deliverables)
	}
}

// TestRun_FailsAfterMaxPasses: max_passes bounds the loop, and the close is
// failed with the last score.
func TestRun_FailsAfterMaxPasses(t *testing.T) {
	ops := &scriptedJobs{onTurn: func(int) []*job.Event { return waiting() }}
	v := &scriptedVerifier{reports: []Report{{Pass: false, Score: 0.3, Report: "no"}}}

	out, err := Run(context.Background(), input(ops, v, spec(2, "tool/verify")))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if out.Passes != 2 || out.Result.Verdict != job.VerdictFailed || len(ops.sent) != 1 {
		t.Fatalf("outcome = %+v, sent = %d", out, len(ops.sent))
	}
	// A pass below the passing score is not accepted even when the verifier says pass.
	ops = &scriptedJobs{onTurn: func(int) []*job.Event { return waiting() }}
	v = &scriptedVerifier{reports: []Report{{Pass: true, Score: 0.5, Report: "meh"}}}
	out, err = Run(context.Background(), input(ops, v, spec(1, "tool/verify")))
	if err != nil || out.Result.Verdict != job.VerdictFailed {
		t.Fatalf("a score under the bar must fail: %+v, %v", out, err)
	}
}

// TestRun_NoVerifierAcceptsTheFirstTurn: nobody named to judge means the work
// stands as delivered, and max_passes zero means one pass.
func TestRun_NoVerifierAcceptsTheFirstTurn(t *testing.T) {
	ops := &scriptedJobs{onTurn: func(int) []*job.Event { return waiting() }}
	v := &scriptedVerifier{}
	out, err := Run(context.Background(), input(ops, v, spec(0, "")))
	if err != nil || out.Passes != 1 || out.Result.Verdict != job.VerdictAccomplished || out.Result.Score != 1 {
		t.Fatalf("outcome = %+v, %v", out, err)
	}
	if len(v.payloads) != 0 {
		t.Error("no verifier must be asked")
	}
}

// TestRun_AVerifierFailureAbandonsTheJob: a verifier that cannot answer
// leaves no job open on the bank.
func TestRun_AVerifierFailureAbandonsTheJob(t *testing.T) {
	ops := &scriptedJobs{onTurn: func(int) []*job.Event { return waiting() }}
	v := &scriptedVerifier{err: errors.New("the reviewer is down")}
	_, err := Run(context.Background(), input(ops, v, spec(2, "agent/reviewer")))
	if err == nil || !strings.Contains(err.Error(), "the reviewer is down") {
		t.Fatalf("err = %v", err)
	}
	if len(ops.closed) != 1 || ops.closed[0].Verdict != job.VerdictAbandoned {
		t.Fatalf("closed = %+v, want abandoned", ops.closed)
	}
}

// TestRun_TheNodesBoundAbandonsTheJob: the node timeout bounds the whole loop.
func TestRun_TheNodesBoundAbandonsTheJob(t *testing.T) {
	ops := &scriptedJobs{onTurn: func(int) []*job.Event { return nil }} // the member never answers
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := Run(ctx, input(ops, &scriptedVerifier{}, spec(1, "")))
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want the deadline", err)
	}
	if len(ops.closed) != 1 || ops.closed[0].Verdict != job.VerdictAbandoned {
		t.Fatalf("closed = %+v, want abandoned", ops.closed)
	}
	// A close that also fails is reported with the cause.
	ops = &scriptedJobs{onTurn: func(int) []*job.Event { return nil }, closeErr: errors.New("postgres is down")}
	ctx2, cancel2 := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel2()
	if _, err := Run(ctx2, input(ops, &scriptedVerifier{}, spec(1, ""))); err == nil || !strings.Contains(err.Error(), "could not be abandoned") {
		t.Fatalf("err = %v", err)
	}
}

// TestRun_AJobClosedElsewhereIsReportedNotOverwritten: a person who closes
// the job first wins, and the node reports that close.
func TestRun_AJobClosedElsewhereIsReportedNotOverwritten(t *testing.T) {
	ops := &scriptedJobs{onTurn: func(int) []*job.Event { return closedByAPerson() }, closedElsewhere: true}
	out, err := Run(context.Background(), input(ops, &scriptedVerifier{}, spec(1, "")))
	if !errors.Is(err, ErrClosedElsewhere) {
		t.Fatalf("err = %v, want ErrClosedElsewhere", err)
	}
	if len(ops.closed) != 0 {
		t.Fatal("the node must not close a job someone else closed")
	}
	if out.Result.Verdict != job.VerdictAccomplished {
		t.Errorf("the reported result is their close: %+v", out.Result)
	}
}

// TestRun_StoreFailuresAreReported: an open, a send, an events read and a
// close that fail each reach the caller.
func TestRun_StoreFailuresAreReported(t *testing.T) {
	boom := errors.New("postgres is down")
	if _, err := Run(context.Background(), input(&scriptedJobs{openErr: boom, onTurn: func(int) []*job.Event { return nil }}, &scriptedVerifier{}, spec(1, ""))); !errors.Is(err, boom) {
		t.Errorf("open: %v", err)
	}
	ops := &scriptedJobs{onTurn: func(int) []*job.Event { return waiting() }, sendErr: boom}
	if _, err := Run(context.Background(), input(ops, &scriptedVerifier{reports: []Report{{Pass: false}}}, spec(2, "tool/v"))); !errors.Is(err, boom) {
		t.Errorf("send: %v", err)
	}
	ops = &scriptedJobs{onTurn: func(int) []*job.Event { return waiting() }, eventErr: boom}
	if _, err := Run(context.Background(), input(ops, &scriptedVerifier{}, spec(1, ""))); !errors.Is(err, boom) {
		t.Errorf("events: %v", err)
	}
	ops = &scriptedJobs{onTurn: func(int) []*job.Event { return waiting() }, closeErr: boom}
	if _, err := Run(context.Background(), input(ops, &scriptedVerifier{}, spec(1, ""))); !errors.Is(err, boom) {
		t.Errorf("close: %v", err)
	}
}

// TestRun_RefusesAnIncompleteInput names each missing part.
func TestRun_RefusesAnIncompleteInput(t *testing.T) {
	ok := input(&scriptedJobs{}, &scriptedVerifier{}, spec(1, ""))
	for name, mutate := range map[string]func(*Input){
		"no ops":      func(in *Input) { in.Ops = nil },
		"no verifier": func(in *Input) { in.Verifier = nil },
		"no bank":     func(in *Input) { in.BankID = "" },
		"no goal":     func(in *Input) { in.Spec = &jobpb.JobSpec{} },
		"no opener":   func(in *Input) { in.Opener = job.Principal{} },
	} {
		in := ok
		mutate(&in)
		if _, err := Run(context.Background(), in); err == nil {
			t.Errorf("%s: must be refused", name)
		}
	}
}
