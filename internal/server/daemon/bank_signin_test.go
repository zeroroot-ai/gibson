// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/harness"
	"github.com/zeroroot-ai/gibson/internal/platform/bank"
	"github.com/zeroroot-ai/gibson/internal/server/daemon/liveagents"
	bankpb "github.com/zeroroot-ai/sdk/api/gen/gibson/bank/v1"
)

const (
	testSignInURL  = "https://claude.com/cai/oauth/authorize?code=true&state=SECRET-STATE"
	testSignInCode = "PASTED-CODE-9f3a"
)

// signInFixture wires a bank service over a fake store with one member that
// needs a sign-in, a shared control queue, a live feed, and a buffer logger.
type signInFixture struct {
	srv     bankpb.BankServiceServer
	control *harness.MemberControl
	feed    *liveagents.Registry
	publish func([]byte)
	finish  func()
	logs    *bytes.Buffer
	bankID  string
}

func newSignInFixture(t *testing.T, allow bool) *signInFixture {
	t.Helper()
	store := newFakeBankStore()
	bankID := seededBankID(t, seedBank(t, store))
	store.members[bankID] = []*bank.Member{{ID: "m-1", BankID: bankID, AgentRunID: "run-1", State: bank.MemberNeedsSignIn}}
	control := harness.NewMemberControl()
	feed := liveagents.NewRegistry()
	publish, finish := feed.RegisterInstance("acme", liveagents.Instance{RunID: "run-1", AgentName: "claude", StartedAt: time.Now()})
	logs := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	srv, err := NewBankServer(BankServerConfig{Store: store, Authorizer: &fakeAuthorizer{deny: !allow}, Control: control, Feed: feed, Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	return &signInFixture{srv: srv, control: control, feed: feed, publish: publish, finish: finish, logs: logs, bankID: bankID}
}

func seedBank(t *testing.T, store *fakeBankStore) *fakeBankStore {
	t.Helper()
	if _, err := store.Create(context.Background(), "acme", bank.CreateInput{
		Name: "nightly", OwnerKind: bank.OwnerUser, OwnerID: "alice",
		LoginShape: bank.LoginShapeSubscription,
	}); err != nil {
		t.Fatal(err)
	}
	return store
}

// signInStream records what the relay sent and ends after n responses.
type signInStream struct {
	grpc.ServerStream
	ctx    context.Context
	got    []*bankpb.StreamSignInResponse
	cancel context.CancelFunc
	stopAt int
}

func (s *signInStream) Context() context.Context { return s.ctx }
func (s *signInStream) Send(r *bankpb.StreamSignInResponse) error {
	s.got = append(s.got, r)
	if s.stopAt > 0 && len(s.got) >= s.stopAt {
		s.cancel()
	}
	return nil
}

// TestStartSignIn_QueuesTheStartWordForTheMember asserts the owner's start
// lands on the member's control queue as a turn, and nothing else.
func TestStartSignIn_QueuesTheStartWordForTheMember(t *testing.T) {
	f := newSignInFixture(t, true)
	defer f.finish()
	resp, err := f.srv.StartSignIn(bankCtx(t, "acme", "alice"), &bankpb.StartSignInRequest{BankId: f.bankID, MemberId: "m-1"})
	if err != nil || resp.GetMember().GetId() != "m-1" {
		t.Fatalf("StartSignIn = %v, %v", resp, err)
	}
	inputs := f.control.Drain("acme", "m-1")
	if len(inputs) != 1 || inputs[0].GetJobId() != harness.SignInJobID || inputs[0].GetMessage() != harness.SignInStart || inputs[0].GetGrant() != "" {
		t.Fatalf("control inputs = %+v", inputs)
	}
}

// TestSubmitSignInCode_QueuesTheCodeInMemoryOnly asserts the code reaches the
// member's queue as an answer with no grant, and that an empty code is
// refused.
func TestSubmitSignInCode_QueuesTheCodeInMemoryOnly(t *testing.T) {
	f := newSignInFixture(t, true)
	defer f.finish()
	ctx := bankCtx(t, "acme", "alice")
	if _, err := f.srv.SubmitSignInCode(ctx, &bankpb.SubmitSignInCodeRequest{BankId: f.bankID, MemberId: "m-1", Code: " " + testSignInCode + " "}); err != nil {
		t.Fatalf("SubmitSignInCode: %v", err)
	}
	inputs := f.control.Drain("acme", "m-1")
	if len(inputs) != 1 || inputs[0].GetMessage() != testSignInCode || inputs[0].GetKind() != 2 /* ANSWER */ {
		t.Fatalf("control inputs = %+v", inputs)
	}
	if _, err := f.srv.SubmitSignInCode(ctx, &bankpb.SubmitSignInCodeRequest{BankId: f.bankID, MemberId: "m-1", Code: "  "}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("an empty code: %v", err)
	}
}

// TestStreamSignIn_RelaysTheFlowAndEndsWhenItDoes asserts the URL and the
// prompt, a refused code, and the end each reach the console, that lines that
// are not the flow's are skipped, and that an earlier finished flow in the
// backlog is not replayed.
func TestStreamSignIn_RelaysTheFlowAndEndsWhenItDoes(t *testing.T) {
	f := newSignInFixture(t, true)
	defer f.finish()
	f.publish([]byte(`{"type":"sign_in","url":"https://old","code_prompt":"Paste > "}` + "\n"))
	f.publish([]byte(`{"type":"sign_in_done"}` + "\n"))
	f.publish([]byte(`{"type":"assistant","text":"hello"}` + "\n"))
	f.publish([]byte(`{"type":"sign_in","url":"` + testSignInURL + `","code_prompt":"Paste code here if prompted > "}` + "\n"))
	f.publish([]byte("not json\n"))
	f.publish([]byte(`{"type":"sign_in_invalid","message":"Invalid code."}` + "\n"))
	f.publish([]byte(`{"type":"sign_in_done"}` + "\n"))

	ctx, cancel := context.WithCancel(bankCtx(t, "acme", "alice"))
	defer cancel()
	stream := &signInStream{ctx: ctx, cancel: cancel}
	if err := f.srv.StreamSignIn(&bankpb.StreamSignInRequest{BankId: f.bankID, MemberId: "m-1"}, stream); err != nil {
		t.Fatalf("StreamSignIn: %v", err)
	}
	if len(stream.got) != 3 {
		t.Fatalf("relayed %d responses, want the URL, the refusal and the end: %+v", len(stream.got), stream.got)
	}
	if stream.got[0].GetUrl() != testSignInURL || !strings.HasPrefix(stream.got[0].GetCodePrompt(), "Paste") {
		t.Errorf("first = %+v", stream.got[0])
	}
	if stream.got[1].GetError() != "Invalid code." || stream.got[1].GetDone() {
		t.Errorf("second = %+v", stream.got[1])
	}
	if !stream.got[2].GetDone() {
		t.Errorf("third = %+v", stream.got[2])
	}
}

// TestStreamSignIn_FollowsALiveFlow asserts lines published after the
// subscription reach the console, and a failure ends the stream with the
// error.
func TestStreamSignIn_FollowsALiveFlow(t *testing.T) {
	f := newSignInFixture(t, true)
	defer f.finish()
	ctx, cancel := context.WithCancel(bankCtx(t, "acme", "alice"))
	defer cancel()
	stream := &signInStream{ctx: ctx, cancel: cancel}
	done := make(chan error, 1)
	go func() {
		done <- f.srv.StreamSignIn(&bankpb.StreamSignInRequest{BankId: f.bankID, MemberId: "m-1"}, stream)
	}()
	time.Sleep(20 * time.Millisecond)
	f.publish([]byte(`{"type":"sign_in","url":"` + testSignInURL + `"}` + "\n"))
	f.publish([]byte(`{"type":"sign_in_failed","error":"the CLI exited"}` + "\n"))
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the stream must end with the flow")
	}
	if len(stream.got) != 2 || !stream.got[1].GetDone() || stream.got[1].GetError() != "the CLI exited" {
		t.Fatalf("got = %+v", stream.got)
	}
}

// TestSignIn_OnlyTheOwnerAndOnlyItsMember asserts the three RPCs answer
// not-found to anyone but the bank's owner, to a member of another bank, and
// to a member that is not running, and refuse empty ids.
func TestSignIn_OnlyTheOwnerAndOnlyItsMember(t *testing.T) {
	f := newSignInFixture(t, false)
	defer f.finish()
	ctx := bankCtx(t, "acme", "mallory")
	if _, err := f.srv.StartSignIn(ctx, &bankpb.StartSignInRequest{BankId: f.bankID, MemberId: "m-1"}); status.Code(err) != codes.NotFound {
		t.Errorf("StartSignIn without ownership: %v", err)
	}
	if _, err := f.srv.SubmitSignInCode(ctx, &bankpb.SubmitSignInCodeRequest{BankId: f.bankID, MemberId: "m-1", Code: "x"}); status.Code(err) != codes.NotFound {
		t.Errorf("SubmitSignInCode without ownership: %v", err)
	}
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if err := f.srv.StreamSignIn(&bankpb.StreamSignInRequest{BankId: f.bankID, MemberId: "m-1"}, &signInStream{ctx: sctx, cancel: cancel}); status.Code(err) != codes.NotFound {
		t.Errorf("StreamSignIn without ownership: %v", err)
	}
	if f.control.Pending("acme", "m-1") != 0 {
		t.Error("a refused call must queue nothing")
	}

	owner := newSignInFixture(t, true)
	defer owner.finish()
	octx := bankCtx(t, "acme", "alice")
	if _, err := owner.srv.StartSignIn(octx, &bankpb.StartSignInRequest{BankId: "bank-other", MemberId: "m-1"}); status.Code(err) != codes.NotFound {
		t.Errorf("a member of another bank: %v", err)
	}
	if _, err := owner.srv.StartSignIn(octx, &bankpb.StartSignInRequest{BankId: owner.bankID, MemberId: "m-9"}); status.Code(err) != codes.NotFound {
		t.Errorf("an unknown member: %v", err)
	}
	if _, err := owner.srv.StartSignIn(octx, &bankpb.StartSignInRequest{BankId: owner.bankID}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("no member id: %v", err)
	}
	owner.finish()
	sctx2, cancel2 := context.WithCancel(octx)
	defer cancel2()
	if err := owner.srv.StreamSignIn(&bankpb.StreamSignInRequest{BankId: owner.bankID, MemberId: "m-1"}, &signInStream{ctx: sctx2, cancel: cancel2}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("a member that is not running: %v", err)
	}
}

// TestSignIn_NoURLOrCodeReachesTheLogs is the log-scan test the issue asks
// for: a whole relayed flow, start to code to done, leaves neither the URL
// nor the code in anything the daemon logged.
func TestSignIn_NoURLOrCodeReachesTheLogs(t *testing.T) {
	f := newSignInFixture(t, true)
	defer f.finish()
	ctx := bankCtx(t, "acme", "alice")
	if _, err := f.srv.StartSignIn(ctx, &bankpb.StartSignInRequest{BankId: f.bankID, MemberId: "m-1"}); err != nil {
		t.Fatal(err)
	}
	f.publish([]byte(`{"type":"sign_in","url":"` + testSignInURL + `","code_prompt":"Paste > "}` + "\n"))
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stream := &signInStream{ctx: sctx, cancel: cancel, stopAt: 1}
	if err := f.srv.StreamSignIn(&bankpb.StreamSignInRequest{BankId: f.bankID, MemberId: "m-1"}, stream); err != nil {
		t.Fatal(err)
	}
	if _, err := f.srv.SubmitSignInCode(ctx, &bankpb.SubmitSignInCodeRequest{BankId: f.bankID, MemberId: "m-1", Code: testSignInCode}); err != nil {
		t.Fatal(err)
	}
	f.control.Drain("acme", "m-1")

	logged := f.logs.String()
	for _, secret := range []string{testSignInURL, "SECRET-STATE", testSignInCode} {
		if strings.Contains(logged, secret) {
			t.Errorf("the logs carry %q:\n%s", secret, logged)
		}
	}
	if !strings.Contains(logged, "sign-in started") || !strings.Contains(logged, "sign-in code submitted") {
		t.Errorf("the state transitions must be logged:\n%s", logged)
	}
}
