// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/bank"
	agentconsolev1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/agentconsole/v1"
	"github.com/zeroroot-ai/gibson/internal/server/daemon/liveagents"
	bankpb "github.com/zeroroot-ai/sdk/api/gen/gibson/bank/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

func tenantCtx(t *testing.T, tenant string) context.Context {
	t.Helper()
	return auth.WithTenant(context.Background(), auth.MustNewTenantID(tenant))
}

// fakeEventStream is a grpc.ServerStreamingServer[AgentEvent] that records the
// events the handler sends and lets the test control the stream context.
type fakeEventStream struct {
	grpc.ServerStream
	ctx     context.Context
	mu      sync.Mutex
	sent    []*agentconsolev1.AgentEvent
	sendErr error
}

func (f *fakeEventStream) Context() context.Context { return f.ctx }

func (f *fakeEventStream) Send(e *agentconsolev1.AgentEvent) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sendErr != nil {
		return f.sendErr
	}
	f.sent = append(f.sent, e)
	return nil
}

func (f *fakeEventStream) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.sent)
}

func (f *fakeEventStream) first() *agentconsolev1.AgentEvent {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.sent) == 0 {
		return nil
	}
	return f.sent[0]
}

func TestNewAgentConsoleServer_NilRegistryPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected a panic on a nil registry")
		}
	}()
	_ = NewAgentConsoleServer(nil, nil)
}

func TestStreamAgentEvents_SendErrorPropagates(t *testing.T) {
	reg := liveagents.NewRegistry()
	publish, fin := reg.RegisterInstance("acme", liveagents.Instance{RunID: "run-1", AgentName: "scanner", SandboxID: "sbx-1", StartedAt: time.Now()})
	defer fin()
	srv := NewAgentConsoleServer(reg, nil)

	stream := &fakeEventStream{ctx: tenantCtx(t, "acme"), sendErr: errBoom}
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.StreamAgentEvents(&agentconsolev1.StreamAgentEventsRequest{RunId: "run-1"}, stream)
	}()

	// Publish until the handler is subscribed; the send then fails and the
	// handler returns that error.
	waitForCond(t, func() bool {
		publish([]byte("x"))
		select {
		case err := <-errCh:
			if !errors.Is(err, errBoom) {
				t.Fatalf("stream returned %v; want the send error", err)
			}
			return true
		default:
			return false
		}
	})
}

var errBoom = errors.New("send failed")

func TestListRunningAgents_ScopedToTenant(t *testing.T) {
	reg := liveagents.NewRegistry()
	base := time.Unix(2000, 0)
	_, f1 := reg.RegisterInstance("acme", liveagents.Instance{RunID: "run-1", AgentName: "scanner", SandboxID: "sbx-1", StartedAt: base})
	_, f2 := reg.RegisterInstance("acme", liveagents.Instance{RunID: "run-2", AgentName: "fuzzer", SandboxID: "sbx-2", StartedAt: base.Add(time.Second)})
	_, f3 := reg.RegisterInstance("globex", liveagents.Instance{RunID: "run-x", AgentName: "probe", SandboxID: "sbx-x", StartedAt: base})
	defer f1()
	defer f2()
	defer f3()

	srv := NewAgentConsoleServer(reg, nil)
	resp, err := srv.ListRunningAgents(tenantCtx(t, "acme"), &agentconsolev1.ListRunningAgentsRequest{})
	if err != nil {
		t.Fatalf("ListRunningAgents: %v", err)
	}
	if len(resp.GetAgents()) != 2 {
		t.Fatalf("acme saw %d agents; want 2 (never globex's)", len(resp.GetAgents()))
	}
	got := map[string]string{}
	for _, a := range resp.GetAgents() {
		got[a.GetRunId()] = a.GetAgentName()
	}
	if got["run-1"] != "scanner" || got["run-2"] != "fuzzer" {
		t.Fatalf("agents = %+v; want run-1/scanner + run-2/fuzzer", got)
	}
	if _, leaked := got["run-x"]; leaked {
		t.Fatal("acme's enumeration leaked globex's instance")
	}
	// First entry carries full metadata.
	if resp.GetAgents()[0].GetStartedUnixNanos() != base.UnixNano() {
		t.Errorf("started_unix_nanos = %d; want %d", resp.GetAgents()[0].GetStartedUnixNanos(), base.UnixNano())
	}
}

func TestListRunningAgents_NoTenantDenied(t *testing.T) {
	srv := NewAgentConsoleServer(liveagents.NewRegistry(), nil)
	_, err := srv.ListRunningAgents(context.Background(), &agentconsolev1.ListRunningAgentsRequest{})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("no-tenant List code = %v; want PermissionDenied", status.Code(err))
	}
}

func TestStreamAgentEvents_ForeignRunIDNotFound(t *testing.T) {
	reg := liveagents.NewRegistry()
	_, fin := reg.RegisterInstance("acme", liveagents.Instance{RunID: "run-1", AgentName: "scanner", SandboxID: "sbx-1", StartedAt: time.Now()})
	defer fin()
	srv := NewAgentConsoleServer(reg, nil)

	// globex asks for acme's run id: NOT_FOUND, never data, never a leak.
	stream := &fakeEventStream{ctx: tenantCtx(t, "globex")}
	err := srv.StreamAgentEvents(&agentconsolev1.StreamAgentEventsRequest{RunId: "run-1"}, stream)
	if status.Code(err) != codes.NotFound {
		t.Fatalf("foreign StreamAgentEvents code = %v; want NotFound", status.Code(err))
	}
	// An unknown run id for the owner is the same NotFound.
	stream2 := &fakeEventStream{ctx: tenantCtx(t, "acme")}
	err = srv.StreamAgentEvents(&agentconsolev1.StreamAgentEventsRequest{RunId: "nope"}, stream2)
	if status.Code(err) != codes.NotFound {
		t.Fatalf("unknown-run StreamAgentEvents code = %v; want NotFound", status.Code(err))
	}
}

func TestStreamAgentEvents_EmptyRunIDInvalid(t *testing.T) {
	srv := NewAgentConsoleServer(liveagents.NewRegistry(), nil)
	stream := &fakeEventStream{ctx: tenantCtx(t, "acme")}
	err := srv.StreamAgentEvents(&agentconsolev1.StreamAgentEventsRequest{}, stream)
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("empty run id code = %v; want InvalidArgument", status.Code(err))
	}
}

func TestStreamAgentEvents_DeliversThenClosesOnTerminal(t *testing.T) {
	reg := liveagents.NewRegistry()
	publish, finish := reg.RegisterInstance("acme", liveagents.Instance{RunID: "run-1", AgentName: "scanner", SandboxID: "sbx-1", StartedAt: time.Now()})
	srv := NewAgentConsoleServer(reg, nil)

	stream := &fakeEventStream{ctx: tenantCtx(t, "acme")}
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.StreamAgentEvents(&agentconsolev1.StreamAgentEventsRequest{RunId: "run-1"}, stream)
	}()

	// Publish until delivered: the handler subscribes asynchronously, so the
	// first chunks before it subscribes are dropped (no subscriber yet), exactly
	// as a live run behaves. Retrying establishes the subscription then delivers.
	waitForCond(t, func() bool {
		publish([]byte(`{"event":"start"}`))
		return stream.count() >= 1
	})
	if got := stream.first(); got == nil || string(got.GetData()) != `{"event":"start"}` {
		t.Fatalf("relayed event = %v; want the start event", got)
	}
	if stream.first().GetUnixNanos() == 0 {
		t.Error("relayed event has no relay timestamp")
	}

	// The run reaches terminal state; the stream must end with no error.
	finish()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("stream ended with %v; want nil on terminal state", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("stream did not end after terminal state")
	}
}

func TestStreamAgentEvents_EndsOnClientCancel(t *testing.T) {
	reg := liveagents.NewRegistry()
	_, fin := reg.RegisterInstance("acme", liveagents.Instance{RunID: "run-1", AgentName: "scanner", SandboxID: "sbx-1", StartedAt: time.Now()})
	defer fin()
	srv := NewAgentConsoleServer(reg, nil)

	ctx, cancel := context.WithCancel(tenantCtx(t, "acme"))
	stream := &fakeEventStream{ctx: ctx}
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.StreamAgentEvents(&agentconsolev1.StreamAgentEventsRequest{RunId: "run-1"}, stream)
	}()

	cancel() // client goes away
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("stream ended with %v; want nil on client cancel", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("stream did not end after client cancel")
	}
}

func TestAgentConsole_TwoStreamsAreIndependent(t *testing.T) {
	reg := liveagents.NewRegistry()
	pub1, fin1 := reg.RegisterInstance("acme", liveagents.Instance{RunID: "run-1", AgentName: "a", SandboxID: "sbx-1", StartedAt: time.Now()})
	pub2, fin2 := reg.RegisterInstance("acme", liveagents.Instance{RunID: "run-2", AgentName: "b", SandboxID: "sbx-2", StartedAt: time.Now()})
	defer fin2()
	srv := NewAgentConsoleServer(reg, nil)

	s1 := &fakeEventStream{ctx: tenantCtx(t, "acme")}
	s2 := &fakeEventStream{ctx: tenantCtx(t, "acme")}
	e1 := make(chan error, 1)
	e2 := make(chan error, 1)
	go func() { e1 <- srv.StreamAgentEvents(&agentconsolev1.StreamAgentEventsRequest{RunId: "run-1"}, s1) }()
	go func() { e2 <- srv.StreamAgentEvents(&agentconsolev1.StreamAgentEventsRequest{RunId: "run-2"}, s2) }()

	// Publish until each handler has subscribed and received (see the race note
	// above).
	waitForCond(t, func() bool { pub1([]byte("one")); return s1.count() >= 1 })
	waitForCond(t, func() bool { pub2([]byte("two")); return s2.count() >= 1 })
	got2 := s2.count()

	// Close stream 1; stream 2 keeps delivering.
	fin1()
	select {
	case err := <-e1:
		if err != nil {
			t.Fatalf("stream 1 ended with %v; want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("stream 1 did not end")
	}
	waitForCond(t, func() bool { pub2([]byte("three")); return s2.count() > got2 })
	_ = e2
}

// waitFor polls cond until true or a short deadline elapses.
func waitForCond(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("condition not met within deadline")
}

func TestStreamAgentEvents_ReplaysBacklogSinceSeqThenLive(t *testing.T) {
	reg := liveagents.NewRegistry()
	publish, finish := reg.RegisterInstance("tenant-a", liveagents.Instance{RunID: "run-1", AgentName: "scanner", SandboxID: "sbx", StartedAt: time.Now()})
	srv := NewAgentConsoleServer(reg, nil)
	publish([]byte("one"))
	publish([]byte("two"))
	publish([]byte("three"))

	ctx, cancel := context.WithCancel(tenantCtx(t, "tenant-a"))
	defer cancel()
	stream := &fakeEventStream{ctx: ctx}
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.StreamAgentEvents(&agentconsolev1.StreamAgentEventsRequest{RunId: "run-1", SinceSeq: 1}, stream)
	}()
	waitForCond(t, func() bool { return stream.count() == 2 })
	publish([]byte("four"))
	waitForCond(t, func() bool { return stream.count() == 3 })
	finish()
	if err := <-errCh; err != nil {
		t.Fatalf("StreamAgentEvents: %v", err)
	}
	stream.mu.Lock()
	defer stream.mu.Unlock()
	want := []struct {
		seq  uint64
		data string
	}{{2, "two"}, {3, "three"}, {4, "four"}}
	for i, w := range want {
		got := stream.sent[i]
		if got.GetSeq() != w.seq || string(got.GetData()) != w.data || got.GetUnixNanos() == 0 {
			t.Fatalf("sent[%d] = seq %d %q nanos %d; want seq %d %q", i, got.GetSeq(), got.GetData(), got.GetUnixNanos(), w.seq, w.data)
		}
	}
}

func TestStreamAgentEvents_BacklogSendErrorPropagates(t *testing.T) {
	reg := liveagents.NewRegistry()
	publish, finish := reg.RegisterInstance("tenant-a", liveagents.Instance{RunID: "run-1", AgentName: "scanner", SandboxID: "sbx", StartedAt: time.Now()})
	defer finish()
	publish([]byte("one"))
	srv := NewAgentConsoleServer(reg, nil)
	stream := &fakeEventStream{ctx: tenantCtx(t, "tenant-a"), sendErr: errors.New("boom")}
	err := srv.StreamAgentEvents(&agentconsolev1.StreamAgentEventsRequest{RunId: "run-1"}, stream)
	if err == nil || !errors.Is(err, stream.sendErr) {
		t.Fatalf("backlog send error = %v; want wrapped boom", err)
	}
}

func TestListRunningAgents_CarriesMissionScope(t *testing.T) {
	reg := liveagents.NewRegistry()
	_, fin := reg.RegisterInstance("tenant-a", liveagents.Instance{
		RunID: "run-1", AgentName: "claude", SandboxID: "sbx-1", StartedAt: time.Now(),
		MissionID: "m-1", MissionRunID: "mr-1",
	})
	defer fin()
	srv := NewAgentConsoleServer(reg, nil)
	resp, err := srv.ListRunningAgents(tenantCtx(t, "tenant-a"), &agentconsolev1.ListRunningAgentsRequest{})
	if err != nil {
		t.Fatalf("ListRunningAgents: %v", err)
	}
	if len(resp.GetAgents()) != 1 {
		t.Fatalf("agents = %d; want 1", len(resp.GetAgents()))
	}
	got := resp.GetAgents()[0]
	if got.GetMissionId() != "m-1" || got.GetMissionRunId() != "mr-1" {
		t.Fatalf("mission scope = %q/%q; want m-1/mr-1", got.GetMissionId(), got.GetMissionRunId())
	}
}

// TestListRunningAgents_DistinguishesAgentsFromTools: tools run in sandboxes
// too and appear on the same console, so a viewer must be able to tell a
// coding agent from a port scan without guessing from the name.
func TestListRunningAgents_DistinguishesAgentsFromTools(t *testing.T) {
	reg := liveagents.NewRegistry()
	_, finA := reg.RegisterInstance("tenant-a", liveagents.Instance{
		RunID: "run-agent", AgentName: "claude", ComponentKind: "agent", StartedAt: time.Now(),
	})
	defer finA()
	_, finT := reg.RegisterInstance("tenant-a", liveagents.Instance{
		RunID: "run-tool", AgentName: "nmap", ComponentKind: "tool", StartedAt: time.Now().Add(time.Second),
	})
	defer finT()

	srv := NewAgentConsoleServer(reg, nil)
	resp, err := srv.ListRunningAgents(tenantCtx(t, "tenant-a"), &agentconsolev1.ListRunningAgentsRequest{})
	if err != nil {
		t.Fatalf("ListRunningAgents: %v", err)
	}
	got := map[string]string{}
	for _, a := range resp.GetAgents() {
		got[a.GetAgentName()] = a.GetComponentKind()
	}
	if got["claude"] != "agent" || got["nmap"] != "tool" {
		t.Fatalf("component kinds = %+v; want claude=agent nmap=tool", got)
	}
}

func TestListRunningAgents_CarriesSandboxClass(t *testing.T) {
	reg := liveagents.NewRegistry()
	_, fin := reg.RegisterInstance("tenant-a", liveagents.Instance{
		RunID: "run-1", AgentName: "claude", SandboxID: "sbx-1", SandboxClass: "agent", StartedAt: time.Now(),
	})
	defer fin()
	srv := NewAgentConsoleServer(reg, nil)
	resp, err := srv.ListRunningAgents(tenantCtx(t, "tenant-a"), &agentconsolev1.ListRunningAgentsRequest{})
	if err != nil {
		t.Fatalf("ListRunningAgents: %v", err)
	}
	if got := resp.GetAgents()[0].GetSandboxClass(); got != "agent" {
		t.Fatalf("sandbox class = %q; want agent", got)
	}
}

// memberSourceFake answers one run as a member.
type memberSourceFake struct {
	runID string
	m     *bank.Member
	err   error
}

func (f *memberSourceFake) MemberByRun(_ context.Context, _, runID string) (*bank.Member, error) {
	if f.err != nil {
		return nil, f.err
	}
	if runID != f.runID {
		return nil, bank.ErrNotFound
	}
	return f.m, nil
}

// TestListRunningAgents_NamesTheBankMember asserts a member's row carries its
// bank, its id and what it last reported, a one-shot row carries none, and a
// member that has not reported yet carries no status.
func TestListRunningAgents_NamesTheBankMember(t *testing.T) {
	reg := liveagents.NewRegistry()
	base := time.Unix(2000, 0)
	_, f1 := reg.RegisterInstance("acme", liveagents.Instance{RunID: "run-1", AgentName: "claude", MissionID: "bank-1", MissionRunID: "mrun-1", StartedAt: base})
	_, f2 := reg.RegisterInstance("acme", liveagents.Instance{RunID: "run-2", AgentName: "scanner", MissionID: "m-9", MissionRunID: "mrun-9", StartedAt: base.Add(time.Second)})
	defer f1()
	defer f2()
	member := &bank.Member{ID: "m-1", BankID: "bank-1", State: bank.MemberBusy, JobsInFlight: 1, JobCap: 2, ClaudeVersion: "2.1.257", LastHeartbeat: base}
	srv := NewAgentConsoleServer(reg, nil, WithMemberSource(&memberSourceFake{runID: "mrun-1", m: member}))

	resp, err := srv.ListRunningAgents(tenantCtx(t, "acme"), &agentconsolev1.ListRunningAgentsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	rows := map[string]*agentconsolev1.RunningAgent{}
	for _, a := range resp.GetAgents() {
		rows[a.GetRunId()] = a
	}
	if rows["run-1"].GetBankId() != "bank-1" || rows["run-1"].GetMemberId() != "m-1" {
		t.Errorf("member row = %+v", rows["run-1"])
	}
	if st := rows["run-1"].GetMember(); st.GetState() != bankpb.MemberState_MEMBER_STATE_BUSY || st.GetJobsInFlight() != 1 || st.GetCap() != 2 {
		t.Errorf("member status = %+v", st)
	}
	if rows["run-2"].GetBankId() != "" || rows["run-2"].GetMember() != nil {
		t.Errorf("a one-shot row must carry no member: %+v", rows["run-2"])
	}

	member.LastHeartbeat = time.Time{}
	resp, _ = srv.ListRunningAgents(tenantCtx(t, "acme"), &agentconsolev1.ListRunningAgentsRequest{})
	for _, a := range resp.GetAgents() {
		if a.GetRunId() == "run-1" && a.GetMember() != nil {
			t.Error("a member that has not reported carries no status")
		}
	}

	srv = NewAgentConsoleServer(reg, nil, WithMemberSource(&memberSourceFake{err: errors.New("postgres is down")}))
	resp, err = srv.ListRunningAgents(tenantCtx(t, "acme"), &agentconsolev1.ListRunningAgentsRequest{})
	if err != nil || len(resp.GetAgents()) != 2 {
		t.Fatalf("a member lookup outage must not hide the rows: %v, %d", err, len(resp.GetAgents()))
	}
}

// TestStreamAgentEvents_JobFilterKeepsOnlyThatJobsLines asserts the job_id
// filter passes the daemon's job lines for that job and holds back the
// agent's own output and other jobs' lines.
func TestStreamAgentEvents_JobFilterKeepsOnlyThatJobsLines(t *testing.T) {
	reg := liveagents.NewRegistry()
	publish, fin := reg.RegisterInstance("acme", liveagents.Instance{RunID: "run-1", AgentName: "claude", StartedAt: time.Now()})
	defer fin()
	publish([]byte(`{"type":"assistant","text":"hi"}` + "\n"))
	publish([]byte(`{"type":"job_opened","job_id":"j-1","goal":"fix"}` + "\n"))
	publish([]byte(`{"type":"job_opened","job_id":"j-2","goal":"other"}` + "\n"))
	publish([]byte("not json\n"))
	publish([]byte(`{"type":"job_state","job_id":"j-1","state":"working"}` + "\n"))

	srv := NewAgentConsoleServer(reg, nil)
	ctx, cancel := context.WithCancel(tenantCtx(t, "acme"))
	stream := &captureStream{ctx: ctx, cancelAfter: 2, cancel: cancel}
	err := srv.StreamAgentEvents(&agentconsolev1.StreamAgentEventsRequest{RunId: "run-1", JobId: "j-1"}, stream)
	if err != nil {
		t.Fatalf("StreamAgentEvents: %v", err)
	}
	if len(stream.got) != 2 {
		t.Fatalf("got %d events, want the two j-1 lines: %q", len(stream.got), stream.got)
	}
	for _, d := range stream.got {
		if !strings.Contains(d, `"job_id":"j-1"`) {
			t.Errorf("a foreign line passed the filter: %s", d)
		}
	}
}

// captureStream records what the server sent and cancels after n sends.
type captureStream struct {
	grpc.ServerStream
	ctx         context.Context
	got         []string
	cancelAfter int
	cancel      context.CancelFunc
}

func (s *captureStream) Context() context.Context { return s.ctx }
func (s *captureStream) Send(ev *agentconsolev1.AgentEvent) error {
	s.got = append(s.got, string(ev.GetData()))
	if len(s.got) >= s.cancelAfter {
		s.cancel()
	}
	return nil
}
