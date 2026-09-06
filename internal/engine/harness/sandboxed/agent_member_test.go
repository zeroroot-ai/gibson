// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package sandboxed

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// memberClient is a sandbox client whose Wait blocks until the test ends the
// run, so a test can prove LaunchMember returned while the sandbox still ran.
type memberClient struct {
	mu        sync.Mutex
	launched  []LaunchRequest
	killed    []string
	runtime   string
	launchErr error
	ended     chan struct{}
}

func newMemberClient() *memberClient {
	return &memberClient{runtime: "gvisor", ended: make(chan struct{})}
}

func (c *memberClient) Launch(_ context.Context, req LaunchRequest) (LaunchResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.launchErr != nil {
		return LaunchResponse{}, c.launchErr
	}
	c.launched = append(c.launched, req)
	return LaunchResponse{SandboxID: "sbx-member-1", Runtime: c.runtime}, nil
}

func (c *memberClient) StreamLogs(context.Context, string) (LogStream, error) {
	return &fixedLogs{}, nil
}

func (c *memberClient) Wait(ctx context.Context, _ string) (WaitResponse, error) {
	select {
	case <-c.ended:
		return WaitResponse{ExitCode: 0, Reason: "ended"}, nil
	case <-ctx.Done():
		return WaitResponse{}, fmt.Errorf("wait: %w", ctx.Err())
	}
}

func (c *memberClient) Kill(_ context.Context, id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.killed = append(c.killed, id)
	return nil
}

func (c *memberClient) killedIDs() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.killed...)
}

// finishCapture records when the live-console registration ends.
type finishCapture struct {
	registered chan LiveInstance
	finished   chan struct{}
}

func (p *finishCapture) RegisterInstance(_ string, inst LiveInstance) (publish func([]byte), finish func()) {
	p.registered <- inst
	return func([]byte) {}, func() { close(p.finished) }
}

func memberSpec() AgentLaunchSpec {
	return AgentLaunchSpec{
		Image:   "ghcr.io/x/claude@sha256:abc",
		Command: []string{"node", "/app/dist/member-main.js"},
		Mode:    "member",
		Env:     map[string]string{"FROM_MANIFEST": "yes", "GIBSON_MEMBER_ID": "manifest-must-not-win"},
	}
}

// TestLaunchMember_ReturnsWhileTheSandboxRuns is the property a member needs:
// the launch returns once the sandbox is admitted, the console sees the
// instance at once, and the feed ends only when the sandbox does.
func TestLaunchMember_ReturnsWhileTheSandboxRuns(t *testing.T) {
	client := newMemberClient()
	events := &finishCapture{registered: make(chan LiveInstance, 1), finished: make(chan struct{})}
	l, err := NewAgentLauncher(AgentLauncherConfig{Client: client, Tenant: "infra", SandboxClass: "agent", Events: events})
	if err != nil {
		t.Fatal(err)
	}

	run, err := l.LaunchMember(context.Background(), memberSpec(), AgentDispatch{
		Grant: "base-grant", CallbackEndpoint: "cb:443", MissionID: "bank-1", MissionRunID: "run-1",
		AgentRunID: "m-1", Tenant: "acme", AgentName: "claude",
		Env: map[string]string{"GIBSON_MEMBER_ID": "m-1", "GIBSON_BANK_ID": "bank-1"},
	})
	if err != nil {
		t.Fatalf("LaunchMember: %v", err)
	}
	if run.SandboxID != "sbx-member-1" || run.RunID == "" {
		t.Fatalf("run = %+v", run)
	}

	req := client.launched[0]
	if req.Timeout != memberLifetime+killGrace {
		t.Errorf("sandbox lifetime = %s, want the member lifetime plus the kill grace", req.Timeout)
	}
	for k, want := range map[string]string{
		"FROM_MANIFEST": "yes", "GIBSON_MEMBER_ID": "m-1", "GIBSON_BANK_ID": "bank-1",
		envAgentGrant: "base-grant", envAgentCallbackEndpoint: "cb:443",
		envAgentMissionID: "bank-1", envAgentMissionRunID: "run-1", envAgentAgentRunID: "m-1",
	} {
		if req.Env[k] != want {
			t.Errorf("env[%s] = %q, want %q", k, req.Env[k], want)
		}
	}

	select {
	case inst := <-events.registered:
		if inst.SandboxID != run.SandboxID || inst.MissionID != "bank-1" || inst.ComponentKind != ComponentKindAgent {
			t.Errorf("registered instance = %+v", inst)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the console must see the member as soon as it is admitted")
	}
	select {
	case <-events.finished:
		t.Fatal("the feed must not end while the sandbox runs")
	case <-time.After(50 * time.Millisecond):
	}

	close(client.ended)
	select {
	case <-events.finished:
	case <-time.After(2 * time.Second):
		t.Fatal("the feed must end when the sandbox does")
	}
}

// TestLaunchMember_RefusesWhatIsNotAMember: a one-shot spec must not be run
// as a member, and a spec with no command has nothing to run.
func TestLaunchMember_RefusesWhatIsNotAMember(t *testing.T) {
	client := newMemberClient()
	l, err := NewAgentLauncher(AgentLauncherConfig{Client: client, Tenant: "infra", SandboxClass: "agent"})
	if err != nil {
		t.Fatal(err)
	}
	spec := memberSpec()
	spec.Mode = "oneshot"
	if _, err := l.LaunchMember(context.Background(), spec, AgentDispatch{}); err == nil {
		t.Error("a one-shot spec must be refused")
	}
	spec = memberSpec()
	spec.Command = nil
	if _, err := l.LaunchMember(context.Background(), spec, AgentDispatch{}); err == nil {
		t.Error("a spec with no command must be refused")
	}
	if len(client.launched) != 0 {
		t.Error("a refused launch must not reach setec")
	}
}

// TestLaunchMember_KillsASandboxItCannotTrust: the isolation gate applies to a
// member as it does to a one-shot, and a launch failure is reported.
func TestLaunchMember_KillsASandboxItCannotTrust(t *testing.T) {
	client := newMemberClient()
	client.runtime = "runc"
	l, err := NewAgentLauncher(AgentLauncherConfig{Client: client, Tenant: "infra", SandboxClass: "agent"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.LaunchMember(context.Background(), memberSpec(), AgentDispatch{Tenant: "acme"}); err == nil {
		t.Fatal("an unisolated runtime must be refused")
	}
	if killed := client.killedIDs(); len(killed) != 1 || killed[0] != "sbx-member-1" {
		t.Fatalf("killed = %v, want the refused sandbox", killed)
	}

	client = newMemberClient()
	client.launchErr = errors.New("setec is down")
	l, _ = NewAgentLauncher(AgentLauncherConfig{Client: client, Tenant: "infra", SandboxClass: "agent"})
	if _, err := l.LaunchMember(context.Background(), memberSpec(), AgentDispatch{Tenant: "acme"}); err == nil {
		t.Fatal("a launch failure must be reported")
	}
}

// TestStopSandbox_KillsByID asserts the teardown reaches setec, and that an
// empty id is refused rather than sent.
func TestStopSandbox_KillsByID(t *testing.T) {
	client := newMemberClient()
	l, err := NewAgentLauncher(AgentLauncherConfig{Client: client, Tenant: "infra", SandboxClass: "agent"})
	if err != nil {
		t.Fatal(err)
	}
	if err := l.StopSandbox(context.Background(), "sbx-9"); err != nil {
		t.Fatalf("StopSandbox: %v", err)
	}
	if killed := client.killedIDs(); len(killed) != 1 || killed[0] != "sbx-9" {
		t.Fatalf("killed = %v", killed)
	}
	if err := l.StopSandbox(context.Background(), ""); err == nil {
		t.Error("an empty id must be refused")
	}
}

// TestLaunchMember_FollowerEndsAtTheLifetime: a sandbox that outlives its
// bound is killed by the follower so setec reaps it.
func TestLaunchMember_FollowerEndsAtTheLifetime(t *testing.T) {
	client := newMemberClient()
	l, err := NewAgentLauncher(AgentLauncherConfig{Client: client, Tenant: "infra", SandboxClass: "agent"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() {
		l.followMember(ctx, func() {}, "sbx-late", AgentDispatch{AgentName: "claude"}, nil, func() { close(done) })
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the follower must end when its context does")
	}
}
