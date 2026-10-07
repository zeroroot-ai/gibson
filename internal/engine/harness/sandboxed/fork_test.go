// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package sandboxed

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
)

// forkClient returns a mockClient whose forks end with a result line that
// names the fork, and records the fork request and each killed id.
func forkClient(ids []string, forkErr error) (*mockClient, *ForkRequest, *[]string) {
	var (
		mu     sync.Mutex
		got    ForkRequest
		killed []string
	)
	c := &mockClient{
		fork: func(_ context.Context, req ForkRequest) (ForkResponse, error) {
			got = req
			if forkErr != nil {
				return ForkResponse{}, forkErr
			}
			return ForkResponse{Snapshot: "snap-7", SandboxIDs: ids}, nil
		},
		streamLog: func(_ context.Context, id string) (LogStream, error) {
			return &fixedLogs{chunks: [][]byte{[]byte(`{"type":"result","success":true,"output":"` + id + "\"}\n")}}, nil
		},
		wait: func(context.Context, string) (WaitResponse, error) { return WaitResponse{ExitCode: 0}, nil },
		kill: func(_ context.Context, id string) error {
			mu.Lock()
			defer mu.Unlock()
			killed = append(killed, id)
			return nil
		},
	}
	return c, &got, &killed
}

// One fork request starts N instances from one snapshot, with the network
// of the node and not of the source, and each instance runs to its end.
func TestForkAgent_ForksOnceAndFollowsEachFork(t *testing.T) {
	c, got, _ := forkClient([]string{"ns/f1/u1", "ns/f2/u2", "ns/f3/u3"}, nil)
	spec := AgentForkSpec{
		NetworkMode: NetworkModeAllowList,
		Egress:      []EgressRule{{Host: "target.example.com", Port: 443}},
	}
	dispatches := []AgentDispatch{{Tenant: "acme"}, {Tenant: "acme"}, {Tenant: "acme"}}

	run, err := newAgentLauncher(t, c).ForkAgent(context.Background(), "ns/src/u0", spec, dispatches)
	if err != nil {
		t.Fatalf("ForkAgent: %v", err)
	}
	if got.Tenant != "acme" || got.SandboxID != "ns/src/u0" || got.Count != 3 {
		t.Fatalf("fork request = %+v", *got)
	}
	if got.NetworkMode != NetworkModeAllowList || len(got.Egress) != 1 || got.Egress[0].Host != "target.example.com" {
		t.Fatalf("fork network = %q %v; want the scope of the node", got.NetworkMode, got.Egress)
	}
	if run.Snapshot != "snap-7" {
		t.Errorf("snapshot = %q", run.Snapshot)
	}
	for i, want := range []string{"ns/f1/u1", "ns/f2/u2", "ns/f3/u3"} {
		if run.Errs[i] != nil {
			t.Fatalf("fork %d: %v", i, run.Errs[i])
		}
		if run.Results[i].SandboxID != want || run.Results[i].Result == nil || run.Results[i].Result.Output != want {
			t.Errorf("fork %d: result = %+v; want the outcome of %s", i, run.Results[i], want)
		}
	}
}

// Each refusal happens before setec is asked for a fork.
func TestForkAgent_Refusals(t *testing.T) {
	tooMany := make([]AgentDispatch, MaxForks+1)
	for i := range tooMany {
		tooMany[i] = AgentDispatch{Tenant: "acme"}
	}
	cases := map[string]struct {
		source     string
		dispatches []AgentDispatch
	}{
		"no source":     {"", []AgentDispatch{{Tenant: "acme"}}},
		"no fork":       {"src", nil},
		"too many":      {"src", tooMany},
		"no tenant":     {"src", []AgentDispatch{{}}},
		"mixed tenants": {"src", []AgentDispatch{{Tenant: "acme"}, {Tenant: "globex"}}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			called := false
			c := &mockClient{fork: func(context.Context, ForkRequest) (ForkResponse, error) {
				called = true
				return ForkResponse{}, nil
			}}
			if _, err := newAgentLauncher(t, c).ForkAgent(context.Background(), tc.source, AgentForkSpec{}, tc.dispatches); err == nil {
				t.Fatal("want an error")
			}
			if called {
				t.Fatal("setec was asked for a fork")
			}
		})
	}
}

// A setec error returns, and a fork count that does not match kills each
// fork that setec started.
func TestForkAgent_FailuresLeaveNoFork(t *testing.T) {
	c, _, _ := forkClient(nil, errors.New("source is not running"))
	if _, err := newAgentLauncher(t, c).ForkAgent(context.Background(), "src", AgentForkSpec{}, []AgentDispatch{{Tenant: "acme"}}); err == nil ||
		!strings.Contains(err.Error(), "fork agent sandbox") {
		t.Fatalf("err = %v; want the fork error", err)
	}

	c, _, killed := forkClient([]string{"ns/f1/u1"}, nil)
	_, err := newAgentLauncher(t, c).ForkAgent(context.Background(), "src", AgentForkSpec{}, []AgentDispatch{{Tenant: "acme"}, {Tenant: "acme"}})
	if err == nil {
		t.Fatal("want an error for a count that does not match")
	}
	if len(*killed) != 1 || (*killed)[0] != "ns/f1/u1" {
		t.Fatalf("killed = %v; want the one fork that setec started", *killed)
	}
}

// A forkable source returns at its result line, with the sandbox left
// running, and its process gets GIBSON_FORKABLE=1.
func TestLaunchAgent_ForkableSourceParksAtTheResultLine(t *testing.T) {
	waitStarted := make(chan struct{}, 2)
	var env map[string]string
	c := &mockClient{
		launch: func(_ context.Context, req LaunchRequest) (LaunchResponse, error) {
			env = req.Env
			return LaunchResponse{SandboxID: "ns/src/u0"}, nil
		},
		streamLog: func(context.Context, string) (LogStream, error) {
			return &fixedLogs{chunks: [][]byte{[]byte(`{"type":"result","success":true,"output":"mapped"}` + "\n")}}, nil
		},
		wait: func(ctx context.Context, _ string) (WaitResponse, error) {
			waitStarted <- struct{}{}
			<-ctx.Done() // a parked source does not end
			return WaitResponse{}, ctx.Err()
		},
		kill: func(context.Context, string) error { t.Error("a parked source must not be killed"); return nil },
	}
	out, err := newAgentLauncher(t, c).LaunchAgent(context.Background(), agentSpec, AgentDispatch{Tenant: "acme", Forkable: true})
	if err != nil {
		t.Fatalf("LaunchAgent: %v", err)
	}
	if !out.Parked || out.Result == nil || out.Result.Output != "mapped" || out.SandboxID != "ns/src/u0" {
		t.Fatalf("outcome = %+v", out)
	}
	if env[EnvForkable] != "1" {
		t.Fatalf("env %s = %q, want 1", EnvForkable, env[EnvForkable])
	}
}

// A forkable source that exits before a result line is read takes the
// normal path: an old sdk exits after its result line.
func TestLaunchAgent_ForkableSourceThatExitsTakesTheNormalPath(t *testing.T) {
	c := &mockClient{
		launch: func(context.Context, LaunchRequest) (LaunchResponse, error) {
			return LaunchResponse{SandboxID: "s"}, nil
		},
		streamLog: func(context.Context, string) (LogStream, error) { return &fixedLogs{}, nil },
		wait:      func(context.Context, string) (WaitResponse, error) { return WaitResponse{ExitCode: 3}, nil },
		kill:      func(context.Context, string) error { return nil },
	}
	out, err := newAgentLauncher(t, c).LaunchAgent(context.Background(), agentSpec, AgentDispatch{Tenant: "acme", Forkable: true})
	if err != nil {
		t.Fatalf("LaunchAgent: %v", err)
	}
	if out.Parked || out.ExitCode != 3 {
		t.Fatalf("outcome = %+v; want the exit of the sandbox", out)
	}
}

// An OnForked error kills each fork and returns.
func TestForkAgent_RecordFailureKillsTheForks(t *testing.T) {
	c, _, killed := forkClient([]string{"ns/f1/u1"}, nil)
	spec := AgentForkSpec{OnForked: func(ForkResponse) error { return errors.New("ledger down") }}
	if _, err := newAgentLauncher(t, c).ForkAgent(context.Background(), "src", spec, []AgentDispatch{{Tenant: "acme"}}); err == nil {
		t.Fatal("want the record error")
	}
	if len(*killed) != 1 {
		t.Fatalf("killed = %v; want the fork", *killed)
	}
}

// ForkSandbox forks once with the network of the request and does not
// follow the fork. FollowAgent follows it later to its result line.
func TestForkSandbox_ThenFollowAgent(t *testing.T) {
	c, got, killed := forkClient([]string{"ns/f1/u1"}, nil)
	l := newAgentLauncher(t, c)
	var recorded []string
	spec := AgentForkSpec{
		NetworkMode: NetworkModeNone,
		OnForked: func(r ForkResponse) error {
			recorded = r.SandboxIDs
			return nil
		},
	}
	id, err := l.ForkSandbox(context.Background(), "acme", "ns/src/u0", spec)
	if err != nil || id != "ns/f1/u1" {
		t.Fatalf("ForkSandbox = %q, %v", id, err)
	}
	if got.Count != 1 || got.Tenant != "acme" || got.NetworkMode != NetworkModeNone || len(recorded) != 1 {
		t.Fatalf("fork request = %+v, recorded = %v", *got, recorded)
	}
	res, err := l.FollowAgent(context.Background(), id, "", AgentDispatch{Tenant: "acme"})
	if err != nil || res.Result == nil || res.Result.Output != "ns/f1/u1" {
		t.Fatalf("FollowAgent = %+v, %v", res, err)
	}
	if len(*killed) != 0 {
		t.Fatalf("killed = %v", *killed)
	}
}

// Each refusal of ForkSandbox and FollowAgent, and a failed record kills the
// fork.
func TestForkSandbox_Refusals(t *testing.T) {
	ctx := context.Background()
	c, _, killed := forkClient([]string{"ns/f1/u1"}, nil)
	l := newAgentLauncher(t, c)
	if _, err := l.ForkSandbox(ctx, "acme", "", AgentForkSpec{}); err == nil {
		t.Error("no source: want an error")
	}
	if _, err := l.ForkSandbox(ctx, "", "ns/src/u0", AgentForkSpec{}); err == nil {
		t.Error("no tenant: want an error")
	}
	if _, err := l.FollowAgent(ctx, "", "", AgentDispatch{Tenant: "acme"}); err == nil {
		t.Error("follow with no sandbox: want an error")
	}
	if _, err := l.FollowAgent(ctx, "ns/f1/u1", "", AgentDispatch{}); err == nil {
		t.Error("follow with no tenant: want an error")
	}
	_, err := l.ForkSandbox(ctx, "acme", "ns/src/u0", AgentForkSpec{OnForked: func(ForkResponse) error { return errors.New("redis down") }})
	if err == nil || len(*killed) != 1 || (*killed)[0] != "ns/f1/u1" {
		t.Fatalf("record failure: err = %v, killed = %v", err, *killed)
	}
}

// A fork runs only when setec reports that it is bound to the class of the
// launcher on the launcher backend. A fork with another report, or with no
// report, is refused and killed.
func TestForkAgent_RefusesAForkWithoutProvenIsolation(t *testing.T) {
	cases := map[string]func(context.Context, string) (LaunchResponse, error){
		"another runtime": func(_ context.Context, id string) (LaunchResponse, error) {
			return LaunchResponse{SandboxID: id, SandboxClass: mockBoundClass, Runtime: "runc"}, nil
		},
		"no report": func(_ context.Context, id string) (LaunchResponse, error) {
			return LaunchResponse{SandboxID: id}, nil
		},
		"attach fails": func(context.Context, string) (LaunchResponse, error) {
			return LaunchResponse{}, errors.New("setec: attach refused")
		},
	}
	for name, isolation := range cases {
		t.Run(name, func(t *testing.T) {
			c, _, killed := forkClient([]string{"ns/f1/u1"}, nil)
			c.isolation = isolation
			run, err := newAgentLauncher(t, c).ForkAgent(context.Background(), "ns/src/u0", AgentForkSpec{}, []AgentDispatch{{Tenant: "acme"}})
			if err != nil {
				t.Fatalf("ForkAgent: %v", err)
			}
			if run.Errs[0] == nil || !strings.Contains(run.Errs[0].Error(), "refused") {
				t.Fatalf("fork error = %v; want the fork refused", run.Errs[0])
			}
			if len(*killed) != 1 || (*killed)[0] != "ns/f1/u1" {
				t.Fatalf("killed = %v; want the refused fork", *killed)
			}
		})
	}
}
