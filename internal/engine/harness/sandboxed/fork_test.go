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
