// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package sandboxed

import (
	"context"
	"errors"
	"testing"
	"time"
)

func restoreClient(launchErr error) (*mockClient, *LaunchRequest, *[]string) {
	var (
		got    LaunchRequest
		killed []string
	)
	c := &mockClient{
		launch: func(_ context.Context, req LaunchRequest) (LaunchResponse, error) {
			got = req
			if launchErr != nil {
				return LaunchResponse{}, launchErr
			}
			return LaunchResponse{SandboxID: "ns/r1/u1"}, nil
		},
		streamLog: func(context.Context, string) (LogStream, error) {
			return &fixedLogs{chunks: [][]byte{[]byte(`{"type":"result","success":true,"output":"again"}` + "\n")}}, nil
		},
		wait: func(context.Context, string) (WaitResponse, error) { return WaitResponse{}, nil },
		kill: func(_ context.Context, id string) error { killed = append(killed, id); return nil },
		snapshot: func(_ context.Context, id string, ttl time.Duration) (string, error) {
			return "snap-of-" + id, nil
		},
	}
	return c, &got, &killed
}

// A restore launches from the snapshot with the network of the node and the
// tenant, records the start before it follows the sandbox, and returns the
// outcome of the run.
func TestLaunchFromSnapshot_RecordsAndFollows(t *testing.T) {
	c, got, _ := restoreClient(nil)
	var recorded string
	spec := AgentForkSpec{NetworkMode: NetworkModeAllowList, Egress: []EgressRule{{Host: "10.0.0.5", Port: 443}}}
	out, err := newAgentLauncher(t, c).LaunchFromSnapshot(context.Background(), "snap-1", spec, AgentDispatch{Tenant: "acme"},
		func(id string) error { recorded = id; return nil })
	if err != nil {
		t.Fatalf("LaunchFromSnapshot: %v", err)
	}
	if got.FromSnapshot != "snap-1" || got.Tenant != "acme" || got.NetworkMode != NetworkModeAllowList || got.Image != "" {
		t.Fatalf("launch = %+v", *got)
	}
	if recorded != "ns/r1/u1" || out.Result == nil || out.Result.Output != "again" {
		t.Fatalf("recorded = %q, outcome = %+v", recorded, out)
	}
}

// A gone snapshot returns ErrSnapshotGone, a record failure kills the
// sandbox, and a call with no tenant or no snapshot is refused.
func TestLaunchFromSnapshot_Failures(t *testing.T) {
	ctx := context.Background()
	c, _, _ := restoreClient(ErrSnapshotGone)
	if _, err := newAgentLauncher(t, c).LaunchFromSnapshot(ctx, "old", AgentForkSpec{}, AgentDispatch{Tenant: "acme"}, func(string) error { return nil }); !errors.Is(err, ErrSnapshotGone) {
		t.Fatalf("gone: err = %v", err)
	}
	c, _, killed := restoreClient(nil)
	if _, err := newAgentLauncher(t, c).LaunchFromSnapshot(ctx, "snap", AgentForkSpec{}, AgentDispatch{Tenant: "acme"}, func(string) error { return errors.New("ledger down") }); err == nil {
		t.Fatal("record failure: want an error")
	}
	if len(*killed) != 1 {
		t.Fatalf("killed = %v; a sandbox with no record must be killed", *killed)
	}
	if _, err := newAgentLauncher(t, c).LaunchFromSnapshot(ctx, "", AgentForkSpec{}, AgentDispatch{Tenant: "acme"}, nil); err == nil {
		t.Fatal("no snapshot: want an error")
	}
	if _, err := newAgentLauncher(t, c).LaunchFromSnapshot(ctx, "snap", AgentForkSpec{}, AgentDispatch{}, nil); err == nil {
		t.Fatal("no tenant: want an error")
	}
}

// SnapshotSandbox names the sandbox, and refuses a call with no tenant.
func TestSnapshotSandbox(t *testing.T) {
	c, _, _ := restoreClient(nil)
	snap, err := newAgentLauncher(t, c).SnapshotSandbox(context.Background(), "acme", "ns/n1/u1", time.Hour)
	if err != nil || snap != "snap-of-ns/n1/u1" {
		t.Fatalf("SnapshotSandbox = %q, %v", snap, err)
	}
	if _, err := newAgentLauncher(t, c).SnapshotSandbox(context.Background(), "", "x", time.Hour); err == nil {
		t.Fatal("no tenant: want an error")
	}
}
