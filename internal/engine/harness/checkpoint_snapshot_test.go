// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"errors"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/harness/sandboxed"
)

func parkedOutcome(id string) sandboxed.AgentRunResult {
	return sandboxed.AgentRunResult{SandboxID: id, Parked: true, Result: &sandboxed.AgentTerminalResult{Success: true, Output: "done"}}
}

// In the sandbox checkpoint mode a node parks, leaves a snapshot that its
// result names, and its sandbox stops when no later node forks it.
func TestCheckpointMode_TheNodeLeavesASnapshot(t *testing.T) {
	launcher := &recordingLauncher{outcome: parkedOutcome("ns/n1/u1"), snapshot: "snap-1"}
	h, _ := forkHarness(t, launcher)
	task := agent.NewTask("recon", "map the host", nil)
	task.NodeID, task.Checkpoint = "recon", true

	res, err := h.DelegateToAgent(callerCtx(t, "user-1", "zerocool-lab"), "zerocool", task)
	if err != nil {
		t.Fatalf("DelegateToAgent: %v", err)
	}
	if !launcher.gotDispatch.Forkable {
		t.Fatal("a checkpoint node must park at its result line")
	}
	if got := CheckpointSnapshot(res); got != "snap-1" {
		t.Fatalf("checkpoint snapshot = %q, want snap-1", got)
	}
	if len(launcher.stopped) != 1 || launcher.stopped[0] != "ns/n1/u1" {
		t.Fatalf("stopped = %v; the parked sandbox must stop", launcher.stopped)
	}
}

// In the state mode a node leaves no snapshot and does not park.
func TestCheckpointMode_TheStateModeLeavesNone(t *testing.T) {
	launcher := &recordingLauncher{outcome: sandboxed.AgentRunResult{SandboxID: "ns/n1/u1", Result: &sandboxed.AgentTerminalResult{Success: true}}}
	h, _ := forkHarness(t, launcher)
	task := agent.NewTask("recon", "map the host", nil)
	task.NodeID = "recon"

	res, err := h.DelegateToAgent(callerCtx(t, "user-1", "zerocool-lab"), "zerocool", task)
	if err != nil {
		t.Fatalf("DelegateToAgent: %v", err)
	}
	if launcher.gotDispatch.Forkable || len(launcher.snapshotted) != 0 || CheckpointSnapshot(res) != "" {
		t.Fatal("a node of the state mode must not park or snapshot")
	}
}

// A failed snapshot does not fail the node. Its checkpoint has no snapshot.
func TestCheckpointMode_AFailedSnapshotKeepsTheNode(t *testing.T) {
	launcher := &recordingLauncher{outcome: parkedOutcome("ns/n1/u1"), snapshotErr: errors.New("disk full")}
	h, _ := forkHarness(t, launcher)
	task := agent.NewTask("recon", "x", nil)
	task.NodeID, task.Checkpoint = "recon", true

	res, err := h.DelegateToAgent(callerCtx(t, "user-1", "zerocool-lab"), "zerocool", task)
	if err != nil || CheckpointSnapshot(res) != "" {
		t.Fatalf("res = %v, err = %v; want the node and no snapshot", res.Output, err)
	}
}

// The node of a rewind starts from the snapshot with the network of its
// node, and the dispatch is recorded for the new sandbox, which claims it
// with its verified identity (D80).
func TestRewind_TheNodeStartsFromTheSnapshot(t *testing.T) {
	launcher := &recordingLauncher{
		restoreID: "ns/restored-1/u9",
		restored:  sandboxed.AgentRunResult{SandboxID: "ns/restored-1/u9", Result: &sandboxed.AgentTerminalResult{Success: true, Output: "again"}},
	}
	h, ledger := forkHarness(t, launcher)
	task := agent.NewTask("exploit", "try again", nil)
	task.NodeID, task.FromSnapshot = "exploit", "snap-1"
	task.Network = &agent.NodeNetwork{Targets: []string{"10.0.0.5:443"}}

	res, err := h.DelegateToAgent(callerCtx(t, "user-1", "zerocool-lab"), "zerocool", task)
	if err != nil {
		t.Fatalf("DelegateToAgent: %v", err)
	}
	if launcher.restoreSnap != "snap-1" || launcher.calls != 0 {
		t.Fatalf("restore = %q, launches = %d", launcher.restoreSnap, launcher.calls)
	}
	if launcher.restoreSpec.NetworkMode != sandboxed.NetworkModeAllowList || len(launcher.restoreSpec.Egress) == 0 {
		t.Fatalf("restore network = %q %v; want the scope of the node", launcher.restoreSpec.NetworkMode, launcher.restoreSpec.Egress)
	}
	meta, _ := res.Output["metadata"].(map[string]any)
	if meta["restored_from_snapshot"] != "snap-1" {
		t.Fatalf("result metadata = %v", meta)
	}
	d, err := ledger.Claim(context.Background(), "restored-1")
	if err != nil || d.NodeID != "exploit" || d.Tenant != "zerocool-lab" || d.AgentName != "zerocool" {
		t.Fatalf("claim = %+v, %v", d, err)
	}
}

// A rewind whose snapshot is gone starts the node in a fresh sandbox.
func TestRewind_AGoneSnapshotStartsFresh(t *testing.T) {
	launcher := &recordingLauncher{
		restoreErr: sandboxed.ErrSnapshotGone,
		outcome:    sandboxed.AgentRunResult{SandboxID: "ns/fresh/u1", Result: &sandboxed.AgentTerminalResult{Success: true}},
	}
	h, _ := forkHarness(t, launcher)
	task := agent.NewTask("exploit", "x", nil)
	task.NodeID, task.FromSnapshot = "exploit", "snap-old"

	if _, err := h.DelegateToAgent(callerCtx(t, "user-1", "zerocool-lab"), "zerocool", task); err != nil {
		t.Fatalf("DelegateToAgent: %v", err)
	}
	if launcher.calls != 1 {
		t.Fatalf("fresh launches = %d, want 1", launcher.calls)
	}
}

// Any other restore error fails the node.
func TestRewind_ARestoreErrorFailsTheNode(t *testing.T) {
	launcher := &recordingLauncher{restoreErr: errors.New("quota")}
	h, _ := forkHarness(t, launcher)
	task := agent.NewTask("exploit", "x", nil)
	task.NodeID, task.FromSnapshot = "exploit", "snap-1"
	if _, err := h.DelegateToAgent(callerCtx(t, "user-1", "zerocool-lab"), "zerocool", task); err == nil || launcher.calls != 0 {
		t.Fatalf("err = %v, launches = %d; want an error and no fresh launch", err, launcher.calls)
	}
}
