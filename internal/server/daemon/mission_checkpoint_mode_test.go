// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/server/daemon/api"
	missionpb "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
)

// In the sandbox checkpoint mode each agent node is a checkpoint node. In
// the state mode, the default, none is (ADR-0170).
func TestMissionDefinitionToProjected_TheCheckpointMode(t *testing.T) {
	for _, tc := range []struct {
		mode missionpb.CheckpointMode
		want bool
	}{
		{missionpb.CheckpointMode_CHECKPOINT_MODE_SANDBOX, true},
		{missionpb.CheckpointMode_CHECKPOINT_MODE_STATE, false},
		{missionpb.CheckpointMode_CHECKPOINT_MODE_UNSPECIFIED, false},
	} {
		def := chainDefinition()
		def.Checkpoints = tc.mode
		proj, _, err := missionDefinitionToProjected(def, "", nil)
		if err != nil {
			t.Fatalf("%v: project: %v", tc.mode, err)
		}
		for _, n := range proj.Nodes {
			if n.Checkpoint != tc.want {
				t.Errorf("%v: node %s Checkpoint = %v, want %v", tc.mode, n.ID, n.Checkpoint, tc.want)
			}
		}
	}
}

// A checkpoint returns the snapshot that its node left, and a rewind to it
// puts that snapshot on the start node of the new run (ADR-0170).
func TestRewind_StartsFromTheSnapshotOfTheCheckpoint(t *testing.T) {
	eng := brain.NewEngine("tenant-a")
	first := storedChain(t)
	id := first.ID.String()
	eng.Submit(brain.MissionProjected{ID: id, Nodes: []brain.WorkNode{
		{ID: "one", Kind: "agent", Checkpoint: true},
		{ID: "two", Kind: "agent", Checkpoint: true, DependsOn: []string{"one"}},
		{ID: "three", Kind: "agent", Checkpoint: true, DependsOn: []string{"two"}},
	}})
	eng.Submit(brain.WorkDispatched{ID: brain.WorkID(id, "one"), MissionID: id, ItemKind: "agent"})
	eng.Submit(brain.WorkCompleted{ID: brain.WorkID(id, "one"), Result: "ok", Snapshot: "snap-one"})
	eng.Submit(brain.WorkDispatched{ID: brain.WorkID(id, "two"), MissionID: id, ItemKind: "agent"})
	eng.Submit(brain.WorkCompleted{ID: brain.WorkID(id, "two"), Result: "ok"})
	eng.Tick()

	cps := missionCheckpoints(eng, id)
	snaps := map[string]string{}
	for _, cp := range cps {
		snaps[cp.CheckpointID] = cp.SnapshotID
	}
	if snaps["one"] != "snap-one" || snaps["two"] != "" {
		t.Fatalf("checkpoint snapshots = %v", snaps)
	}

	starts := &startRecorder{}
	r := missionRewinder{tenant: "tenant-a", eng: eng, store: newMemStore(first), start: starts.start}
	withSnap, err := r.rewind(tenantCtx(t, "tenant-a"), api.RewindRequest{MissionID: id, CheckpointID: "one"})
	if err != nil {
		t.Fatalf("rewind to one: %v", err)
	}
	fresh, err := r.rewind(tenantCtx(t, "tenant-a"), api.RewindRequest{MissionID: id, CheckpointID: "two"})
	if err != nil {
		t.Fatalf("rewind to two: %v", err)
	}
	eng.Tick()
	if p, ok := eng.MissionRewind(withSnap); !ok || p.StartSnapshot != "snap-one" {
		t.Fatalf("rewind to one = %+v (ok=%v), want the snapshot", p, ok)
	}
	if p, ok := eng.MissionRewind(fresh); !ok || p.StartSnapshot != "" {
		t.Fatalf("rewind to two = %+v (ok=%v), want no snapshot", p, ok)
	}
}
