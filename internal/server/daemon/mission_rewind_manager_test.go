// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/mission"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/server/daemon/api"
	missionpb "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
)

// rewindManager is a mission manager with a live brain registry and no pool.
func rewindManager(t *testing.T) (*missionManager, *brain.Registry) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	reg := brain.NewRegistry(ctx)
	return &missionManager{logger: slog.New(slog.DiscardHandler), brainRegistry: reg}, reg
}

// The manager returns the node ends of a run of the caller's tenant, and an
// empty list for a run it does not know.
func TestMissionManager_Checkpoints(t *testing.T) {
	m, reg := rewindManager(t)
	mid := types.NewID().String()
	submitChain(reg.For("tenant-a"), mid)
	ctx := tenantCtx(t, "tenant-a")

	var cps []api.MissionCheckpoint
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		var err error
		cps, err = m.Checkpoints(ctx, mid)
		if err != nil {
			t.Fatalf("Checkpoints: %v", err)
		}
		if len(cps) == 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(cps) != 2 || cps[0].CheckpointID != "one" || cps[1].CheckpointID != "two" {
		t.Fatalf("checkpoints = %+v, want one and two", cps)
	}

	other, err := m.Checkpoints(tenantCtx(t, "tenant-b"), mid)
	if err != nil || other == nil || len(other) != 0 {
		t.Fatalf("another tenant: %+v, %v, want an empty list", other, err)
	}
	if _, err := m.Checkpoints(ctx, ""); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("no mission id: code %v, want InvalidArgument", status.Code(err))
	}
	if _, err := m.Checkpoints(context.Background(), mid); err == nil {
		t.Fatal("no tenant: want an error")
	}
}

// A rewind needs a tenant, both ids and a mission store.
func TestMissionManager_RewindRefusesWhatItCannotServe(t *testing.T) {
	m, _ := rewindManager(t)
	ctx := tenantCtx(t, "tenant-a")
	req := api.RewindRequest{MissionID: types.NewID().String(), CheckpointID: "two"}

	if _, err := m.Rewind(context.Background(), req); err == nil {
		t.Fatal("no tenant: want an error")
	}
	if _, err := m.Rewind(ctx, api.RewindRequest{MissionID: req.MissionID}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("no checkpoint id: code %v, want InvalidArgument", status.Code(err))
	}
	if _, err := m.Rewind(ctx, req); status.Code(err) != codes.Unavailable {
		t.Fatalf("no mission store: code %v, want Unavailable", status.Code(err))
	}
}

// A mission that a rewind started reads with its parent.
func TestMissionManager_GetReadsTheParentOfARewind(t *testing.T) {
	m, reg := rewindManager(t)
	child := types.NewID().String()
	eng := reg.For("tenant-a")
	eng.Submit(brain.MissionProjected{ID: child, TenantID: "tenant-a", Nodes: []brain.WorkNode{{ID: "two"}}})
	eng.Submit(brain.MissionRewound{MissionID: child, ParentMissionID: "parent-1", ParentCheckpointID: "two"})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		got, err := m.Get(tenantCtx(t, "tenant-a"), child)
		if err == nil && got.ParentMissionID == "parent-1" && got.ParentCheckpointID == "two" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the mission did not read with its parent")
}

// failingStore fails the call that a test names.
type failingStore struct {
	*memStore
	getErr  error
	saveErr error
}

func (s failingStore) Get(ctx context.Context, id types.ID) (*mission.Mission, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	return s.memStore.Get(ctx, id)
}

func (s failingStore) Save(ctx context.Context, m *mission.Mission) error {
	if s.saveErr != nil {
		return s.saveErr
	}
	return s.memStore.Save(ctx, m)
}

// Each request that the rewind cannot serve fails, and no run starts.
func TestRewind_RefusesWhatItCannotServe(t *testing.T) {
	eng := brain.NewEngine("tenant-a")
	parent := storedChain(t)
	runChain(eng, parent.ID.String())
	noDef := storedChain(t)
	noDef.MissionDefinitionJSON = ""
	runChain(eng, noDef.ID.String())
	badDef := storedChain(t)
	badDef.MissionDefinitionJSON = "{not json"
	runChain(eng, badDef.ID.String())
	missing := types.NewID()
	runChain(eng, missing.String())
	down := errors.New("store down")
	newGoal := "look again"

	cases := map[string]struct {
		store rewindStore
		req   api.RewindRequest
		code  codes.Code
	}{
		"not a mission id":  {newMemStore(parent), api.RewindRequest{MissionID: "x", CheckpointID: "two"}, codes.InvalidArgument},
		"unknown parent":    {newMemStore(), api.RewindRequest{MissionID: missing.String(), CheckpointID: "two"}, codes.NotFound},
		"no definition":     {newMemStore(noDef), api.RewindRequest{MissionID: noDef.ID.String(), CheckpointID: "two"}, codes.FailedPrecondition},
		"bad definition":    {newMemStore(badDef), api.RewindRequest{MissionID: badDef.ID.String(), CheckpointID: "two"}, codes.Unknown},
		"store down":        {failingStore{memStore: newMemStore(parent), getErr: down}, api.RewindRequest{MissionID: parent.ID.String(), CheckpointID: "two"}, codes.Unknown},
		"key lookup fails":  {failingStore{memStore: newMemStore(parent), getErr: down}, api.RewindRequest{MissionID: parent.ID.String(), CheckpointID: "two", IdempotencyKey: "k"}, codes.Unknown},
		"save fails":        {failingStore{memStore: newMemStore(parent), saveErr: down}, api.RewindRequest{MissionID: parent.ID.String(), CheckpointID: "two"}, codes.Unknown},
		"a new instruction": {newMemStore(parent), api.RewindRequest{MissionID: parent.ID.String(), CheckpointID: "two", Instruction: &newGoal}, codes.OK},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			starts := &startRecorder{}
			r := missionRewinder{tenant: "tenant-a", eng: eng, store: c.store, start: starts.start}
			_, err := r.rewind(tenantCtx(t, "tenant-a"), c.req)
			if status.Code(err) != c.code {
				t.Fatalf("code %v (%v), want %v", status.Code(err), err, c.code)
			}
			if c.code != codes.OK && len(starts.ids) != 0 {
				t.Fatalf("a refused rewind started %v", starts.ids)
			}
		})
	}
}

// The daemon answers Unavailable with no mission manager and passes each call
// to the manager when it has one.
func TestDaemonRewindRPCs(t *testing.T) {
	d := &daemonImpl{logger: testObservabilityLogger()}
	ctx := tenantCtx(t, "tenant-a")
	if _, err := d.GetMissionCheckpoints(ctx, "m"); status.Code(err) != codes.Unavailable {
		t.Fatalf("GetMissionCheckpoints: code %v, want Unavailable", status.Code(err))
	}
	if _, err := d.RewindMission(ctx, api.RewindRequest{MissionID: "m", CheckpointID: "c"}); status.Code(err) != codes.Unavailable {
		t.Fatalf("RewindMission: code %v, want Unavailable", status.Code(err))
	}

	d.missionManager, _ = rewindManager(t)
	if cps, err := d.GetMissionCheckpoints(ctx, "m"); err != nil || len(cps) != 0 {
		t.Fatalf("GetMissionCheckpoints: %v, %v", cps, err)
	}
	if _, err := d.RewindMission(ctx, api.RewindRequest{MissionID: "m"}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("RewindMission: code %v, want InvalidArgument", status.Code(err))
	}
}

// A join and the edges keep only the nodes from the checkpoint
// on. A join that waits only for earlier nodes, and a new instruction for a
// node that is not an agent with a task, are refused.
func TestRewindDefinition_TrimsJoinsConditionsAndEdges(t *testing.T) {
	def := chainDefinition()
	def.Nodes["check"] = &missionpb.MissionNode{
		Id: "check", Type: missionpb.NodeType_NODE_TYPE_CONDITION, Dependencies: []string{"two"},
		Config: &missionpb.MissionNode_ConditionConfig{ConditionConfig: &missionpb.ConditionNodeConfig{
			TrueBranch: []string{"three"},
		}},
	}
	def.Nodes["join"] = &missionpb.MissionNode{
		Id: "join", Type: missionpb.NodeType_NODE_TYPE_JOIN, Dependencies: []string{"two"},
		Config: &missionpb.MissionNode_JoinConfig{JoinConfig: &missionpb.JoinNodeConfig{WaitFor: []string{"one", "two"}}},
	}
	def.Edges = []*missionpb.MissionEdge{{From: "one", To: "two"}, {From: "two", To: "three"}}

	out, err := rewindDefinition(def, "two", nil)
	if err != nil {
		t.Fatalf("rewindDefinition: %v", err)
	}
	if len(out.GetEdges()) != 1 || out.GetEdges()[0].GetFrom() != "two" {
		t.Errorf("edges = %v, want only two -> three", out.GetEdges())
	}
	if got := out.GetNodes()["join"].GetJoinConfig().GetWaitFor(); len(got) != 1 || got[0] != "two" {
		t.Errorf("join waits for %v, want [two]", got)
	}
	cc := out.GetNodes()["check"].GetConditionConfig()
	if len(cc.GetTrueBranch()) != 1 || cc.GetTrueBranch()[0] != "three" {
		t.Errorf("condition branches = %v / %v", cc.GetTrueBranch(), cc.GetFalseBranch())
	}

	def.Nodes["join"].GetJoinConfig().WaitFor = []string{"one"}
	if _, err := rewindDefinition(def, "two", nil); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("a join on earlier nodes only: code %v, want FailedPrecondition", status.Code(err))
	}
	delete(def.Nodes, "join")

	goal := "look again"
	if _, err := rewindDefinition(def, "check", &goal); status.Code(err) != codes.InvalidArgument {
		t.Errorf("an instruction for a condition node: code %v, want InvalidArgument", status.Code(err))
	}
	def.Nodes["two"].GetAgentConfig().Task = nil
	if _, err := rewindDefinition(def, "two", &goal); status.Code(err) != codes.InvalidArgument {
		t.Errorf("an instruction for an agent with no task: code %v, want InvalidArgument", status.Code(err))
	}
}
