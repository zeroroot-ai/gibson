// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"sync"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/mission"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/server/daemon/api"
	missionpb "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
	typespb "github.com/zeroroot-ai/sdk/api/gen/gibson/types/v1"
)

// stepNode is an agent node of the test chain.
func stepNode(id string, deps ...string) *missionpb.MissionNode {
	return &missionpb.MissionNode{
		Id:           id,
		Type:         missionpb.NodeType_NODE_TYPE_AGENT,
		Dependencies: deps,
		Config: &missionpb.MissionNode_AgentConfig{AgentConfig: &missionpb.AgentNodeConfig{
			AgentName: "worker",
			Task:      &typespb.Task{Goal: "do " + id},
		}},
	}
}

// chainDefinition is the chain one -> two -> three.
func chainDefinition() *missionpb.MissionDefinition {
	return &missionpb.MissionDefinition{
		Id:   "chain",
		Name: "chain",
		Nodes: map[string]*missionpb.MissionNode{
			"one":   stepNode("one"),
			"two":   stepNode("two", "one"),
			"three": stepNode("three", "two"),
		},
		EntryPoints: []string{"one"},
		ExitPoints:  []string{"three"},
	}
}

// runChain projects the chain for missionID into the engine and ends the
// first two nodes. The third node stays pending.
func runChain(eng *brain.Engine, missionID string) {
	eng.Submit(brain.MissionProjected{ID: missionID, Nodes: []brain.WorkNode{
		{ID: "one"},
		{ID: "two", DependsOn: []string{"one"}},
		{ID: "three", DependsOn: []string{"two"}},
	}})
	for _, n := range []string{"one", "two"} {
		id := brain.WorkID(missionID, n)
		eng.Submit(brain.WorkDispatched{ID: id, MissionID: missionID, ItemKind: "agent"})
		eng.Submit(brain.WorkCompleted{ID: id, Result: "ok"})
	}
	eng.Tick()
}

// memStore is an in-memory mission store for the rewind.
type memStore struct {
	mu    sync.Mutex
	byID  map[types.ID]*mission.Mission
	saves int
}

func newMemStore(ms ...*mission.Mission) *memStore {
	s := &memStore{byID: make(map[types.ID]*mission.Mission)}
	for _, m := range ms {
		s.byID[m.ID] = m
	}
	return s
}

func (s *memStore) Get(_ context.Context, id types.ID) (*mission.Mission, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.byID[id]
	if !ok {
		return nil, mission.NewNotFoundError(id.String())
	}
	return m, nil
}

func (s *memStore) Save(_ context.Context, m *mission.Mission) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byID[m.ID] = m
	s.saves++
	return nil
}

// storedChain is the record of a run of the chain.
func storedChain(t *testing.T) *mission.Mission {
	t.Helper()
	defJSON, err := mission.MarshalDefinitionJSON(chainDefinition())
	if err != nil {
		t.Fatalf("marshal definition: %v", err)
	}
	return &mission.Mission{
		ID:                    types.NewID(),
		TenantID:              "tenant-a",
		Name:                  "chain",
		TargetID:              types.NewID(),
		MissionDefinitionJSON: string(defJSON),
	}
}

// startRecorder counts the runs a rewind starts.
type startRecorder struct {
	mu  sync.Mutex
	ids []string
}

func (r *startRecorder) start(_ context.Context, id string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ids = append(r.ids, id)
	return id, nil
}

// A rewind of one mission leaves a second mission of the same tenant World as
// it was, and it deletes no Timeline event (ADR-0170).
func TestRewind_TheSecondMissionDoesNotChange(t *testing.T) {
	eng := brain.NewEngine("tenant-a")
	first, second := storedChain(t), storedChain(t)
	runChain(eng, first.ID.String())
	runChain(eng, second.ID.String())

	secondWorkBefore := workOf(eng, second.ID.String())
	secondEventsBefore := len(eng.MissionEvents(second.ID.String()))
	eventsBefore := len(eng.Events())

	starts := &startRecorder{}
	r := missionRewinder{tenant: "tenant-a", eng: eng, store: newMemStore(first, second), start: starts.start}
	newID, err := r.rewind(tenantCtx(t, "tenant-a"), api.RewindRequest{MissionID: first.ID.String(), CheckpointID: "two"})
	if err != nil {
		t.Fatalf("rewind: %v", err)
	}
	eng.Tick()

	if got := workOf(eng, second.ID.String()); !sameWork(got, secondWorkBefore) {
		t.Fatalf("the work of the second mission changed:\nbefore %+v\nafter  %+v", secondWorkBefore, got)
	}
	if got := len(eng.MissionEvents(second.ID.String())); got != secondEventsBefore {
		t.Fatalf("the slice of the second mission has %d events, want %d", got, secondEventsBefore)
	}
	if got := len(eng.Events()); got != eventsBefore+1 {
		t.Fatalf("the Timeline has %d events, want %d: the rewind adds one and deletes none", got, eventsBefore+1)
	}
	parent, ok := eng.MissionRewind(newID)
	if !ok || parent.ParentMissionID != first.ID.String() || parent.ParentCheckpointID != "two" {
		t.Fatalf("parent of %s = %+v (ok=%v)", newID, parent, ok)
	}
	if len(starts.ids) != 1 || starts.ids[0] != newID {
		t.Fatalf("started %v, want only %s", starts.ids, newID)
	}
}

// A second request with the same idempotency key starts no second run.
func TestRewind_TheSameKeyStartsNoSecondRun(t *testing.T) {
	eng := brain.NewEngine("tenant-a")
	first := storedChain(t)
	runChain(eng, first.ID.String())

	store := newMemStore(first)
	starts := &startRecorder{}
	r := missionRewinder{tenant: "tenant-a", eng: eng, store: store, start: starts.start}
	req := api.RewindRequest{MissionID: first.ID.String(), CheckpointID: "two", IdempotencyKey: "k-1"}

	id1, err := r.rewind(tenantCtx(t, "tenant-a"), req)
	if err != nil {
		t.Fatalf("first rewind: %v", err)
	}
	id2, err := r.rewind(tenantCtx(t, "tenant-a"), req)
	if err != nil {
		t.Fatalf("second rewind: %v", err)
	}
	if id1 != id2 {
		t.Fatalf("the same key returned %s and %s", id1, id2)
	}
	if len(starts.ids) != 1 {
		t.Fatalf("started %d runs, want 1", len(starts.ids))
	}
	if store.saves != 1 {
		t.Fatalf("saved %d missions, want 1", store.saves)
	}
}

func workOf(eng *brain.Engine, missionID string) []brain.WorkSnapshot {
	var out []brain.WorkSnapshot
	for _, w := range eng.Work() {
		if w.MissionID == missionID {
			out = append(out, w)
		}
	}
	return out
}

func sameWork(a, b []brain.WorkSnapshot) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].ID != b[i].ID || a[i].State != b[i].State || a[i].Result != b[i].Result || a[i].CompletedSeq != b[i].CompletedSeq {
			return false
		}
	}
	return true
}

// The new run holds the node of the checkpoint and each node after it. The
// link to the node before the checkpoint is removed.
func TestRewindDefinition_KeepsTheNodeAndTheNodesAfterIt(t *testing.T) {
	instr := "do two again"
	def, err := rewindDefinition(chainDefinition(), "two", &instr)
	if err != nil {
		t.Fatalf("rewindDefinition: %v", err)
	}
	if len(def.GetNodes()) != 2 || def.GetNodes()["one"] != nil {
		t.Fatalf("nodes = %v, want two and three", def.GetNodes())
	}
	if deps := def.GetNodes()["two"].GetDependencies(); len(deps) != 0 {
		t.Fatalf("two still depends on %v", deps)
	}
	if got := def.GetEntryPoints(); len(got) != 1 || got[0] != "two" {
		t.Fatalf("entry points = %v, want [two]", got)
	}
	if got := def.GetNodes()["two"].GetAgentConfig().GetTask().GetGoal(); got != instr {
		t.Fatalf("instruction = %q, want %q", got, instr)
	}
	if got := def.GetNodes()["three"].GetAgentConfig().GetTask().GetGoal(); got != "do three" {
		t.Fatalf("a later node changed its instruction to %q", got)
	}
	if chainDefinition().GetNodes()["two"].GetAgentConfig().GetTask().GetGoal() != "do two" {
		t.Fatal("the source definition changed")
	}
}

func TestRewindDefinition_RefusesANodeNotInTheDefinition(t *testing.T) {
	_, err := rewindDefinition(chainDefinition(), "two#target", nil)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("code = %v, want FailedPrecondition", status.Code(err))
	}
}

func TestRewind_RefusesAnUnknownCheckpoint(t *testing.T) {
	eng := brain.NewEngine("tenant-a")
	first := storedChain(t)
	runChain(eng, first.ID.String())
	starts := &startRecorder{}
	r := missionRewinder{tenant: "tenant-a", eng: eng, store: newMemStore(first), start: starts.start}

	// "three" never ended, so it is not a checkpoint.
	_, err := r.rewind(tenantCtx(t, "tenant-a"), api.RewindRequest{MissionID: first.ID.String(), CheckpointID: "three"})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("code = %v, want NotFound", status.Code(err))
	}
	if len(starts.ids) != 0 {
		t.Fatal("a refused rewind started a run")
	}
}

func TestMissionCheckpoints_ListsTheNodeEndsInOrder(t *testing.T) {
	eng := brain.NewEngine("tenant-a")
	runChain(eng, "m-1")
	runChain(eng, "m-2")

	cps := missionCheckpoints(eng, "m-1")
	if len(cps) != 2 || cps[0].NodeID != "one" || cps[1].NodeID != "two" {
		t.Fatalf("checkpoints = %+v, want one then two", cps)
	}
	if cps[0].TimelinePosition == 0 || cps[1].TimelinePosition <= cps[0].TimelinePosition {
		t.Fatalf("positions = %d, %d, want increasing and not zero", cps[0].TimelinePosition, cps[1].TimelinePosition)
	}
	frame := eng.MissionFrameAt("m-1", int(cps[0].TimelinePosition)) //nolint:gosec // a test position is small
	for _, w := range frame.WorkSnapshot() {
		if w.ID == brain.WorkID("m-1", "one") && w.State != brain.WorkDone {
			t.Fatalf("the frame at the position does not hold the end of one: %s", w.State)
		}
	}
}
