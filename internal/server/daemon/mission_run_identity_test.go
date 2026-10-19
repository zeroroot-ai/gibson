// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/brain/braintest"
	"github.com/zeroroot-ai/gibson/internal/engine/mission"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/sdk/auth"
)

// A run must wait for its own terminal status. The World holds the status of
// the run before until the projection of the new run is folded (gibson#1217).
func TestAwaitBrainMission_IgnoresTheTerminalStatusOfTheRunBefore(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	eng := brain.NewEngine("t1", braintest.NewMemTimelineStore())
	eng.AddSystem(brain.MissionCompletionSystem)
	eng.Submit(brain.MissionProjected{ID: "m1", RunID: "run-1"})
	eng.Tick()
	eng.Tick()
	if ms := eng.Missions(); len(ms) != 1 || ms[0].Status != brain.MissionCompleted {
		t.Fatalf("run 1: %+v, want completed", ms)
	}

	// Run 2 is submitted but not folded: the engine does not tick.
	type result struct {
		status mission.MissionStatus
	}
	done := make(chan result, 1)
	go func() {
		var mm missionManager
		status, _ := mm.awaitBrainMission(ctx, eng, "m1", "run-2")
		done <- result{status}
	}()
	select {
	case r := <-done:
		t.Fatalf("the awaiter of run 2 returned %s with the terminal status of run 1", r.status)
	case <-time.After(700 * time.Millisecond): // three polls
	}

	eng.Submit(brain.MissionProjected{ID: "m1", RunID: "run-2"})
	eng.Tick()
	eng.Tick()
	select {
	case r := <-done:
		if r.status != mission.MissionStatusCompleted {
			t.Fatalf("run 2 = %s, want completed", r.status)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the awaiter of run 2 did not return after run 2 ended")
	}
}

func activeRunOfRecord(rec *mission.Mission, tenant auth.TenantID) *activeMission {
	return &activeMission{
		mission:    rec,
		missionRun: &mission.MissionRun{ID: types.NewID()},
		cancel:     func() {},
		tenantID:   tenant,
	}
}

// Two runs of one record never share the active entry: a run that still runs
// refuses the next start, a run that ended gives its entry to the next run, and
// the cleanup of the ended run does not remove the entry of the next run.
func TestClaimActive_OneRunOfARecordAtATime(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mm := helperMM()
	mm.activeMissions = map[auth.TenantID]map[string]*activeMission{}
	mm.brainRegistry = brain.NewRegistry(ctx, braintest.StoreFactory())
	tenant := auth.MustNewTenantID("acme")
	eng := mm.brainRegistry.For(tenant.String())

	rec := &mission.Mission{ID: types.NewID()}
	id := rec.ID.String()
	run1 := activeRunOfRecord(rec, tenant)
	if err := mm.claimActive(tenant, id, run1); err != nil {
		t.Fatalf("first claim: %v", err)
	}
	eng.Submit(brain.MissionProjected{ID: id, RunID: runIDOf(run1)})
	waitWorldStatus(t, eng, id, string(brain.MissionRunning))

	run2 := activeRunOfRecord(rec, tenant)
	if err := mm.claimActive(tenant, id, run2); err == nil {
		t.Fatal("a second run took the entry while run 1 still runs")
	}
	if got, _ := mm.getActive(tenant, id); got != run1 {
		t.Fatal("a refused run changed the active entry")
	}

	eng.Submit(brain.MissionDone{ID: id, RunID: runIDOf(run1), Outcome: brain.MissionCompleted})
	waitWorldStatus(t, eng, id, string(brain.MissionCompleted))
	if err := mm.claimActive(tenant, id, run2); err != nil {
		t.Fatalf("claim after run 1 ended: %v", err)
	}

	// The cleanup of run 1 runs late. It must leave run 2 in place.
	mm.deleteActive(tenant, id, run1)
	if got, _ := mm.getActive(tenant, id); got != run2 {
		t.Fatal("the cleanup of run 1 removed run 2")
	}
	mm.deleteActive(tenant, id, run2)
	if _, ok := mm.getActive(tenant, id); ok {
		t.Fatal("the cleanup of run 2 left its entry")
	}
}

// The cleanup of a run removes its own binding and no other.
func TestUnregister_KeepsTheBindingOfTheNextRun(t *testing.T) {
	b := newBrainExecutor(nil, nil)
	run1, run2 := &missionBinding{slot: "run-1"}, &missionBinding{slot: "run-2"}
	b.register("m1", run1)
	b.register("m1", run2)
	b.unregister("m1", run1)
	if got, ok := b.get("m1"); !ok || got != run2 {
		t.Fatal("the cleanup of run 1 removed the binding of run 2")
	}
}
