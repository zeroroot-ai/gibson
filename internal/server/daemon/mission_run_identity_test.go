// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/brain/braintest"
	"github.com/zeroroot-ai/gibson/internal/engine/mission"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	missionpb "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
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

// A dispatch that run 1 queued must not run under run 2. The binding of run 2
// replaces the binding of run 1 under the same mission ID.
func TestDispatch_RefusesTheDispatchOfAnotherRun(t *testing.T) {
	eng := brain.NewEngine("t1", braintest.NewMemTimelineStore())
	b := newBrainExecutor(nil, slog.New(slog.DiscardHandler))
	b.register("m1", &missionBinding{ctx: context.Background(), eng: eng, runID: "run-2"})

	// A kind the executor does not support completes the work with an error at
	// once. That is the sign that the dispatch ran.
	b.Dispatch(brain.DispatchRequest{WorkID: "m1/scan", MissionID: "m1", RunID: "run-1", Kind: "unsupported"})
	b.Dispatch(brain.DispatchRequest{WorkID: "m1/scan", MissionID: "m1", RunID: "run-2", Kind: "unsupported"})

	deadline := time.After(2 * time.Second)
	for {
		eng.Tick()
		var runs []string
		for _, ev := range eng.Timeline.Events() {
			if wc, ok := ev.(brain.WorkCompleted); ok {
				runs = append(runs, wc.RunID)
			}
		}
		if len(runs) > 0 {
			if len(runs) != 1 || runs[0] != "run-2" {
				t.Fatalf("completions of runs %v, want only run-2", runs)
			}
			break
		}
		select {
		case <-deadline:
			t.Fatal("the dispatch of run 2 did not run")
		case <-time.After(10 * time.Millisecond):
		}
	}
	// Give a wrongly run dispatch of run 1 time to report.
	time.Sleep(100 * time.Millisecond)
	eng.Tick()
	for _, ev := range eng.Timeline.Events() {
		if wc, ok := ev.(brain.WorkCompleted); ok && wc.RunID == "run-1" {
			t.Fatal("the dispatch of run 1 ran under the binding of run 2")
		}
	}
}

// racingPool occupies the active slot of a record in the window between the
// early check of startRun and its claim. It stands for a second start that wins
// the race.
type racingPool struct {
	datapool.Pool
	onFor func()
}

func (p *racingPool) For(context.Context, auth.TenantID) (*datapool.Conn, error) {
	p.onFor()
	return nil, &datapool.NotProvisionedError{}
}

type countingAuthzStore struct {
	mission.MissionAuthzStore
	puts int
}

func (c *countingAuthzStore) Put(context.Context, string, string, string, string) error {
	c.puts++
	return nil
}

// A start that loses the claim leaves nothing behind: no authz entry, and the
// active entry of the winner stays.
func TestStartRun_RefusedStartLeavesNothingBehind(t *testing.T) {
	tenant := auth.MustNewTenantID("acme")
	rec := &mission.Mission{ID: types.NewID()}
	id := rec.ID.String()
	winner := activeRunOfRecord(rec, tenant)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mm := helperMM()
	mm.brainRegistry = brain.NewRegistry(ctx, braintest.StoreFactory())
	mm.activeMissions = map[auth.TenantID]map[string]*activeMission{}
	authz := &countingAuthzStore{}
	mm.authzStore = authz
	mm.pool = &racingPool{onFor: func() { mm.setActive(tenant, id, winner) }}

	_, err := mm.startRun(auth.ContextWithTenant(ctx, tenant), tenant, rec, &missionpb.MissionDefinition{Name: "recon"})
	if err == nil || !strings.Contains(err.Error(), "already running") {
		t.Fatalf("want an already-running refusal, got %v", err)
	}
	if authz.puts != 0 {
		t.Errorf("a refused start wrote %d authz entries", authz.puts)
	}
	if got, _ := mm.getActive(tenant, id); got != winner {
		t.Error("a refused start changed the active entry of the winner")
	}
}

// A claim that is given back did not complete a mission, so it is not counted.
func TestReleaseActive_DoesNotCountACompletedMission(t *testing.T) {
	mm := helperMM()
	mm.activeMissions = map[auth.TenantID]map[string]*activeMission{}
	tenant := auth.MustNewTenantID("acme")
	rec := &mission.Mission{ID: types.NewID()}
	id := rec.ID.String()

	run := activeRunOfRecord(rec, tenant)
	mm.setActive(tenant, id, run)
	mm.releaseActive(tenant, id, run)
	if _, ok := mm.getActive(tenant, id); ok {
		t.Fatal("the claim was not given back")
	}
	if mm.completedCount != 0 {
		t.Errorf("completedCount = %d after a released claim, want 0", mm.completedCount)
	}

	run = activeRunOfRecord(rec, tenant)
	mm.setActive(tenant, id, run)
	mm.deleteActive(tenant, id, run)
	if mm.completedCount != 1 {
		t.Errorf("completedCount = %d after a finished run, want 1", mm.completedCount)
	}
}

// setActive puts a run in the active map without the claim check. Tests use it
// to seed an active run. The daemon claims the slot with claimActive.
func (m *missionManager) setActive(tenant auth.TenantID, missionID string, am *activeMission) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.activeMissions[tenant] == nil {
		m.activeMissions[tenant] = make(map[string]*activeMission)
	}
	m.activeMissions[tenant][missionID] = am
}

// Run 2 starts while the cleanup of run 1 still has to run. The authz state of
// run 1 is the only one that the cleanup changes, and run 2 stays active.
func TestCleanupOfRun1_LeavesRun2Alone(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	authz := &fakeAuthzStore{}
	mm := helperMM()
	mm.authzStore = authz
	mm.activeMissions = map[auth.TenantID]map[string]*activeMission{}
	mm.brainRegistry = brain.NewRegistry(ctx, braintest.StoreFactory())
	tenant := auth.MustNewTenantID("acme")
	eng := mm.brainRegistry.For(tenant.String())

	rec := &mission.Mission{ID: types.NewID()}
	id := rec.ID.String()
	run1 := activeRunOfRecord(rec, tenant)
	if err := mm.claimActive(tenant, id, run1); err != nil {
		t.Fatalf("claim run 1: %v", err)
	}
	eng.Submit(brain.MissionProjected{ID: id, RunID: runIDOf(run1)})
	eng.Submit(brain.MissionDone{ID: id, RunID: runIDOf(run1), Outcome: brain.MissionCompleted})
	waitWorldStatus(t, eng, id, string(brain.MissionCompleted))

	run2 := activeRunOfRecord(rec, tenant)
	if err := mm.claimActive(tenant, id, run2); err != nil {
		t.Fatalf("claim run 2: %v", err)
	}

	mm.finalizeAuthzState(ctx, run1.missionRun, mission.MissionStatusCompleted)
	mm.deleteActive(tenant, id, run1)

	if len(authz.completed) != 1 || authz.completed[0] != run1.missionRun.ID.String() || len(authz.cancelled) != 0 {
		t.Fatalf("authz completed=%v cancelled=%v, want only the run ID of run 1", authz.completed, authz.cancelled)
	}
	if got, _ := mm.getActive(tenant, id); got != run2 {
		t.Fatal("the cleanup of run 1 removed run 2")
	}
}

// countingQuota counts the open runs of a tenant.
type countingQuota struct{ open int }

func (q *countingQuota) IncrementMissionCount(context.Context) error { q.open++; return nil }
func (q *countingQuota) DecrementMissionCount(context.Context) error { q.open--; return nil }

// The accounting of run 1 runs while run 2 of the same record is active. It
// must not decrement the quota of run 2 and must not release the child
// reservation that the record holds for run 2 (gibson#1228).
func TestEndRunAccounting_Run1LeavesRun2Alone(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn, cleanup := newMiniredisConn(t)
	defer cleanup()
	quota := &countingQuota{}
	mm := helperMM()
	mm.quotaCounter = quota
	mm.activeMissions = map[auth.TenantID]map[string]*activeMission{}
	tenant := auth.MustNewTenantID("acme")

	parent := &mission.Mission{ID: types.NewID()}
	rec := &mission.Mission{ID: types.NewID(), ParentMissionID: &parent.ID}
	cost := int64(500)
	ledger := mission.NewRedisReservationLedger(conn.Redis)
	if _, err := ledger.Reserve(ctx, parent, rec.ID, mission.ChildBudget{CostUSDCents: &cost}); err != nil {
		t.Fatalf("reserve: %v", err)
	}

	id := rec.ID.String()
	run1, run2 := activeRunOfRecord(rec, tenant), activeRunOfRecord(rec, tenant)
	mm.setActive(tenant, id, run1)
	_ = quota.IncrementMissionCount(ctx) // run 1 started
	mm.setActive(tenant, id, run2)       // run 2 took the entry while run 1 cleans up
	_ = quota.IncrementMissionCount(ctx) // run 2 started

	mm.endRunAccounting(ctx, conn, run1)
	if quota.open != 1 {
		t.Fatalf("open runs = %d after the cleanup of run 1, want 1 (the quota of run 2)", quota.open)
	}
	held, err := ledger.Reserved(ctx, parent.ID)
	if err != nil || held.CostUSDCents == nil {
		t.Fatalf("the cleanup of run 1 released the reservation of run 2: %+v, %v", held, err)
	}

	mm.endRunAccounting(ctx, conn, run2)
	if quota.open != 0 {
		t.Fatalf("open runs = %d after both runs ended, want 0", quota.open)
	}
	held, err = ledger.Reserved(ctx, parent.ID)
	if err != nil || held.CostUSDCents != nil {
		t.Fatalf("the reservation was not released when the last run ended: %+v, %v", held, err)
	}
}
