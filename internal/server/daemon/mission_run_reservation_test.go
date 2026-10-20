// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/brain/braintest"
	"github.com/zeroroot-ai/gibson/internal/engine/mission"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	missionpb "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// The reservation belongs to the record, and the end of a run releases it. A
// later run of the record reserves again when it starts, and it releases at its
// own end (gibson#1270).
func TestReserveChildBudget_ALaterRunReservesAgain(t *testing.T) {
	ctx := context.Background()
	conn, cleanup := newMiniredisConn(t)
	defer cleanup()
	mm := helperMM()
	mm.activeMissions = map[auth.TenantID]map[string]*activeMission{}
	tenant := auth.MustNewTenantID("acme")

	parent := &mission.Mission{
		ID:          types.NewID(),
		Name:        "parent",
		TargetID:    types.NewID(),
		Constraints: &missionpb.MissionConstraints{MaxCost: 100},
	}
	mm.loadMission = func(_ context.Context, _ *datapool.Conn, id types.ID) (*mission.Mission, error) {
		if id == parent.ID {
			return parent, nil
		}
		return nil, errors.New("not found")
	}
	child := &mission.Mission{
		ID:              types.NewID(),
		ParentMissionID: &parent.ID,
		Constraints:     &missionpb.MissionConstraints{MaxCost: 5},
	}
	ledger := mission.NewRedisReservationLedger(conn.Redis)
	held := func() *int64 {
		r, err := ledger.Reserved(ctx, parent.ID)
		if err != nil {
			t.Fatalf("reserved: %v", err)
		}
		return r.CostUSDCents
	}

	run1 := activeRunOfRecord(child, tenant)
	if err := mm.reserveChildBudget(ctx, conn, run1); err != nil {
		t.Fatalf("run 1 reserve: %v", err)
	}
	if got := held(); got == nil || *got != 500 {
		t.Fatalf("run 1 holds %v, want 500 cents", got)
	}
	mm.endRunAccounting(ctx, conn, run1)
	if got := held(); got != nil {
		t.Fatalf("the end of run 1 left a reservation: %d", *got)
	}

	run2 := activeRunOfRecord(child, tenant)
	if err := mm.reserveChildBudget(ctx, conn, run2); err != nil {
		t.Fatalf("run 2 reserve: %v", err)
	}
	if got := held(); got == nil || *got != 500 {
		t.Fatalf("run 2 holds %v, want 500 cents", got)
	}
	mm.endRunAccounting(ctx, conn, run2)
	if got := held(); got != nil {
		t.Fatalf("the end of run 2 left a reservation: %d", *got)
	}
}

// A run with no parent reserves nothing. A run whose parent is gone, or whose
// parent has no budget left, is refused.
func TestReserveChildBudget_RefusesWhatCannotBeReserved(t *testing.T) {
	ctx := context.Background()
	conn, cleanup := newMiniredisConn(t)
	defer cleanup()
	mm := helperMM()
	tenant := auth.MustNewTenantID("acme")

	root := activeRunOfRecord(&mission.Mission{ID: types.NewID()}, tenant)
	if err := mm.reserveChildBudget(ctx, conn, root); err != nil {
		t.Fatalf("a run with no parent: %v", err)
	}

	missing := types.NewID()
	orphan := activeRunOfRecord(&mission.Mission{ID: types.NewID(), ParentMissionID: &missing}, tenant)
	if err := mm.reserveChildBudget(ctx, conn, orphan); err == nil {
		t.Fatal("a run whose parent does not exist was not refused")
	}

	parent := &mission.Mission{
		ID:          types.NewID(),
		Name:        "parent",
		TargetID:    types.NewID(),
		Constraints: &missionpb.MissionConstraints{MaxCost: 5},
	}
	mm.loadMission = func(_ context.Context, _ *datapool.Conn, id types.ID) (*mission.Mission, error) {
		if id == parent.ID {
			return parent, nil
		}
		return nil, errors.New("not found")
	}
	ledger := mission.NewRedisReservationLedger(conn.Redis)
	cost := int64(500)
	if _, err := ledger.Reserve(ctx, parent, types.NewID(), mission.ChildBudget{CostUSDCents: &cost}); err != nil {
		t.Fatalf("sibling reserve: %v", err)
	}
	child := activeRunOfRecord(&mission.Mission{
		ID: types.NewID(), ParentMissionID: &parent.ID,
		Constraints: &missionpb.MissionConstraints{MaxCost: 1},
	}, tenant)
	if err := mm.reserveChildBudget(ctx, conn, child); err == nil {
		t.Fatal("a run against a spent parent was not refused")
	}
}

// failingLedger refuses every reservation.
type failingLedger struct{ mission.ReservationLedger }

func (failingLedger) Reserve(context.Context, *mission.Mission, types.ID, mission.ChildBudget) (mission.ChildBudget, error) {
	return mission.ChildBudget{}, errors.New("ledger down")
}

// A run that cannot reserve its budget fails before it starts, and the World
// records the failure.
func TestReserveRunBudget_ARefusalFailsTheRunBeforeItStarts(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn, cleanup := newMiniredisConn(t)
	defer cleanup()
	mm := helperMM()
	mm.brainRegistry = brain.NewRegistry(ctx, braintest.StoreFactory())
	tenant := auth.MustNewTenantID("acme")
	parent := &mission.Mission{ID: types.NewID(), Constraints: &missionpb.MissionConstraints{MaxCost: 100}}
	mm.loadMission = func(context.Context, *datapool.Conn, types.ID) (*mission.Mission, error) { return parent, nil }
	mm.newLedger = func(*datapool.Conn) mission.ReservationLedger { return failingLedger{} }
	quota := &countingQuota{open: 1} // the run took a slot when it started
	mm.quotaCounter = quota

	run := activeRunOfRecord(&mission.Mission{ID: types.NewID(), ParentMissionID: &parent.ID}, tenant)
	if mm.reserveRunBudget(ctx, conn, run, "child") {
		t.Fatal("the run went on without a reservation")
	}
	waitWorldStatus(t, mm.brainRegistry.For(tenant.String()), run.mission.ID.String(), string(brain.MissionFailed))
	if quota.open != 0 {
		t.Fatalf("open runs = %d after a refused run, want 0: the slot leaked", quota.open)
	}

	// A run with no parent goes on.
	root := activeRunOfRecord(&mission.Mission{ID: types.NewID()}, tenant)
	if !mm.reserveRunBudget(ctx, conn, root, "root") {
		t.Fatal("a run with no parent was stopped")
	}
}
