// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/brain/braintest"
	"github.com/zeroroot-ai/gibson/internal/engine/mission"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/sdk/auth"
)

// A stop ends the mission as "canceled" and not as "failed" (ADR-0175).
func TestStop_EndsTheMissionAsCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mm := helperMM()
	mm.activeMissions = map[auth.TenantID]map[string]*activeMission{}
	mm.brainRegistry = brain.NewRegistry(ctx, braintest.StoreFactory())
	tenant := auth.MustNewTenantID("acme")
	eng := mm.brainRegistry.For(tenant.String())

	rec := &mission.Mission{ID: types.NewID()}
	id := rec.ID.String()
	run := activeRunOfRecord(rec, tenant)
	if err := mm.claimActive(tenant, id, run); err != nil {
		t.Fatalf("claim: %v", err)
	}
	eng.Submit(brain.MissionProjected{ID: id, RunID: runIDOf(run)})
	waitWorldStatus(t, eng, id, string(brain.MissionWorking))

	if err := mm.Stop(auth.ContextWithTenant(ctx, tenant), id, false); err != nil {
		t.Fatalf("stop: %v", err)
	}
	waitWorldStatus(t, eng, id, string(brain.MissionCanceled))

	// The awaiter of the run reports the cancel and not a failure.
	status, _ := mm.awaitBrainMission(ctx, eng, id, runIDOf(run))
	if status != mission.MissionStatusCanceled {
		t.Errorf("awaited status = %q, want %q", status, mission.MissionStatusCanceled)
	}
	if !mm.runEnded(tenant, run) {
		t.Error("a canceled run must count as ended")
	}
}

// A canceled run is an end state. A run that waits for input is not.
func TestIsEndedRunStatus_CanceledEnds(t *testing.T) {
	if !isEndedRunStatus(string(brain.MissionCanceled)) {
		t.Error("canceled must be an end state")
	}
	if isEndedRunStatus(string(brain.MissionInputRequired)) {
		t.Error("input_required must not be an end state")
	}
}
