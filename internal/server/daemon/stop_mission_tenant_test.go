// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"log/slog"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/mission"
	"github.com/zeroroot-ai/sdk/auth"
)

// seedActiveMission registers a running mission for `tenant` on mm and returns
// a func reporting whether its context was cancelled.
func seedActiveMission(t *testing.T, mm *missionManager, tenant auth.TenantID, missionID string) func() bool {
	t.Helper()
	mctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	mm.setActive(tenant, missionID, &activeMission{
		mission:  &mission.Mission{},
		ctx:      mctx,
		cancel:   cancel,
		tenantID: tenant,
	})
	return func() bool { return mctx.Err() != nil }
}

// newStopMissionTestDaemon builds a daemonImpl carrying only what StopMission
// touches: a logger and a missionManager with a live brain registry.
func newStopMissionTestDaemon(t *testing.T) *daemonImpl {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	mm := &missionManager{
		logger:         slog.New(slog.DiscardHandler),
		brainRegistry:  brain.NewRegistry(ctx),
		activeMissions: make(map[auth.TenantID]map[string]*activeMission),
	}
	d := newMinimalDaemon(minimalCfg())
	d.missionManager = mm
	return d
}

// TestStopMission_OwningTenantStops is the positive half of the
// GHSA-hmq9-jvvc-73w9 regression pair: the tenant that owns the mission can
// still stop it, so the fix did not simply break cancellation.
func TestStopMission_OwningTenantStops(t *testing.T) {
	d := newStopMissionTestDaemon(t)
	acme := auth.MustNewTenantID("acme")
	cancelled := seedActiveMission(t, d.missionManager, acme, "mission-1")

	ctx := auth.WithTenant(context.Background(), acme)
	if err := d.StopMission(ctx, "mission-1", false); err != nil {
		t.Fatalf("owning tenant must be able to stop its own mission: %v", err)
	}
	if !cancelled() {
		t.Error("owning tenant's StopMission did not cancel the mission context")
	}
}

// TestStopMission_CrossTenantDenied is the regression guard for
// GHSA-hmq9-jvvc-73w9. Tenant "evil" names a mission ID owned by "acme".
// StopMission must refuse and must NOT cancel acme's mission.
//
// This used to be reachable through a daemon-level activeMissions map keyed by
// mission ID with no tenant component. That map is gone; cancellation now goes
// only through missionManager, whose map is keyed by (tenant, missionID).
func TestStopMission_CrossTenantDenied(t *testing.T) {
	d := newStopMissionTestDaemon(t)
	acme := auth.MustNewTenantID("acme")
	evil := auth.MustNewTenantID("evil")
	cancelled := seedActiveMission(t, d.missionManager, acme, "mission-1")

	ctx := auth.WithTenant(context.Background(), evil)
	if err := d.StopMission(ctx, "mission-1", false); err == nil {
		t.Fatal("StopMission must refuse a mission ID owned by another tenant")
	}
	if cancelled() {
		t.Error("cross-tenant StopMission cancelled another tenant's mission (GHSA-hmq9-jvvc-73w9)")
	}

	// The owner is unaffected and can still stop it afterwards.
	if err := d.StopMission(auth.WithTenant(context.Background(), acme), "mission-1", false); err != nil {
		t.Fatalf("owner stop after a rejected cross-tenant attempt: %v", err)
	}
	if !cancelled() {
		t.Error("owner's stop did not cancel the mission")
	}
}

// TestStopMission_EmptyMissionID keeps the argument guard covered.
func TestStopMission_EmptyMissionID(t *testing.T) {
	d := newStopMissionTestDaemon(t)
	if err := d.StopMission(context.Background(), "", false); err == nil {
		t.Fatal("expected an error for an empty mission ID")
	}
}
