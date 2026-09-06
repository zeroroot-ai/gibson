// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/zeroroot-ai/sdk/auth"
)

func TestNewMissionContext_CarriesTheTenant(t *testing.T) {
	tenant, err := auth.NewTenantID("zerocool-lab")
	if err != nil {
		t.Fatalf("NewTenantID: %v", err)
	}
	ctx, cancel := newMissionContext(context.Background(), tenant)
	defer cancel()

	if got := auth.TenantStringFromContext(ctx); got != "zerocool-lab" {
		t.Fatalf("tenant on mission context = %q, want zerocool-lab", got)
	}
}

func TestNewMissionContext_SurvivesTheCallersCancellation(t *testing.T) {
	// The RunMission stream ending must not end the mission.
	caller, cancelCaller := context.WithCancel(context.Background())
	tenant, err := auth.NewTenantID("zerocool-lab")
	if err != nil {
		t.Fatalf("NewTenantID: %v", err)
	}
	ctx, cancel := newMissionContext(context.Background(), tenant)
	defer cancel()

	cancelCaller()
	_ = caller

	select {
	case <-ctx.Done():
		t.Fatal("mission context was cancelled by the caller's cancellation")
	case <-time.After(50 * time.Millisecond):
	}
}
