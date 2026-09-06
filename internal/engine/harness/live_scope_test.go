// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/sdk/auth"
)

// liveScope decides who can SEE a running sandbox on the agent console. It is
// stamped on every sandboxed dispatch, and the registry it feeds is keyed by
// tenant — so a wrong or empty tenant here either hides a tenant's own sandbox
// from them or, worse, shows it to somebody else.

func TestLiveScope_CarriesCallerTenantAndMission(t *testing.T) {
	missionID := types.NewID()
	h := &DefaultAgentHarness{missionCtx: MissionContext{
		ID:           missionID,
		MissionRunID: "run-77",
	}}

	got := h.liveScope(auth.ContextWithTenantString(context.Background(), "tenant-acme"))

	if got.Tenant != "tenant-acme" {
		t.Errorf("Tenant = %q, want the CALLER's tenant tenant-acme", got.Tenant)
	}
	if got.MissionID != missionID.String() {
		t.Errorf("MissionID = %q, want %q", got.MissionID, missionID.String())
	}
	if got.MissionRunID != "run-77" {
		t.Errorf("MissionRunID = %q, want run-77", got.MissionRunID)
	}
}

// A context with no tenant yields an empty tenant rather than a stale or
// borrowed one. The console registry treats "" as unregisterable, so the
// sandbox is invisible — the safe direction. Silently substituting any other
// tenant would publish one caller's sandbox onto another's console.
func TestLiveScope_NoTenantInContextIsEmptyNotBorrowed(t *testing.T) {
	h := &DefaultAgentHarness{missionCtx: MissionContext{
		ID:           types.NewID(),
		MissionRunID: "run-77",
	}}

	if got := h.liveScope(context.Background()); got.Tenant != "" {
		t.Errorf("Tenant = %q, want empty when the context carries no tenant", got.Tenant)
	}
}
