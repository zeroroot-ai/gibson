// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	worldpb "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/world/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// TestGetReputation_TenantScoped proves GetReputation reads the caller's own
// tenant's reputation and refuses a request with no tenant in context — the
// same tenant-isolation contract every other WorldService RPC holds
// (TestGetCalibration_TenantScoped).
func TestGetReputation_TenantScoped(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx)
	srv := NewWorldServer(reg, nil)

	acme := reg.For("acme")
	acme.Submit(brain.BetSettledTrue{HypothesisID: "h1", Technique: "T1190", ScopeID: "net-a"})

	// Settlement folds asynchronously (ADR-0001): wait for it to land before
	// aggregating it.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && len(acme.BetSettlements()) == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	if len(acme.BetSettlements()) == 0 {
		t.Fatal("settlement never landed")
	}

	// UpdateReputation is not yet wired to run automatically when a bet
	// settles (that live trigger is separate, still-to-be-designed work); a
	// caller that already holds the Engine and a substrate -- exactly what
	// that future trigger will look like -- calls it directly, same as
	// Engine.Calibration's own substrate convention.
	substrate := brain.NewWorldBeliefSubstrate(acme)
	if _, err := acme.UpdateReputation(context.Background(), "T1190", "net-a", substrate); err != nil {
		t.Fatalf("UpdateReputation: %v", err)
	}

	tctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))

	// SetBelief is itself async (WorldBeliefSubstrate.SetBelief submits a
	// NodeBeliefSet event, processed on the next tick), so poll the RPC
	// itself -- the same idiom TestGetCalibration_TenantScoped uses.
	var resp *worldpb.GetReputationResponse
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		var err error
		if resp, err = srv.GetReputation(tctx, &worldpb.GetReputationRequest{Technique: "T1190", ScopeId: "net-a"}); err != nil {
			t.Fatalf("GetReputation: %v", err)
		}
		if resp.GetHasTrackRecord() {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !resp.GetHasTrackRecord() {
		t.Fatal("expected a track record for acme")
	}
	if resp.GetPriorStrength() != 1.0 {
		t.Fatalf("prior_strength = %v, want 1.0", resp.GetPriorStrength())
	}

	// A different tenant querying the exact same technique/scope key must
	// see no track record -- proof this reads through the caller's own
	// engine, never another tenant's.
	gctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("globex"))
	gresp, err := srv.GetReputation(gctx, &worldpb.GetReputationRequest{Technique: "T1190", ScopeId: "net-a"})
	if err != nil {
		t.Fatalf("GetReputation (globex): %v", err)
	}
	if gresp.GetHasTrackRecord() {
		t.Fatal("globex must not see acme's reputation")
	}

	if _, err := srv.GetReputation(context.Background(), &worldpb.GetReputationRequest{Technique: "T1190", ScopeId: "net-a"}); err == nil {
		t.Fatal("expected an error when no tenant is in context")
	}
}

// TestGetReputation_NoTrackRecord_ReturnsNeutralPrior proves a technique x
// environment key nothing has settled yet reports has_track_record=false
// with the neutral DefaultReputationPrior, never a bare zero.
func TestGetReputation_NoTrackRecord_ReturnsNeutralPrior(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx)
	srv := NewWorldServer(reg, nil)

	tctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))
	resp, err := srv.GetReputation(tctx, &worldpb.GetReputationRequest{Technique: "never-seen", ScopeId: "net-a"})
	if err != nil {
		t.Fatalf("GetReputation: %v", err)
	}
	if resp.GetHasTrackRecord() {
		t.Fatal("expected no track record")
	}
	if resp.GetPriorStrength() != brain.DefaultReputationPrior {
		t.Fatalf("prior_strength = %v, want the neutral default %v", resp.GetPriorStrength(), brain.DefaultReputationPrior)
	}
}
