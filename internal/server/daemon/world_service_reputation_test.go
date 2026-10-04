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
	// NodeBeliefSet event, processed on the next tick), so poll the read the
	// RPC performs. The response carries no measures (gibson#502), so the
	// engine read is the observable and the RPC call proves the path.
	var (
		prior float64
		ok    bool
	)
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		var err error
		if prior, ok, err = brain.ReadReputation(context.Background(), "acme", "T1190", "net-a", substrate); err != nil {
			t.Fatalf("ReadReputation: %v", err)
		}
		if ok {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !ok {
		t.Fatal("expected a track record for acme")
	}
	if prior != 1.0 {
		t.Fatalf("prior_strength = %v, want 1.0", prior)
	}
	if _, err := srv.GetReputation(tctx, &worldpb.GetReputationRequest{Technique: "T1190", ScopeId: "net-a"}); err != nil {
		t.Fatalf("GetReputation: %v", err)
	}

	// A different tenant querying the exact same technique/scope key must
	// see no track record -- proof this reads through the caller's own
	// engine, never another tenant's.
	gctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("globex"))
	if _, err := srv.GetReputation(gctx, &worldpb.GetReputationRequest{Technique: "T1190", ScopeId: "net-a"}); err != nil {
		t.Fatalf("GetReputation (globex): %v", err)
	}
	globex := reg.For("globex")
	if _, gok, err := brain.ReadReputation(context.Background(), "globex", "T1190", "net-a", brain.NewWorldBeliefSubstrate(globex)); err != nil || gok {
		t.Fatalf("globex must not see acme's reputation: ok=%v err=%v", gok, err)
	}

	if _, err := srv.GetReputation(context.Background(), &worldpb.GetReputationRequest{Technique: "T1190", ScopeId: "net-a"}); err == nil {
		t.Fatal("expected an error when no tenant is in context")
	}
}

// TestGetReputation_NoTrackRecord_ReturnsNeutralPrior proves a technique x
// environment key nothing has settled yet reads as no track record with the
// neutral DefaultReputationPrior, never a bare zero, and that the RPC path
// over it succeeds.
func TestGetReputation_NoTrackRecord_ReturnsNeutralPrior(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx)
	srv := NewWorldServer(reg, nil)

	tctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))
	if _, err := srv.GetReputation(tctx, &worldpb.GetReputationRequest{Technique: "never-seen", ScopeId: "net-a"}); err != nil {
		t.Fatalf("GetReputation: %v", err)
	}
	acme := reg.For("acme")
	prior, ok, err := brain.ReadReputation(context.Background(), "acme", "never-seen", "net-a", brain.NewWorldBeliefSubstrate(acme))
	if err != nil {
		t.Fatalf("ReadReputation: %v", err)
	}
	if ok {
		t.Fatal("expected no track record")
	}
	if prior != brain.DefaultReputationPrior {
		t.Fatalf("prior_strength = %v, want the neutral default %v", prior, brain.DefaultReputationPrior)
	}
}
