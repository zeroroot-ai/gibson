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

// TestGetReputation_ReturnsTheTrackRecord proves the response carries the
// two measures the dashboard track-record panel reads (gibson#619): the
// prior strength and whether a track record exists.
func TestGetReputation_ReturnsTheTrackRecord(t *testing.T) {
	// The registry comes from the world view helper, so this test follows
	// any change to how a test registry is built.
	_, reg := newWorldViewTestSource(t)
	srv := NewWorldServer(reg, nil)

	acme := reg.For("acme")
	acme.Submit(brain.BetSettledTrue{HypothesisID: "h1", Technique: "T1190", ScopeID: "net-a"})
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && len(acme.BetSettlements()) == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	if len(acme.BetSettlements()) == 0 {
		t.Fatal("settlement never landed")
	}
	substrate := brain.NewWorldBeliefSubstrate(acme)
	if _, err := acme.UpdateReputation(context.Background(), "T1190", "net-a", substrate); err != nil {
		t.Fatalf("UpdateReputation: %v", err)
	}

	tctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))
	var resp *worldpb.GetReputationResponse
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		var err error
		resp, err = srv.GetReputation(tctx, &worldpb.GetReputationRequest{Technique: "T1190", ScopeId: "net-a"})
		if err != nil {
			t.Fatalf("GetReputation: %v", err)
		}
		if resp.GetHasRecord() {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !resp.GetHasRecord() {
		t.Fatal("has_record = false, want true after a settled bet")
	}
	if resp.GetPrior() != 1.0 {
		t.Fatalf("prior = %v, want 1.0", resp.GetPrior())
	}
}

// TestGetReputation_NoTrackRecordReturnsTheNeutralPrior proves a key with
// no settled bet returns has_record false and the neutral prior,
// never a bare zero.
func TestGetReputation_NoTrackRecordReturnsTheNeutralPrior(t *testing.T) {
	_, reg := newWorldViewTestSource(t)
	srv := NewWorldServer(reg, nil)

	tctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))
	resp, err := srv.GetReputation(tctx, &worldpb.GetReputationRequest{Technique: "never-seen", ScopeId: "net-a"})
	if err != nil {
		t.Fatalf("GetReputation: %v", err)
	}
	if resp.GetHasRecord() {
		t.Fatal("has_record = true, want false")
	}
	if resp.GetPrior() != brain.DefaultReputationPrior {
		t.Fatalf("prior = %v, want %v", resp.GetPrior(), brain.DefaultReputationPrior)
	}
}
