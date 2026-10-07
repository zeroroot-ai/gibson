// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/brain/braintest"
	worldpb "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/world/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// TestGetCalibration_TenantScoped proves GetCalibration reads the caller's own
// tenant's settled bets and refuses a request with no tenant in context — the
// same tenant-isolation contract every other WorldService RPC holds
// (TestWorldService_TenantScopedRead).
func TestGetCalibration_TenantScoped(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx, braintest.StoreFactory())
	srv := NewWorldServer(reg, nil)

	reg.For("acme").Submit(brain.BetSettledTrue{HypothesisID: "h1", Technique: "sqli"})

	tctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))
	var resp *worldpb.GetCalibrationResponse
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		var err error
		if resp, err = srv.GetCalibration(tctx, &worldpb.GetCalibrationRequest{}); err != nil {
			t.Fatalf("GetCalibration: %v", err)
		}
		if resp.GetUnscored() == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if resp.GetTenant() != "acme" {
		t.Fatalf("Tenant = %q, want acme", resp.GetTenant())
	}
	// WorldBeliefSubstrate does not back Claim nodes yet (see the handler's
	// doc comment) — a settled bet with no live predicted-probability read
	// path is honestly Unscored, not silently defaulted, until that lands.
	if resp.GetUnscored() != 1 {
		t.Fatalf("Unscored = %d, want 1 (no claim-node belief substrate wired yet)", resp.GetUnscored())
	}
	if resp.GetOverall().GetN() != 0 {
		t.Fatalf("Overall.N = %d, want 0 (the unscored settlement contributes nothing)", resp.GetOverall().GetN())
	}

	// No tenant in context -> an error (PermissionDenied), never another
	// tenant's data.
	if _, err := srv.GetCalibration(context.Background(), &worldpb.GetCalibrationRequest{}); err == nil {
		t.Fatal("expected an error when no tenant is in context")
	}
}

// TestGetCalibration_ReturnsWellFormedEmptyReport proves a tenant with no
// settled bets yet gets a valid, empty (not nil, not an error) report — the
// dashboard's reliability diagram should render an empty state, not crash.
func TestGetCalibration_ReturnsWellFormedEmptyReport(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx, braintest.StoreFactory())
	srv := NewWorldServer(reg, nil)

	tctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))
	resp, err := srv.GetCalibration(tctx, &worldpb.GetCalibrationRequest{})
	if err != nil {
		t.Fatalf("GetCalibration: %v", err)
	}
	if resp.GetTenant() != "acme" || resp.GetUnscored() != 0 || len(resp.GetByTechnique()) != 0 {
		t.Fatalf("resp = %+v, want an empty-but-well-formed report for acme", resp)
	}
	if resp.GetOverall() == nil {
		t.Fatal("Overall must never be nil, even with zero settled bets")
	}
	if got := len(resp.GetOverall().GetBins()); got != brain.DefaultCalibrationBins {
		t.Fatalf("got %d bins, want the default %d", got, brain.DefaultCalibrationBins)
	}
}

// TestGetCalibration_BinsOverride proves the request's bins field reaches
// brain.ComputeCalibration — a non-default resolution actually changes the
// number of bins returned.
func TestGetCalibration_BinsOverride(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx, braintest.StoreFactory())
	srv := NewWorldServer(reg, nil)

	tctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))
	resp, err := srv.GetCalibration(tctx, &worldpb.GetCalibrationRequest{Bins: 4})
	if err != nil {
		t.Fatalf("GetCalibration: %v", err)
	}
	if got := len(resp.GetOverall().GetBins()); got != 4 {
		t.Fatalf("got %d bins, want the requested 4", got)
	}
}
