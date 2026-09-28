// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/sdk/auth"
)

// awaitBelief polls sub for ref's belief under ctx's tenant until it matches
// want, or fails the test — brain.WorldBeliefSubstrate.SetBelief is async
// (it Submits an event for the next tick, node_belief.go), the same
// Submit/tick pattern every other brain write in this package uses.
func awaitBelief(ctx context.Context, t *testing.T, sub brain.BeliefSubstrate, ref brain.NodeRef, want float64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		nb, ok, err := sub.Belief(ctx, ref)
		if err != nil {
			t.Fatalf("Belief: %v", err)
		}
		if ok && nb.Belief.Exploitable == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("belief for %+v never reached %v within the deadline", ref, want)
}

// TestTenantRoutedBeliefSubstrate_RoutesEachCallByContextTenant proves a
// single adapter (the one value wired onto HarnessCallbackService for every
// tenant's PlaceBet calls, ADR-0022) resolves the caller's tenant from ctx
// and writes/reads through that tenant's own WorldBeliefSubstrate — so two
// tenants' PlaceBet calls never collide, and never reach the wrong World.
func TestTenantRoutedBeliefSubstrate_RoutesEachCallByContextTenant(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	registry := brain.NewRegistry(ctx)
	sub := newTenantRoutedBeliefSubstrate(registry)

	ref := brain.NodeRef{Kind: brain.NodeKindClaim, ID: "shared-id"} // same ref, two tenants
	acmeCtx := auth.ContextWithTenantString(context.Background(), "acme")
	globexCtx := auth.ContextWithTenantString(context.Background(), "globex")

	if err := sub.SetBelief(acmeCtx, ref, brain.NodeBelief{Belief: brain.Belief{Exploitable: 0.9}}); err != nil {
		t.Fatalf("SetBelief acme: %v", err)
	}
	if err := sub.SetBelief(globexCtx, ref, brain.NodeBelief{Belief: brain.Belief{Exploitable: 0.1}}); err != nil {
		t.Fatalf("SetBelief globex: %v", err)
	}

	awaitBelief(acmeCtx, t, sub, ref, 0.9)
	awaitBelief(globexCtx, t, sub, ref, 0.1)
}

// TestTenantRoutedBeliefSubstrate_NoTenantInContext_Errors proves both
// methods fail closed — never a silent default tenant — when ctx carries
// none, the same "no tenant in context" refusal world_service.go's engine(ctx)
// gives.
func TestTenantRoutedBeliefSubstrate_NoTenantInContext_Errors(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	registry := brain.NewRegistry(ctx)
	sub := newTenantRoutedBeliefSubstrate(registry)
	ref := brain.NodeRef{Kind: brain.NodeKindClaim, ID: "x"}

	if _, _, err := sub.Belief(context.Background(), ref); err == nil {
		t.Fatal("Belief: expected an error with no tenant in context")
	}
	if err := sub.SetBelief(context.Background(), ref, brain.NodeBelief{}); err == nil {
		t.Fatal("SetBelief: expected an error with no tenant in context")
	}
}

var _ brain.BeliefSubstrate = (*tenantRoutedBeliefSubstrate)(nil)
