// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/harness"
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
// tenant's PlaceBet calls, ADR-0122) resolves the caller's tenant from ctx
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

// TestTenantRoutedBeliefSubstrate_WrapsDelegateErrors proves Belief/SetBelief
// wrap the underlying WorldBeliefSubstrate's error rather than returning it
// bare (wrapcheck) — errors.Is/As must still see through to it. An empty
// NodeRef is a genuine caller error WorldBeliefSubstrate itself rejects
// (belief_world_substrate.go), not an injected fake, so this exercises the
// real error path.
func TestTenantRoutedBeliefSubstrate_WrapsDelegateErrors(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	registry := brain.NewRegistry(ctx)
	sub := newTenantRoutedBeliefSubstrate(registry)
	acmeCtx := auth.ContextWithTenantString(context.Background(), "acme")

	_, _, err := sub.Belief(acmeCtx, brain.NodeRef{})
	if err == nil {
		t.Fatal("Belief: expected an error for an empty NodeRef")
	}
	if !strings.Contains(err.Error(), "belief substrate:") {
		t.Fatalf("Belief error = %q, want it wrapped with the belief-substrate context", err.Error())
	}

	if err := sub.SetBelief(acmeCtx, brain.NodeRef{}, brain.NodeBelief{}); err == nil {
		t.Fatal("SetBelief: expected an error for an empty NodeRef")
	} else if !strings.Contains(err.Error(), "belief substrate:") {
		t.Fatalf("SetBelief error = %q, want it wrapped with the belief-substrate context", err.Error())
	}
}

// TestWirePlaceBetBeliefSubstrate proves the daemon.go Start() glue reaches
// the callback manager: wirePlaceBetBeliefSubstrate is extracted into its own
// function (belief_substrate_adapter.go) specifically so this step is
// testable independent of Start()'s much larger bootstrap sequence, the same
// reason wireBrainRegistry (belief_provider.go) is its own function.
func TestWirePlaceBetBeliefSubstrate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	registry := brain.NewRegistry(ctx)
	callback := harness.NewCallbackManager(harness.CallbackConfig{ListenAddress: "127.0.0.1:0"}, slog.Default())

	wirePlaceBetBeliefSubstrate(callback, registry)

	got := callback.BeliefSubstrate()
	if got == nil {
		t.Fatal("wirePlaceBetBeliefSubstrate must set a non-nil belief substrate")
	}
	if _, ok := got.(*tenantRoutedBeliefSubstrate); !ok {
		t.Fatalf("belief substrate = %T, want *tenantRoutedBeliefSubstrate", got)
	}
}

var _ brain.BeliefSubstrate = (*tenantRoutedBeliefSubstrate)(nil)
