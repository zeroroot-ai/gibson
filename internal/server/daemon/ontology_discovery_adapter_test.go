// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/brain/braintest"
	"github.com/zeroroot-ai/gibson/internal/engine/harness"
	"github.com/zeroroot-ai/gibson/internal/engine/taxonomy"
	"github.com/zeroroot-ai/sdk/auth"
)

// awaitOntologyProposal polls e's OntologyProposals until it contains kind,
// label with the given recurrence, or fails the test —
// Engine.ProposeOntologyExtension folds OntologyExtensionProposed
// asynchronously through the normal single-writer Submit path (ADR-0101),
// the same Submit/tick pattern awaitProofSettlements already polls for.
func awaitOntologyProposal(t *testing.T, e *brain.Engine, kind taxonomy.ProposalKind, label string, wantRecurrence int) brain.OntologyProposalSnapshot {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for _, snap := range e.OntologyProposals() {
			if snap.ProposalKind == kind && snap.Label == label && snap.Recurrence == wantRecurrence {
				return snap
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("proposal (%v, %q) never reached recurrence %d within the deadline", kind, label, wantRecurrence)
	return brain.OntologyProposalSnapshot{}
}

// TestTenantRoutedOntologyDiscovery_RoutesEachCallByContextTenant proves a
// single adapter (the one value wired onto HarnessCallbackService for every
// tenant's ProposeOntologyExtension calls, gibson#391) resolves the caller's
// tenant from ctx and folds through that tenant's own Engine — so two
// tenants' proposed labels and recurrence counts never collide.
func TestTenantRoutedOntologyDiscovery_RoutesEachCallByContextTenant(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	registry := brain.NewRegistry(ctx, braintest.StoreFactory())
	disc := newTenantRoutedOntologyDiscovery(registry)

	acmeCtx := auth.ContextWithTenantString(context.Background(), "acme")
	globexCtx := auth.ContextWithTenantString(context.Background(), "globex")

	if err := disc.ProposeOntologyExtension(acmeCtx, taxonomy.ProposedNodeLabel, "CustomHost", "recon-agent", "seen it twice"); err != nil {
		t.Fatalf("ProposeOntologyExtension acme: %v", err)
	}
	if err := disc.ProposeOntologyExtension(globexCtx, taxonomy.ProposedNodeLabel, "CustomHost", "recon-agent", "seen it once"); err != nil {
		t.Fatalf("ProposeOntologyExtension globex: %v", err)
	}

	acmeEngine := registry.For("acme")
	globexEngine := registry.For("globex")
	awaitOntologyProposal(t, acmeEngine, taxonomy.ProposedNodeLabel, "CustomHost", 1)
	awaitOntologyProposal(t, globexEngine, taxonomy.ProposedNodeLabel, "CustomHost", 1)
}

// TestTenantRoutedOntologyDiscovery_NoTenantInContext_Errors proves
// ProposeOntologyExtension fails closed — never a silent default tenant —
// when ctx carries none, the same "no tenant in context" refusal
// tenantRoutedBeliefSubstrate and tenantRoutedProofSettlement give.
func TestTenantRoutedOntologyDiscovery_NoTenantInContext_Errors(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	registry := brain.NewRegistry(ctx, braintest.StoreFactory())
	disc := newTenantRoutedOntologyDiscovery(registry)

	err := disc.ProposeOntologyExtension(context.Background(), taxonomy.ProposedNodeLabel, "CustomHost", "recon-agent", "claim")
	if err == nil {
		t.Fatal("ProposeOntologyExtension: expected an error with no tenant in context")
	}
}

// TestTenantRoutedOntologyDiscovery_InvalidIdentifier_FailsClosed proves the
// adapter surfaces Engine.ProposeOntologyExtension's *taxonomy.InvalidProposalError
// unchanged, so the RPC handler can classify it and report it in-band rather
// than as an opaque error.
func TestTenantRoutedOntologyDiscovery_InvalidIdentifier_FailsClosed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	registry := brain.NewRegistry(ctx, braintest.StoreFactory())
	disc := newTenantRoutedOntologyDiscovery(registry)
	acmeCtx := auth.ContextWithTenantString(context.Background(), "acme")

	err := disc.ProposeOntologyExtension(acmeCtx, taxonomy.ProposedNodeLabel, "not valid!", "recon-agent", "claim")
	var invalid *taxonomy.InvalidProposalError
	if !errors.As(err, &invalid) {
		t.Fatalf("expected a *taxonomy.InvalidProposalError, got %v", err)
	}
}

// TestWireOntologyDiscovery proves the daemon.go Start() glue reaches the
// callback manager: wireOntologyDiscovery is extracted into its own function
// (ontology_discovery_adapter.go) specifically so this step is testable
// independent of Start()'s much larger bootstrap sequence, the same reason
// wireProofSettlement/wirePlaceBetBeliefSubstrate are their own functions.
func TestWireOntologyDiscovery(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	registry := brain.NewRegistry(ctx, braintest.StoreFactory())
	callback := harness.NewCallbackManager(harness.CallbackConfig{ListenAddress: "127.0.0.1:0"}, slog.Default())

	wireOntologyDiscovery(callback, registry)

	got := callback.OntologyDiscovery()
	if got == nil {
		t.Fatal("wireOntologyDiscovery must set a non-nil ontology discovery engine")
	}
	if _, ok := got.(*tenantRoutedOntologyDiscovery); !ok {
		t.Fatalf("ontology discovery engine = %T, want *tenantRoutedOntologyDiscovery", got)
	}
}
