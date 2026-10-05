// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/harness"
	"github.com/zeroroot-ai/sdk/auth"
)

// tenantRoutedBeliefSubstrate implements brain.BeliefSubstrate for
// HarnessCallbackService.PlaceBet (ADR-0122, gibson#273/#278). PlaceBet
// wires ONE BeliefSubstrate value shared across every tenant's calls, but
// brain.WorldBeliefSubstrate is bound to a single *brain.Engine — one
// tenant's World. This adapter closes that gap: it resolves the caller's
// tenant from ctx (auth.TenantFromContext, the same mechanism
// world_service.go's engine(ctx) already uses) and delegates to that
// tenant's own WorldBeliefSubstrate, so two tenants' bets never collide and
// a call never reaches the wrong World. PlaceBet itself does no tenant
// derivation of its own for this: getHarness already required and
// validated ctx's tenant against the mission before PlaceBet runs, so the
// same ctx flowing through here already carries the right one.
type tenantRoutedBeliefSubstrate struct {
	registry *brain.Registry
}

// newTenantRoutedBeliefSubstrate builds the adapter over registry — the same
// per-tenant engine registry wireBrainRegistry installs the belief/VoI
// pipelines onto.
func newTenantRoutedBeliefSubstrate(registry *brain.Registry) *tenantRoutedBeliefSubstrate {
	return &tenantRoutedBeliefSubstrate{registry: registry}
}

// forTenant resolves ctx's tenant and returns that tenant's own
// WorldBeliefSubstrate. Fails closed (never a silent default tenant) when
// ctx carries none.
func (s *tenantRoutedBeliefSubstrate) forTenant(ctx context.Context) (brain.BeliefSubstrate, error) {
	tenant, ok := auth.TenantFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.PermissionDenied, "no tenant in context")
	}
	return brain.NewWorldBeliefSubstrate(s.registry.For(tenant.String())), nil
}

// Belief implements brain.BeliefSubstrate.
func (s *tenantRoutedBeliefSubstrate) Belief(ctx context.Context, ref brain.NodeRef) (brain.NodeBelief, bool, error) {
	sub, err := s.forTenant(ctx)
	if err != nil {
		return brain.NodeBelief{}, false, err
	}
	nb, ok, err := sub.Belief(ctx, ref)
	if err != nil {
		return brain.NodeBelief{}, false, fmt.Errorf("belief substrate: %w", err)
	}
	return nb, ok, nil
}

// SetBelief implements brain.BeliefSubstrate.
func (s *tenantRoutedBeliefSubstrate) SetBelief(ctx context.Context, ref brain.NodeRef, nb brain.NodeBelief) error {
	sub, err := s.forTenant(ctx)
	if err != nil {
		return err
	}
	if err := sub.SetBelief(ctx, ref, nb); err != nil {
		return fmt.Errorf("belief substrate: %w", err)
	}
	return nil
}

// wirePlaceBetBeliefSubstrate wires PlaceBet's belief substrate onto callback
// (ADR-0122, ADR-0129, gibson#273/#278): before this, PlaceBet always
// answered Unavailable — no daemon ever gave it a substrate to persist a
// staked bet to. Extracted from daemon.go's Start() into its own function so
// this wiring step is unit-testable independent of Start()'s much larger
// bootstrap sequence — the same reason wireBrainRegistry (belief_provider.go)
// is its own function.
func wirePlaceBetBeliefSubstrate(callback *harness.CallbackManager, registry *brain.Registry) {
	callback.SetBeliefSubstrate(newTenantRoutedBeliefSubstrate(registry))
}
