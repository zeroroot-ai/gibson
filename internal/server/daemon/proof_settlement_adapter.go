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
	"github.com/zeroroot-ai/gibson/internal/engine/settlement"
	"github.com/zeroroot-ai/sdk/auth"
)

// tenantRoutedProofSettlement implements brain.ProofSettlementEngine for
// HarnessCallbackService.SubmitProof (ADR-0030, ADR-0031, gibson#389),
// mirroring tenantRoutedBeliefSubstrate (belief_substrate_adapter.go)
// exactly and for the same reason: SubmitProof wires ONE ProofSettlementEngine
// value shared across every tenant's calls, but *brain.Engine (and the
// DomainPacks/SettleBetTrue methods it already exposes) is bound to a single
// tenant's World. This adapter resolves the caller's tenant from ctx
// (auth.TenantFromContext, the same mechanism world_service.go's engine(ctx)
// and the belief substrate adapter already use) and delegates to that
// tenant's own Engine, so two tenants' Domain Packs and bets never collide
// and a call never reaches the wrong World.
type tenantRoutedProofSettlement struct {
	registry *brain.Registry
}

// newTenantRoutedProofSettlement builds the adapter over registry — the same
// per-tenant engine registry wireBrainRegistry installs the belief/VoI
// pipelines onto.
func newTenantRoutedProofSettlement(registry *brain.Registry) *tenantRoutedProofSettlement {
	return &tenantRoutedProofSettlement{registry: registry}
}

// forTenant resolves ctx's tenant and returns that tenant's own *brain.Engine.
// Fails closed (never a silent default tenant) when ctx carries none.
func (s *tenantRoutedProofSettlement) forTenant(ctx context.Context) (*brain.Engine, error) {
	tenant, ok := auth.TenantFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.PermissionDenied, "no tenant in context")
	}
	return s.registry.For(tenant.String()), nil
}

// DomainPackPredicate implements brain.ProofSettlementEngine. It searches
// ctx's tenant's currently enabled Domain Packs for predicateName, the same
// per-technique-identifier lookup World.DomainPackPredicate performs for a
// direct in-process reader, via the Engine's own read-locked DomainPacks
// accessor (safe to call concurrently with that tenant's tick loop).
func (s *tenantRoutedProofSettlement) DomainPackPredicate(ctx context.Context, predicateName string) (string, bool, error) {
	e, err := s.forTenant(ctx)
	if err != nil {
		return "", false, err
	}
	for _, pack := range e.DomainPacks() {
		if expr, ok := pack.Predicates[predicateName]; ok {
			return expr, true, nil
		}
	}
	return "", false, nil
}

// SettleBetTrue implements brain.ProofSettlementEngine by delegating to ctx's
// tenant's own Engine.SettleBetTrue.
func (s *tenantRoutedProofSettlement) SettleBetTrue(
	ctx context.Context, registry *settlement.Registry, authorize brain.DestructiveProofAuthorizer, req brain.BetSettlementRequest,
) (bool, error) {
	e, err := s.forTenant(ctx)
	if err != nil {
		return false, err
	}
	settled, err := e.SettleBetTrue(ctx, registry, authorize, req)
	if err != nil {
		return false, fmt.Errorf("proof settlement: %w", err)
	}
	return settled, nil
}

// wireProofSettlement wires SubmitProof's proof-settlement engine onto
// callback (ADR-0030, ADR-0031, gibson#389): before this, SubmitProof always
// answered Unavailable — no daemon ever gave it an engine to resolve pack
// predicates and settle bets against. Extracted from daemon.go's Start()
// into its own function for the same reason wirePlaceBetBeliefSubstrate
// (belief_substrate_adapter.go) is its own function: unit-testable
// independent of Start()'s much larger bootstrap sequence.
func wireProofSettlement(callback *harness.CallbackManager, registry *brain.Registry) {
	callback.SetProofSettlement(newTenantRoutedProofSettlement(registry))
}
