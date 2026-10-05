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
	"github.com/zeroroot-ai/gibson/internal/engine/taxonomy"
	"github.com/zeroroot-ai/sdk/auth"
)

// tenantRoutedOntologyDiscovery implements brain.OntologyDiscoveryEngine for
// HarnessCallbackService.ProposeOntologyExtension (ADR-0124, ADR-0133,
// gibson#391), mirroring tenantRoutedProofSettlement
// (proof_settlement_adapter.go) exactly and for the same reason:
// ProposeOntologyExtension wires ONE OntologyDiscoveryEngine value shared
// across every tenant's calls, but *brain.Engine (and the
// ProposeOntologyExtension/OntologyProposals methods it already exposes) is
// bound to a single tenant's World. This adapter resolves the caller's
// tenant from ctx (auth.TenantFromContext, the same mechanism the belief
// substrate and proof settlement adapters already use) and delegates to
// that tenant's own Engine, so two tenants' proposed labels and recurrence
// counts never collide.
type tenantRoutedOntologyDiscovery struct {
	registry *brain.Registry
}

// newTenantRoutedOntologyDiscovery builds the adapter over registry — the
// same per-tenant engine registry wireBrainRegistry installs the
// belief/VoI/proof-settlement pipelines onto.
func newTenantRoutedOntologyDiscovery(registry *brain.Registry) *tenantRoutedOntologyDiscovery {
	return &tenantRoutedOntologyDiscovery{registry: registry}
}

// ProposeOntologyExtension implements brain.OntologyDiscoveryEngine by
// resolving ctx's tenant and delegating to that tenant's own
// Engine.ProposeOntologyExtension. Fails closed (never a silent default
// tenant) when ctx carries none — the same guard
// tenantRoutedProofSettlement.forTenant enforces.
func (s *tenantRoutedOntologyDiscovery) ProposeOntologyExtension(
	ctx context.Context, kind taxonomy.ProposalKind, label, proposer, claim string,
) error {
	tenant, ok := auth.TenantFromContext(ctx)
	if !ok {
		return status.Error(codes.PermissionDenied, "no tenant in context")
	}
	if err := s.registry.For(tenant.String()).ProposeOntologyExtension(ctx, kind, label, proposer, claim); err != nil {
		return fmt.Errorf("propose ontology extension: %w", err)
	}
	return nil
}

var _ brain.OntologyDiscoveryEngine = (*tenantRoutedOntologyDiscovery)(nil)

// wireOntologyDiscovery wires ProposeOntologyExtension's ontology-discovery
// engine onto callback (ADR-0124, ADR-0133, gibson#391): before
// this, ProposeOntologyExtension always answered Unavailable — no daemon
// ever gave it an engine to fold the proposal through ValidIdentifier and
// PromotionGate.Observe. Extracted from daemon.go's Start() into its own
// function for the same reason wireProofSettlement
// (proof_settlement_adapter.go) is its own function: unit-testable
// independent of Start()'s much larger bootstrap sequence.
func wireOntologyDiscovery(callback *harness.CallbackManager, registry *brain.Registry) {
	callback.SetOntologyDiscovery(newTenantRoutedOntologyDiscovery(registry))
}
