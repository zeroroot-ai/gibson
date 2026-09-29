// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/zeroroot-ai/gibson/internal/engine/ontology"
	"github.com/zeroroot-ai/gibson/internal/infra/reconciler"
	"github.com/zeroroot-ai/gibson/internal/platform/authz"
)

// seedDomainPackCatalogGate feeds the Domain Pack catalog to the platform
// catalog-gate converge (ADR-0033, gibson#381), the same generalized
// reconciler.SeedComponentCatalogGate the connector/agent/tool/plugin
// catalogs use. Unlike seedComponentCatalogGate, no supply-chain image
// verification runs first: a Domain Pack is data (taxonomy/ontology/CEL
// predicate text), never an executable image, so there is no image signature
// to verify (ADR-0033 decision 1's "safe by construction" — a Pack's blast
// radius is bounded by DomainPack.Validate, not by an image digest).
//
// Split from Start so the ref collection and the converge call are directly
// testable, mirroring seedComponentCatalogGate.
func seedDomainPackCatalogGate(
	ctx context.Context,
	authorizer authz.Authorizer,
	catalog *ontology.DomainPackCatalog,
	logger *slog.Logger,
) error {
	packs := catalog.List()
	refs := make([]reconciler.CatalogRef, 0, len(packs))
	for _, p := range packs {
		refs = append(refs, reconciler.CatalogRef{Kind: authz.KindDomainPack, ID: p.Name})
	}
	if err := reconciler.SeedComponentCatalogGate(ctx, authorizer, refs, logger); err != nil {
		return fmt.Errorf("daemon: domain pack catalog gate: %w", err)
	}
	return nil
}
