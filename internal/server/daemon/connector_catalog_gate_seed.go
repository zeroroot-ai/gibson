// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/zeroroot-ai/gibson/internal/infra/reconciler"
	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/internal/platform/componentcatalog"
	"github.com/zeroroot-ai/gibson/internal/platform/supplychain"
)

// seedComponentCatalogGate feeds the embedded component catalog refs to the
// platform-catalog-gate converge (ADR-0015). Split from Start so the ref
// collection and the converge call are directly testable.
func seedComponentCatalogGate(
	ctx context.Context,
	authorizer authz.Authorizer,
	verifier supplychain.Verifier,
	logger *slog.Logger,
) error {
	// Verify before seeding: platform_enabled is the tuple that makes a
	// component offerable, so the signature check has to happen on the near
	// side of it (ADR-0015, gibson#1639). Components whose image does not
	// verify are dropped here and never reach the converge.
	refs, verifyErr := verifyCatalogImages(ctx, verifier, componentcatalog.Refs(), logger)
	if verifyErr != nil {
		// Loud, and it does not stop the verified components being seeded —
		// verifyCatalogImages has already excluded the ones that failed.
		logger.Error("component image verification refused one or more components", "error", verifyErr)
	}
	catalogRefs := make([]reconciler.CatalogRef, 0, len(refs))
	for _, r := range refs {
		catalogRefs = append(catalogRefs, reconciler.CatalogRef{Kind: r.Kind, ID: r.ID})
	}
	if err := reconciler.SeedComponentCatalogGate(ctx, authorizer, catalogRefs, logger); err != nil {
		return fmt.Errorf("daemon: component catalog gate: %w", err)
	}
	return verifyErr
}
