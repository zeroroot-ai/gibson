// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"

	"google.golang.org/grpc"

	"github.com/zeroroot-ai/gibson/internal/server/daemon/api"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

// registerOntologyExtension registers gibson.tenant.v1.OntologyExtensionService
// on srv (ADR-0024 §2, ADR-0033 decisions 2-3, gibson#392; decision 2's
// "submit upstream" arrow, gibson#393): the tenant owner's review of
// agent-proposed Taxonomy extensions, plus rendering an already-live one as
// an SDK pack contribution. The service submits OntologyExtensionApproved/
// Rejected events onto the caller's tenant brain.Engine via d.brainRegistry —
// the SAME per-tenant registry registerDomainPack and WorldService
// read/write, so an approved proposal's promotion is visible to every other
// daemon surface immediately. SubmitOntologyExtensionUpstream submits no
// event; it only reads that same per-tenant state.
//
// d.brainRegistry must already be constructed by the time this runs — it is
// built earlier in the WorldService registration block (grpc.go), the same
// precondition registerDomainPack relies on. Mirrors registerDomainPack's
// shape exactly, minus the platform-catalog gate: an ontology proposal is
// per-tenant agent-discovered content, not shipped catalog content, so no
// CatalogGate applies here.
func (d *daemonImpl) registerOntologyExtension(ctx context.Context, srv *grpc.Server) {
	if d.brainRegistry == nil {
		d.logger.Warn(ctx, "OntologyExtensionService: no brain registry; not registering")
		return
	}
	tenantv1.RegisterOntologyExtensionServiceServer(srv, api.NewOntologyExtensionService(d.brainRegistry))
	d.logger.Info(ctx, "OntologyExtensionService registered (ADR-0033, gibson#392)")
}
