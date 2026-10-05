// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"

	"google.golang.org/grpc"

	"github.com/zeroroot-ai/gibson/internal/engine/ontology"
	"github.com/zeroroot-ai/gibson/internal/server/daemon/api"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

// registerDomainPack registers gibson.tenant.v1.DomainPackService on srv
// (ADR-0133, gibson#381). The service folds DomainPackEnabled/Disabled brain
// events into the caller's tenant World via d.brainRegistry — the same
// per-tenant registry WorldService reads — gated by the platform catalog gate
// (d.authorizer), mirroring registerConnector's ADR-0067 gate.
//
// d.brainRegistry and d.domainPackCatalog must already be constructed by the
// time this runs (the WorldService registration block builds brainRegistry;
// newInfrastructure builds domainPackCatalog). Without an authorizer the
// service is not registered — Unimplemented, never a fail-open catalog.
func (d *daemonImpl) registerDomainPack(ctx context.Context, srv *grpc.Server) {
	if d.authorizer == nil {
		d.logger.Warn(ctx, "DomainPackService: no authorizer; not registering")
		return
	}
	if d.brainRegistry == nil {
		d.logger.Warn(ctx, "DomainPackService: no brain registry; not registering")
		return
	}
	if d.domainPackCatalog == nil {
		d.domainPackCatalog = ontology.NewDomainPackCatalog(ontology.MainDomainPack())
	}
	tenantv1.RegisterDomainPackServiceServer(srv, api.NewDomainPackService(d.brainRegistry, d.domainPackCatalog, d.authorizer))
	d.logger.Info(ctx, "DomainPackService registered (ADR-0133)")
}
