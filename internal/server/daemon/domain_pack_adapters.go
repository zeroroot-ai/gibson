// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"fmt"
	"github.com/zeroroot-ai/gibson/internal/platform/audit/compliance"

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
// newInfrastructure builds domainPackCatalog). The daemon cannot start
// without the authorizer or the platform database, so a missing one is an
// error, and never a service that is silently Unimplemented.
func (d *daemonImpl) registerDomainPack(ctx context.Context, srv *grpc.Server) error {
	if d.authorizer == nil {
		return errors.New("daemon: DomainPackService needs the authorizer")
	}
	if d.brainRegistry == nil {
		return errors.New("daemon: DomainPackService needs the brain registry")
	}
	if d.domainPackCatalog == nil {
		d.domainPackCatalog = ontology.EmbeddedCatalog()
	}
	imports, err := ontology.NewImportStore(d.platformDB)
	if err != nil {
		return fmt.Errorf("daemon: DomainPackService: %w", err)
	}
	tenantv1.RegisterDomainPackServiceServer(srv,
		api.NewDomainPackService(d.brainRegistry, d.domainPackCatalog, d.authorizer, imports))
	d.logger.Info(ctx, "DomainPackService registered (ADR-0133)")

	// ComplianceService reads the same catalog and the same Worlds: a
	// framework pack is a Domain Pack, and the reader needs the packs that a
	// tenant enabled (ADR-0113, gibson#674). The audit log is in the
	// platform database.
	reader, err := compliance.NewReader(d.platformDB, d.domainPackCatalog, api.BrainEnabledPacks{Registry: d.brainRegistry})
	if err != nil {
		return fmt.Errorf("daemon: ComplianceService: %w", err)
	}
	tenantv1.RegisterComplianceServiceServer(srv, api.NewComplianceService(reader))
	d.logger.Info(ctx, "ComplianceService registered (ADR-0113)")
	return nil
}
