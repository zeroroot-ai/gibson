// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/grpc"

	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	"github.com/zeroroot-ai/gibson/internal/platform/capabilitygrant"
	"github.com/zeroroot-ai/gibson/internal/platform/incidentreport"
	"github.com/zeroroot-ai/gibson/internal/server/daemon/api"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

// registerIncidentReport registers gibson.tenant.v1.IncidentReportService
// (ADR-0180, gibson#1480). It reads the graph of the tenant through the
// data-plane pool, the Timeline of the tenant through the brain registry, and
// the grants from the platform database. The tenant comes from the context of
// each call.
func (d *daemonImpl) registerIncidentReport(ctx context.Context, srv *grpc.Server) error {
	if d.brainRegistry == nil {
		return errors.New("daemon: IncidentReportService needs the brain registry")
	}
	if d.platformDB == nil {
		return errors.New("daemon: IncidentReportService needs the platform database")
	}
	reader, err := incidentreport.NewReader(
		incidentreport.PoolGraph{Pool: func() datapool.Pool { return d.pool }},
		incidentreport.BrainHistory{Registry: d.brainRegistry},
		incidentreport.StoreGrants{Source: capabilitygrant.NewCapabilityGrantStore(d.platformDB)},
	)
	if err != nil {
		return fmt.Errorf("daemon: IncidentReportService: %w", err)
	}
	tenantv1.RegisterIncidentReportServiceServer(srv, api.NewIncidentReportService(reader))
	d.logger.Info(ctx, "IncidentReportService registered (ADR-0180)")
	return nil
}
