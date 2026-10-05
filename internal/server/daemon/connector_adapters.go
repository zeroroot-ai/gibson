// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"fmt"

	"google.golang.org/grpc"

	"github.com/zeroroot-ai/gibson/internal/platform/tenantconnector"
	discoverysvc "github.com/zeroroot-ai/gibson/internal/server/api/discovery"
	"github.com/zeroroot-ai/gibson/internal/server/daemon/api"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

// registerConnector registers gibson.tenant.v1.ConnectorService on srv. The
// service records the connectors each tenant wants in the platform database.
// The connector operator pulls them and makes the ConnectorInstances
// (ADR-0114, gibson#662). The daemon makes no Kubernetes call for it.
func (d *daemonImpl) registerConnector(ctx context.Context, srv *grpc.Server) {
	// The platform catalog gate (ADR-0067) needs the authorizer. Without one
	// the service is not registered — Unimplemented, never a fail-open
	// catalog.
	if d.authorizer == nil {
		d.logger.Warn(ctx, "ConnectorService: no authorizer; not registering")
		return
	}
	tenantv1.RegisterConnectorServiceServer(srv,
		api.NewConnectorService(tenantconnector.NewStore(d.platformDB), d.authorizer))
	d.logger.Info(ctx, "ConnectorService registered (ADR-0114)")
}

// tenantConnectorLister adapts the tenant connector store to
// discovery.ConnectorLister (ADR-0067): the tenant's enabled connectors are
// the rows of tenant_connectors, keyed by catalog id.
type tenantConnectorLister struct {
	store interface {
		List(ctx context.Context, tenantID string) ([]tenantconnector.Connector, error)
	}
}

func (l *tenantConnectorLister) ListEnabledConnectors(ctx context.Context, tenant string) ([]string, error) {
	rows, err := l.store.List(ctx, tenant)
	if err != nil {
		return nil, fmt.Errorf("list enabled connectors: %w", err)
	}
	ids := make([]string, 0, len(rows))
	for _, r := range rows {
		ids = append(ids, r.ConnectorID)
	}
	return ids, nil
}

// connectorLister returns the discovery ConnectorLister over the platform
// database.
func (d *daemonImpl) connectorLister(_ context.Context) discoverysvc.ConnectorLister {
	return &tenantConnectorLister{store: tenantconnector.NewStore(d.platformDB)}
}
