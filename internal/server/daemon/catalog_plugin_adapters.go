// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"

	"google.golang.org/grpc"

	"github.com/zeroroot-ai/gibson/internal/platform/catalogplugin"
	"github.com/zeroroot-ai/gibson/internal/server/daemon/api"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

// registerCatalogPlugin registers CatalogPluginService (gibson#815): the API a
// tenant uses to enable a plugin of the platform catalog. The service needs
// the catalog gate (d.authorizer) and the platform database. Without the
// authorizer it is not registered — Unimplemented, never a fail-open catalog.
func (d *daemonImpl) registerCatalogPlugin(ctx context.Context, srv *grpc.Server) {
	if d.authorizer == nil {
		d.logger.Warn(ctx, "CatalogPluginService: no authorizer; not registering")
		return
	}
	tenantv1.RegisterCatalogPluginServiceServer(srv,
		api.NewCatalogPluginService(catalogplugin.NewStore(d.platformDB), d.authorizer))
	d.logger.Info(ctx, "CatalogPluginService registered (gibson#815)")
}
