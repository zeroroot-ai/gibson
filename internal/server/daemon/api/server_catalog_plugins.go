// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/catalogplugin"
	daemonoperatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
)

// ListDesiredCatalogPlugins returns every (tenant, catalog plugin) pair a
// tenant enabled (gibson#815). The tenant-operator pulls it and runs one
// instance of the plugin for each pair. The read spans every tenant on
// purpose, so the method policy admits the tenant-operator only.
//
// gibsoncheck:allow tenant-from-request — DaemonOperatorService: platform_operator on
// system_tenant at ext-authz, plus the SPIFFE peer allowlist.
func (s *DaemonServer) ListDesiredCatalogPlugins(
	ctx context.Context, _ *daemonoperatorv1.ListDesiredCatalogPluginsRequest,
) (*daemonoperatorv1.ListDesiredCatalogPluginsResponse, error) {
	db := s.entitlementsDB()
	if db == nil {
		return nil, status.Error(codes.Unavailable, "platform Postgres not configured")
	}
	plugins, err := catalogplugin.NewStore(db).ListAll(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list desired catalog plugins: %v", err)
	}
	out := make([]*daemonoperatorv1.DesiredCatalogPlugin, 0, len(plugins))
	for _, p := range plugins {
		out = append(out, &daemonoperatorv1.DesiredCatalogPlugin{TenantId: p.TenantID, PluginId: p.PluginID})
	}
	return &daemonoperatorv1.ListDesiredCatalogPluginsResponse{Plugins: out}, nil
}

// ReportCatalogPluginStatus records the state the tenant-operator sees for one
// tenant's instance of a catalog plugin (gibson#815). A report for a pair no
// tenant enabled changes nothing and answers updated=false.
//
// gibsoncheck:allow tenant-from-request — DaemonOperatorService: platform_operator on
// system_tenant at ext-authz, plus the SPIFFE peer allowlist.
func (s *DaemonServer) ReportCatalogPluginStatus(
	ctx context.Context, req *daemonoperatorv1.ReportCatalogPluginStatusRequest,
) (*daemonoperatorv1.ReportCatalogPluginStatusResponse, error) {
	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id required")
	}
	if req.GetPluginId() == "" {
		return nil, status.Error(codes.InvalidArgument, "plugin_id required")
	}
	if req.GetPhase() == "" {
		return nil, status.Error(codes.InvalidArgument, "phase required")
	}
	db := s.entitlementsDB()
	if db == nil {
		return nil, status.Error(codes.Unavailable, "platform Postgres not configured")
	}
	updated, err := catalogplugin.NewStore(db).ReportStatus(ctx,
		req.GetTenantId(), req.GetPluginId(), req.GetPhase(), req.GetLastError())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "report catalog plugin status: %v", err)
	}
	return &daemonoperatorv1.ReportCatalogPluginStatusResponse{Updated: updated}, nil
}
