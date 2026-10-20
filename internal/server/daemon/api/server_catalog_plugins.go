// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/catalogplugin"
	"github.com/zeroroot-ai/gibson/internal/platform/componentcatalog"
	"github.com/zeroroot-ai/gibson/internal/platform/pagetoken"
	daemonoperatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
)

// ListDesiredCatalogPlugins returns one page of the (tenant, catalog plugin) pairs a
// tenant enabled (gibson#815). The tenant-operator pulls it and runs one
// instance of the plugin for each pair. The read spans every tenant on
// purpose, so the method policy admits the tenant-operator only.
//
// gibsoncheck:allow tenant-from-request — DaemonOperatorService: platform_operator on
// system_tenant at ext-authz, plus the SPIFFE peer allowlist.
func (s *DaemonServer) ListDesiredCatalogPlugins(
	ctx context.Context, req *daemonoperatorv1.ListDesiredCatalogPluginsRequest,
) (*daemonoperatorv1.ListDesiredCatalogPluginsResponse, error) {
	db := s.entitlementsDB()
	if db == nil {
		return nil, status.Error(codes.Unavailable, "platform Postgres not configured")
	}
	key, err := s.pageStart(pageScopeDesiredCatalogPlugins, req.GetPageToken(), 2)
	if err != nil {
		return nil, err
	}
	var after *catalogplugin.PageKey
	if key != nil {
		after = &catalogplugin.PageKey{TenantID: key[0], PluginID: key[1]}
	}
	// One more row than the page tells whether a next page exists.
	size := pagetoken.Size(req.GetPageSize())
	plugins, err := catalogplugin.NewStore(db).ListPage(ctx, after, size+1)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list desired catalog plugins: %v", err)
	}
	out := &daemonoperatorv1.ListDesiredCatalogPluginsResponse{}
	if len(plugins) > size {
		plugins = plugins[:size]
		last := plugins[size-1]
		out.NextPageToken = s.pageToken(pageScopeDesiredCatalogPlugins, last.TenantID, last.PluginID)
	}
	// The image and the egress list come from the catalog of this daemon. A
	// row whose plugin left the catalog is not desired any more: the operator
	// does not get it, and it removes the instance. A page can hold fewer
	// items than page_size, or none, and still have a next page.
	out.Plugins = make([]*daemonoperatorv1.DesiredCatalogPlugin, 0, len(plugins))
	for _, p := range plugins {
		entry, listed := componentcatalog.LookupPlugin(p.PluginID)
		if !listed {
			continue
		}
		out.Plugins = append(out.Plugins, &daemonoperatorv1.DesiredCatalogPlugin{
			TenantId:    p.TenantID,
			PluginId:    p.PluginID,
			Image:       entry.Image,
			EgressAllow: entry.EgressAllow,
		})
	}
	return out, nil
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
