// Package api — tenant_admin_catalog.go implements
// TenantAdminService.ListCatalogComponents.
//
// The dashboard's deploy-wizard Permissions step and the agent / tool
// detail Permissions tab call this RPC to render catalog-aware grant
// pickers without operators typing FGA refs by hand. Read-only; no
// audit emission.
//
// Spec: component-bootstrap-dashboard-completion Requirement 1.
package api

import (
	"context"
	"log/slog"
	"strings"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	tenantpb "github.com/zero-day-ai/platform-sdk/gen/gibson/tenant/v1"
	"github.com/zero-day-ai/sdk/auth"
)

// ListCatalogComponents returns the components and plugins available
// to the caller's tenant. Caller's tenant is derived from ext-authz
// headers; the request is empty.
//
// Visibility rules:
//   - components: FGA `in_tenant_catalog` is true for the caller's tenant
//     (i.e. (platform_enabled OR tenant_published) AND tenant_enabled).
//     Implemented as ListObjects against the FGA authorizer.
//   - plugins: FGA `belongs_to` ties the plugin to a tenant. We list
//     plugins belonging to the caller's tenant. (System-tenant plugins
//     are out of scope for the MVP — they require a tenant_enabled
//     equivalent on the plugin type, which the model does not yet
//     define.)
//
// Empty catalogs return empty arrays, never error.
func (s *DaemonServer) ListCatalogComponents(ctx context.Context, req *tenantpb.ListCatalogComponentsRequest) (*tenantpb.ListCatalogComponentsResponse, error) {
	tenantID := auth.TenantStringFromContext(ctx)
	if tenantID == "" {
		return nil, status_grpc.Error(codes.PermissionDenied, "no tenant in context")
	}

	if s.authorizer == nil {
		return nil, status_grpc.Error(codes.Unavailable, "authorizer not configured")
	}

	tenantSubject := "tenant:" + tenantID

	componentRefs, err := s.authorizer.ListObjects(ctx, tenantSubject, "in_tenant_catalog", "component")
	if err != nil {
		s.logger.WarnContext(ctx, "ListCatalogComponents: component ListObjects failed; returning empty list",
			slog.String("tenant_id", tenantID),
			slog.String("error", err.Error()),
		)
		componentRefs = nil
	}

	pluginRefs, err := s.authorizer.ListObjects(ctx, tenantSubject, "belongs_to", "plugin")
	if err != nil {
		s.logger.WarnContext(ctx, "ListCatalogComponents: plugin ListObjects failed; returning empty list",
			slog.String("tenant_id", tenantID),
			slog.String("error", err.Error()),
		)
		pluginRefs = nil
	}

	resp := &tenantpb.ListCatalogComponentsResponse{
		Components: make([]*tenantpb.CatalogComponent, 0, len(componentRefs)),
		Plugins:    make([]*tenantpb.CatalogPlugin, 0, len(pluginRefs)),
	}
	for _, ref := range componentRefs {
		name := strings.TrimPrefix(ref, "component:")
		resp.Components = append(resp.Components, &tenantpb.CatalogComponent{
			Name:        name,
			Ref:         ref,
			Description: "", // populated when the component-registry projection lands
			Version:     "",
		})
	}
	for _, ref := range pluginRefs {
		name := strings.TrimPrefix(ref, "plugin:")
		resp.Plugins = append(resp.Plugins, &tenantpb.CatalogPlugin{
			Name:        name,
			Ref:         ref,
			Description: "",
			Version:     "",
		})
	}

	s.logger.InfoContext(ctx, "ListCatalogComponents: served",
		slog.String("tenant_id", tenantID),
		slog.Int("components", len(resp.Components)),
		slog.Int("plugins", len(resp.Plugins)),
	)
	return resp, nil
}
