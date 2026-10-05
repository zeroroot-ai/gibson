// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"errors"

	"github.com/zeroroot-ai/sdk/auth"
	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/internal/platform/catalogplugin"
	"github.com/zeroroot-ai/gibson/internal/platform/componentcatalog"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

// CatalogPluginStore is the slice of the catalog plugin store the service
// needs. *catalogplugin.Store satisfies it.
type CatalogPluginStore interface {
	Enable(ctx context.Context, tenantID, pluginID string) (catalogplugin.Plugin, error)
	Disable(ctx context.Context, tenantID, pluginID string) error
	List(ctx context.Context, tenantID string) ([]catalogplugin.Plugin, error)
}

// CatalogPluginService is the daemon API a tenant uses to enable a plugin of
// the platform catalog (gibson#815). It records what the tenant wants in the
// platform database and starts nothing. The tenant operator reads the desired
// state and runs one instance of the plugin for the tenant.
type CatalogPluginService struct {
	tenantv1.UnimplementedCatalogPluginServiceServer

	store CatalogPluginStore

	// gate answers the platform catalog gate (ADR-0067): an entry without
	// its platform_enabled tuple is invisible to ListPluginCatalog and refused
	// by EnableCatalogPlugin.
	gate CatalogGate
}

// NewCatalogPluginService constructs the service over the store and the
// catalog gate.
func NewCatalogPluginService(store CatalogPluginStore, gate CatalogGate) *CatalogPluginService {
	return &CatalogPluginService{store: store, gate: gate}
}

// tenant resolves the caller's tenant from the ext-authz context, and only
// from there.
func (s *CatalogPluginService) tenant(ctx context.Context, rpc string) (string, error) {
	tenantID, ok := auth.TenantFromContext(ctx)
	if !ok || tenantID.IsZero() {
		return "", status_grpc.Errorf(codes.PermissionDenied, "%s: missing tenant in context", rpc)
	}
	return tenantID.String(), nil
}

// ListPluginCatalog returns the catalog plugins the tenant may enable. An
// entry is visible only when its component object carries platform_enabled
// from the system tenant. A gate error fails closed.
func (s *CatalogPluginService) ListPluginCatalog(
	ctx context.Context, _ *tenantv1.ListPluginCatalogRequest,
) (*tenantv1.ListPluginCatalogResponse, error) {
	if _, err := s.tenant(ctx, "ListPluginCatalog"); err != nil {
		return nil, err
	}
	entries := componentcatalog.ListPlugins()
	checks := make([]authz.CheckRequest, len(entries))
	for i, e := range entries {
		checks[i] = authz.CheckRequest{
			User:     systemTenantRef,
			Relation: "platform_enabled",
			Object:   authz.ComponentObject(authz.KindPlugin, e.ID),
		}
	}
	allowed, err := s.gate.BatchCheck(ctx, checks)
	if err != nil || len(allowed) != len(entries) {
		return nil, status_grpc.Errorf(codes.Internal, "ListPluginCatalog: catalog gate: %v", err)
	}
	out := make([]*tenantv1.PluginCatalogEntry, 0, len(entries))
	for i, e := range entries {
		if !allowed[i] {
			continue
		}
		out = append(out, &tenantv1.PluginCatalogEntry{
			Id:          e.ID,
			DisplayName: e.DisplayName,
			Description: e.Description,
		})
	}
	return &tenantv1.ListPluginCatalogResponse{Entries: out}, nil
}

// EnableCatalogPlugin records that the caller's tenant wants one instance of
// the plugin. A plugin the catalog does not list, or one the gate does not
// pass, reads as not in the catalog.
func (s *CatalogPluginService) EnableCatalogPlugin(
	ctx context.Context, req *tenantv1.EnableCatalogPluginRequest,
) (*tenantv1.EnableCatalogPluginResponse, error) {
	tenantID, err := s.tenant(ctx, "EnableCatalogPlugin")
	if err != nil {
		return nil, err
	}
	entry, listed := componentcatalog.LookupPlugin(req.GetPluginId())
	if !listed {
		return nil, status_grpc.Errorf(codes.NotFound,
			"EnableCatalogPlugin: plugin %q is not in the catalog", req.GetPluginId())
	}
	allowed, err := s.gate.Check(ctx, systemTenantRef, "platform_enabled",
		authz.ComponentObject(authz.KindPlugin, entry.ID))
	if err != nil {
		return nil, status_grpc.Errorf(codes.Internal, "EnableCatalogPlugin: catalog gate: %v", err)
	}
	if !allowed {
		return nil, status_grpc.Errorf(codes.NotFound,
			"EnableCatalogPlugin: plugin %q is not in the catalog", entry.ID)
	}
	p, err := s.store.Enable(ctx, tenantID, entry.ID)
	if err != nil {
		if errors.Is(err, catalogplugin.ErrAlreadyEnabled) {
			return nil, status_grpc.Errorf(codes.AlreadyExists,
				"EnableCatalogPlugin: plugin %q is already enabled", entry.ID)
		}
		return nil, status_grpc.Errorf(codes.Internal, "EnableCatalogPlugin: %v", err)
	}
	return &tenantv1.EnableCatalogPluginResponse{Plugin: catalogPluginPB(p)}, nil
}

// ListCatalogPlugins returns the plugins the caller's tenant enabled.
func (s *CatalogPluginService) ListCatalogPlugins(
	ctx context.Context, _ *tenantv1.ListCatalogPluginsRequest,
) (*tenantv1.ListCatalogPluginsResponse, error) {
	tenantID, err := s.tenant(ctx, "ListCatalogPlugins")
	if err != nil {
		return nil, err
	}
	plugins, err := s.store.List(ctx, tenantID)
	if err != nil {
		return nil, status_grpc.Errorf(codes.Internal, "ListCatalogPlugins: %v", err)
	}
	out := make([]*tenantv1.CatalogPlugin, 0, len(plugins))
	for _, p := range plugins {
		out = append(out, catalogPluginPB(p))
	}
	return &tenantv1.ListCatalogPluginsResponse{Plugins: out}, nil
}

// DisableCatalogPlugin removes the plugin from what the caller's tenant wants.
func (s *CatalogPluginService) DisableCatalogPlugin(
	ctx context.Context, req *tenantv1.DisableCatalogPluginRequest,
) (*tenantv1.DisableCatalogPluginResponse, error) {
	tenantID, err := s.tenant(ctx, "DisableCatalogPlugin")
	if err != nil {
		return nil, err
	}
	if req.GetPluginId() == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "DisableCatalogPlugin: plugin_id is required")
	}
	if err := s.store.Disable(ctx, tenantID, req.GetPluginId()); err != nil {
		if errors.Is(err, catalogplugin.ErrNotEnabled) {
			return nil, status_grpc.Errorf(codes.NotFound,
				"DisableCatalogPlugin: plugin %q is not enabled", req.GetPluginId())
		}
		return nil, status_grpc.Errorf(codes.Internal, "DisableCatalogPlugin: %v", err)
	}
	return &tenantv1.DisableCatalogPluginResponse{}, nil
}

func catalogPluginPB(p catalogplugin.Plugin) *tenantv1.CatalogPlugin {
	return &tenantv1.CatalogPlugin{Id: p.PluginID, Phase: p.Phase, LastError: p.LastError}
}
