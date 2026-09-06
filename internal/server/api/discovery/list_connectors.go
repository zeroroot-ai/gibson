// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package discovery

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/component"
	"github.com/zeroroot-ai/gibson/internal/platform/componentcatalog"
	discoverypb "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/discovery/v1"
)

// ConnectorLister enumerates the caller tenant's enabled connectors — the
// catalog ids of its ConnectorInstance CRs. The daemon implements it over the
// narrow ConnectorInstance kube client (connector_adapters.go).
type ConnectorLister interface {
	ListEnabledConnectors(ctx context.Context, tenant string) ([]string, error)
}

// ListConnectors implements DiscoveryServiceServer for the fourth component
// kind (ADR-0067). Connectors are not registry components: the source is the
// tenant's ConnectorInstance CRs, and rwx is computed against
// component:connector/<id> through the same catalogItemForScope path the
// other kinds use — so the RWX matrix, denies, and scope views behave
// identically.
func (s *Server) ListConnectors(ctx context.Context, req *discoverypb.ListConnectorsRequest) (*discoverypb.ListConnectorsResponse, error) {
	if s.connectors == nil {
		// No lister wired (detached daemon, no kube). Fail closed and loud.
		return nil, status.Error(codes.FailedPrecondition, "connector discovery unavailable: no connector lister")
	}
	q := req.GetQuery()
	if q == nil {
		q = &discoverypb.ListQuery{}
	}
	userRef := callerUserRef(ctx)
	tenantName := callerTenant(ctx)
	if tenantName == "" {
		return nil, status.Error(codes.PermissionDenied, "no tenant in context")
	}

	ids, err := s.connectors.ListEnabledConnectors(ctx, tenantName)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list connectors: %v", err)
	}

	items := make([]*discoverypb.CatalogItem, 0, len(ids))
	for _, id := range ids {
		info := connectorComponentInfo(id)
		item, include := s.catalogItemForScope(ctx, "connector", id, info, userRef, q)
		if !include {
			continue
		}
		items = append(items, item)
	}

	items = paginate(items, q.GetCursor(), q.GetPageSize())
	nextCursor := ""
	if len(items) == int(pageLimit(q.GetPageSize())) {
		nextCursor = items[len(items)-1].Name
	}
	return &discoverypb.ListConnectorsResponse{Items: items, NextCursor: nextCursor}, nil
}

// connectorComponentInfo builds the ComponentInfo view of a connector from
// the embedded catalog. An enabled connector whose entry has since left the
// catalog falls back to its bare id — it stays visible and gateable.
func connectorComponentInfo(id string) *component.ComponentInfo {
	info := &component.ComponentInfo{Name: id, Metadata: map[string]string{}}
	if entry, err := componentcatalog.LookupConnector(id); err == nil {
		info.Description = entry.Description
		info.Metadata["display_name"] = entry.DisplayName
	}
	return info
}
