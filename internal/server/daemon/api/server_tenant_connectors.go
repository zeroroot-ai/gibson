// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/componentcatalog"
	"github.com/zeroroot-ai/gibson/internal/platform/tenantconnector"
	daemonoperatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
)

// The connector operator pulls the connectors each tenant enabled, converges
// the ConnectorInstances, and reports their state (gibson#662). The three
// RPCs below are on the method list of the connector operator only.

// connectorStore returns the tenant connector store over the platform
// database, or Unavailable when the daemon has none.
func (s *DaemonServer) connectorStore() (*tenantconnector.Store, error) {
	db := s.entitlementsDB()
	if db == nil {
		return nil, status.Error(codes.Unavailable, "platform Postgres not configured")
	}
	return tenantconnector.NewStore(db), nil
}

// ListDesiredConnectors returns every (tenant, connector) pair a tenant
// enabled, with the fields of the catalog entry. The read spans every tenant
// on purpose, so the method policy admits the connector operator only.
//
// gibsoncheck:allow tenant-from-request — DaemonOperatorService: platform_operator on
// system_tenant at ext-authz, plus the SPIFFE peer method policy.
func (s *DaemonServer) ListDesiredConnectors(
	ctx context.Context, _ *daemonoperatorv1.ListDesiredConnectorsRequest,
) (*daemonoperatorv1.ListDesiredConnectorsResponse, error) {
	store, err := s.connectorStore()
	if err != nil {
		return nil, err
	}
	rows, err := store.ListAll(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list desired connectors: %v", err)
	}
	out := make([]*daemonoperatorv1.DesiredConnector, 0, len(rows))
	for _, r := range rows {
		// A row whose connector left the catalog is not desired any more: the
		// operator does not get it, and it removes the instance.
		entry, lerr := componentcatalog.LookupConnector(r.ConnectorID)
		if lerr != nil {
			continue
		}
		out = append(out, &daemonoperatorv1.DesiredConnector{
			TenantId:    r.TenantID,
			ConnectorId: r.ConnectorID,
			Shape:       string(entry.Shape),
			Image:       entry.Image,
			Endpoint:    entry.Endpoint,
			Transport:   string(entry.Transport),
			Auth:        string(entry.Auth),
			EgressAllow: entry.EgressAllow,
		})
	}
	return &daemonoperatorv1.ListDesiredConnectorsResponse{Connectors: out}, nil
}

// ReportConnectorStatus records the state that the connector operator reads
// from one ConnectorInstance. A report for a pair no tenant enabled changes
// nothing and answers updated=false.
//
// gibsoncheck:allow tenant-from-request — DaemonOperatorService: platform_operator on
// system_tenant at ext-authz, plus the SPIFFE peer method policy.
func (s *DaemonServer) ReportConnectorStatus(
	ctx context.Context, req *daemonoperatorv1.ReportConnectorStatusRequest,
) (*daemonoperatorv1.ReportConnectorStatusResponse, error) {
	if req.GetTenantId() == "" || req.GetConnectorId() == "" || req.GetPhase() == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id, connector_id and phase are required")
	}
	store, err := s.connectorStore()
	if err != nil {
		return nil, err
	}
	updated, err := store.ReportStatus(ctx, req.GetTenantId(), req.GetConnectorId(), tenantconnector.Status{
		Phase:     req.GetPhase(),
		LastError: req.GetLastError(),
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "report connector status: %v", err)
	}
	return &daemonoperatorv1.ReportConnectorStatusResponse{Updated: updated}, nil
}

// AdoptConnector records a connector that the daemon wrote as a
// ConnectorInstance before the table existed. Only a catalog connector can be
// adopted.
//
// gibsoncheck:allow tenant-from-request — DaemonOperatorService: platform_operator on
// system_tenant at ext-authz, plus the SPIFFE peer method policy.
func (s *DaemonServer) AdoptConnector(
	ctx context.Context, req *daemonoperatorv1.AdoptConnectorRequest,
) (*daemonoperatorv1.AdoptConnectorResponse, error) {
	if req.GetTenantId() == "" || req.GetConnectorId() == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id and connector_id are required")
	}
	if _, err := componentcatalog.LookupConnector(req.GetConnectorId()); err != nil {
		return nil, status.Errorf(codes.NotFound, "adopt connector: %v", err)
	}
	store, err := s.connectorStore()
	if err != nil {
		return nil, err
	}
	if err := store.Adopt(ctx, req.GetTenantId(), req.GetConnectorId()); err != nil {
		return nil, status.Errorf(codes.Internal, "adopt connector: %v", err)
	}
	return &daemonoperatorv1.AdoptConnectorResponse{}, nil
}
