// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package api — server_connector_status.go
//
// DaemonOperatorService.GetConnectorAuthStatus: the connector-operator's
// ConnectorInstance controller asks the daemon why a connector's credential is
// dead, so the CR carries a Degraded condition instead of a silent Active
// (ADR-0015 decision 4).
//
// Only the daemon holds a secret-store client, so only the daemon knows
// whether a grant still refreshes. The operator owns the CR status and cannot
// read the store, so it pulls the reason over the SPIFFE direct-dial path
// (ADR-0002), exactly as the finalizer pulls the revoke.
package api

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	daemonoperatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// ConnectorAuthStatusReader reports one tenant connector's grant and token
// state. The production implementation is admin.ConnectorAuthAdminServer,
// the same code the tenant-scoped ConnectorAuthService.GetConnectorAuthStatus
// runs, so the operator and the dashboard read one view.
type ConnectorAuthStatusReader interface {
	AuthStatus(ctx context.Context, tenant auth.TenantID, connector string) *tenantv1.GetConnectorAuthStatusResponse
}

// WithConnectorAuthStatusReader wires the reader the operator-scoped
// GetConnectorAuthStatus delegates to. Unwired (a daemon with no secrets
// stack), the RPC answers Unavailable, and the controller leaves the
// condition alone rather than reporting a health it cannot prove.
func (s *DaemonServer) WithConnectorAuthStatusReader(r ConnectorAuthStatusReader) *DaemonServer {
	s.connectorAuthStatusReader = r
	return s
}

// GetConnectorAuthStatus reports the named tenant connector's credential state
// for the connector-operator's ConnectorInstance controller. Operator-only
// (platform_operator on system_tenant at ext-authz, plus the SPIFFE peer
// method policy). It never returns credential material.
//
// gibsoncheck:allow tenant-from-request — DaemonOperatorService: platform_operator on
// system_tenant at ext-authz, plus the SPIFFE peer method policy. The operator
// reconciles ConnectorInstances in every tenant namespace by design.
func (s *DaemonServer) GetConnectorAuthStatus(ctx context.Context, req *daemonoperatorv1.GetConnectorAuthStatusRequest) (*daemonoperatorv1.GetConnectorAuthStatusResponse, error) {
	if s.connectorAuthStatusReader == nil {
		return nil, status.Error(codes.Unavailable, "connector auth status is not configured on this daemon")
	}
	tenant, err := auth.NewTenantID(req.GetTenantId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "tenant_id: %v", err)
	}
	connector := req.GetConnector()
	if connector == "" {
		return nil, status.Error(codes.InvalidArgument, "connector is required")
	}
	return &daemonoperatorv1.GetConnectorAuthStatusResponse{
		Status: s.connectorAuthStatusReader.AuthStatus(ctx, tenant, connector),
	}, nil
}
