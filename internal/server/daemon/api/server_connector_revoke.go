// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package api — server_connector_revoke.go
//
// DaemonOperatorService.RevokeConnectorGrant: the connector-operator's
// ConnectorInstance finalizer asks the daemon to revoke a tenant's connector
// grant on delete (ADR-0015 §5, gibson#1566). The operator has no secret-store
// client by design; the daemon owns the grant and the access pair, so the
// revoke runs here and the operator only carries the (tenant, connector) pair
// over the SPIFFE direct-dial path (ADR-0002).
package api

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	daemonoperatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// ConnectorGrantRevoker revokes one tenant's connector grant. The production
// implementation is admin.ConnectorAuthAdminServer.Revoke, the same code the
// tenant-scoped ConnectorAuthService.RevokeConnectorGrant runs.
type ConnectorGrantRevoker interface {
	Revoke(ctx context.Context, tenant auth.TenantID, connector string) (hadGrant, vendorRevoked bool, err error)
}

// WithConnectorGrantRevoker wires the revoker the operator-scoped
// RevokeConnectorGrant delegates to. Unwired (a daemon with no secrets stack),
// the RPC answers Unavailable so the finalizer retries and then releases with
// a logged warning rather than wedging the delete.
func (s *DaemonServer) WithConnectorGrantRevoker(r ConnectorGrantRevoker) *DaemonServer {
	s.connectorGrantRevoker = r
	return s
}

// RevokeConnectorGrant revokes the named tenant's connector grant for the
// connector-operator finalizer. Operator-only (platform_operator on
// system_tenant at ext-authz, plus the SPIFFE peer method policy). Idempotent:
// a connector with no grant is had_grant=false.
//
// gibsoncheck:allow tenant-from-request — DaemonOperatorService: platform_operator on
// system_tenant at ext-authz, plus the SPIFFE peer method policy. The operator
// finalizes ConnectorInstances in every tenant namespace by design.
func (s *DaemonServer) RevokeConnectorGrant(ctx context.Context, req *daemonoperatorv1.RevokeConnectorGrantRequest) (*daemonoperatorv1.RevokeConnectorGrantResponse, error) {
	if s.connectorGrantRevoker == nil {
		return nil, status.Error(codes.Unavailable, "connector grant revocation is not configured on this daemon")
	}
	tenant, err := auth.NewTenantID(req.GetTenantId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "tenant_id: %v", err)
	}
	connector := req.GetConnector()
	if connector == "" {
		return nil, status.Error(codes.InvalidArgument, "connector is required")
	}
	hadGrant, vendorRevoked, err := s.connectorGrantRevoker.Revoke(ctx, tenant, connector)
	if err != nil {
		// Revoke returns gRPC statuses; keep the code and name the RPC.
		st := status.Convert(err)
		return nil, status.Errorf(st.Code(), "revoke connector grant: %s", st.Message())
	}
	s.logger.Info("connector grant revoked by operator finalizer",
		"tenant", tenant.String(), "connector", connector,
		"had_grant", hadGrant, "vendor_revoked", vendorRevoked)
	return &daemonoperatorv1.RevokeConnectorGrantResponse{HadGrant: hadGrant, VendorRevoked: vendorRevoked}, nil
}
