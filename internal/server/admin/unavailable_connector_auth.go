// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package admin — unavailable_connector_auth.go
//
// unavailableConnectorAuthServer is the boot-survival fallback registered by
// internal/server/daemon/grpc.go when the secrets stack is absent. It returns
// codes.Unavailable on every ConnectorAuthService RPC so the dashboard
// surfaces an actionable "service unavailable" message instead of the
// misleading codes.Unimplemented an unregistered service would return.
//
// ADR-0064: gibson.tenant.v1.ConnectorAuthService.
package admin

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

type unavailableConnectorAuthServer struct {
	tenantv1.UnimplementedConnectorAuthServiceServer
}

// NewUnavailableConnectorAuthServer returns a stub ConnectorAuthServiceServer
// that responds with codes.Unavailable on every RPC. Registered when the
// secrets stack is not present at daemon startup.
func NewUnavailableConnectorAuthServer() tenantv1.ConnectorAuthServiceServer {
	return &unavailableConnectorAuthServer{}
}

const connectorAuthUnavailableMsg = "ConnectorAuthService: service unavailable — secrets stack not initialised"

func (s *unavailableConnectorAuthServer) GetConnectorAuthStatus(_ context.Context, _ *tenantv1.GetConnectorAuthStatusRequest) (*tenantv1.GetConnectorAuthStatusResponse, error) {
	return nil, status.Error(codes.Unavailable, connectorAuthUnavailableMsg)
}

func (s *unavailableConnectorAuthServer) StartConnectorAuthorization(_ context.Context, _ *tenantv1.StartConnectorAuthorizationRequest) (*tenantv1.StartConnectorAuthorizationResponse, error) {
	return nil, status.Error(codes.Unavailable, connectorAuthUnavailableMsg)
}

func (s *unavailableConnectorAuthServer) CompleteConnectorAuthorization(_ context.Context, _ *tenantv1.CompleteConnectorAuthorizationRequest) (*tenantv1.CompleteConnectorAuthorizationResponse, error) {
	return nil, status.Error(codes.Unavailable, connectorAuthUnavailableMsg)
}

func (s *unavailableConnectorAuthServer) RevokeConnectorGrant(_ context.Context, _ *tenantv1.RevokeConnectorGrantRequest) (*tenantv1.RevokeConnectorGrantResponse, error) {
	return nil, status.Error(codes.Unavailable, connectorAuthUnavailableMsg)
}

func (s *unavailableConnectorAuthServer) SetConnectorSecret(_ context.Context, _ *tenantv1.SetConnectorSecretRequest) (*tenantv1.SetConnectorSecretResponse, error) {
	return nil, status.Error(codes.Unavailable, connectorAuthUnavailableMsg)
}
