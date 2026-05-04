// Package admin — unavailable_tenant_admin.go
//
// unavailableTenantAdminServer is the boot-survival fallback registered by
// internal/daemon/grpc.go when initBrokerStack failed (no system KEK, no
// dashboard Postgres, or registry construction error). It returns
// codes.Unavailable on every broker-config-dependent RPC so the dashboard
// surfaces an actionable "broker stack not initialised" message instead of
// the misleading codes.Unimplemented (which looks like a daemon-version
// mismatch).
//
// Only the four broker-config-touching methods (Get/Probe/Set/Count) are
// overridden. The providers-wizard methods (GetSupportedProviders,
// ProbeProvider, ListProviderModels) are owned by a different feature path
// and fall through to UnimplementedTenantAdminServiceServer — those would
// return Unimplemented from this stub. A future spec that wires providers-
// wizard against this service will either widen this stub or split the
// registration.
//
// Spec: tenant-secrets-broker-completion (Task 8, design D2).
package admin

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	adminv1 "github.com/zero-day-ai/sdk/api/gen/gibson/admin/v1"
)

// unavailableTenantAdminServer is intentionally tiny. It embeds the
// generated UnimplementedTenantAdminServiceServer to satisfy the
// mustEmbedUnimplementedTenantAdminServiceServer requirement and to keep
// future SDK additions from breaking compilation here. Only the
// broker-config-dependent methods are overridden; everything else falls
// through to the Unimplemented behavior.
type unavailableTenantAdminServer struct {
	adminv1.UnimplementedTenantAdminServiceServer
}

// NewUnavailableTenantAdminServer returns a stub server that responds with
// codes.Unavailable on the four broker-config-dependent RPCs. Used by
// internal/daemon/grpc.go when the broker stack did not initialize.
func NewUnavailableTenantAdminServer() adminv1.TenantAdminServiceServer {
	return &unavailableTenantAdminServer{}
}

const unavailableMsg = "broker stack not initialised"

func (*unavailableTenantAdminServer) GetBrokerConfig(context.Context, *adminv1.GetBrokerConfigRequest) (*adminv1.GetBrokerConfigResponse, error) {
	return nil, status.Error(codes.Unavailable, unavailableMsg)
}

func (*unavailableTenantAdminServer) ProbeBrokerConfig(context.Context, *adminv1.ProbeBrokerConfigRequest) (*adminv1.ProbeBrokerConfigResponse, error) {
	return nil, status.Error(codes.Unavailable, unavailableMsg)
}

func (*unavailableTenantAdminServer) SetBrokerConfig(context.Context, *adminv1.SetBrokerConfigRequest) (*adminv1.SetBrokerConfigResponse, error) {
	return nil, status.Error(codes.Unavailable, unavailableMsg)
}

func (*unavailableTenantAdminServer) CountSecrets(context.Context, *adminv1.CountSecretsRequest) (*adminv1.CountSecretsResponse, error) {
	return nil, status.Error(codes.Unavailable, unavailableMsg)
}
