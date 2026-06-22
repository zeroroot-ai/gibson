// Package admin — unavailable_tenant_admin.go
//
// unavailableMembershipServer is the boot-survival fallback registered by
// internal/server/daemon/grpc.go when the broker stack failed (no system KEK, no
// dashboard Postgres, or registry construction error). It returns
// codes.Unavailable on every MembershipService RPC so the dashboard
// surfaces an actionable "broker stack not initialised" message instead of
// the misleading codes.Unimplemented.
//
// ADR-0039: formerly backed by adminv1.TenantAdminServiceServer; now backs
// tenantv1.MembershipServiceServer.
//
// Spec: tenant-secrets-broker-completion (Task 8, design D2).
package admin

import (
	tenantv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/tenant/v1"
)

type unavailableMembershipServer struct {
	tenantv1.UnimplementedMembershipServiceServer
}

// NewUnavailableMembershipServer returns a stub MembershipServiceServer that
// responds with codes.Unavailable on every RPC via the embedded Unimplemented
// stub (which returns Unimplemented). The purpose is to ensure the service is
// registered so callers get a consistent gRPC response rather than a connection
// error when the broker stack is absent.
//
// Note: Unimplemented rather than Unavailable here is intentional — when the
// broker stack is absent, MembershipService RPCs can still be served by the
// embedded stub (they return Unimplemented). The secrects-stack-unavailable path
// is handled by unavailableSecretsServer.
func NewUnavailableMembershipServer() tenantv1.MembershipServiceServer {
	return &unavailableMembershipServer{}
}
