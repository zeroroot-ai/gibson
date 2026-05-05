package api

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/zero-day-ai/gibson/internal/daemon/api/gibson/platform/v1"
)

// GetReservedNames returns the chart-managed reserved-names denylist that
// backs the Tenant CRD admission webhook and the dashboard signup form.
//
// Spec: tenant-provisioning-unification-phase2 Requirement 4.5. Source of
// truth is the gibson-reserved-names ConfigMap in the gibson namespace
// (managed by enterprise/deploy/helm/gibson). The handler defers to a
// provider wired via WithReservedNames; the provider owns caching and
// the K8s client.
//
// Authz: rule-mode (platform_operator on system_tenant). Callers are the
// dashboard's signup-form proxy (SPIFFE service identity) and the
// admission webhook itself.
func (s *DaemonServer) GetReservedNames(ctx context.Context, _ *platformv1.GetReservedNamesRequest) (*platformv1.GetReservedNamesResponse, error) {
	if s.reservedNames == nil {
		// Empty lists are a valid response — the chart may have wiped the
		// ConfigMap or the daemon may be running without K8s access (kind
		// dev path). Return empty rather than Unavailable so callers can
		// rely on the RPC being safe to call unconditionally.
		return &platformv1.GetReservedNamesResponse{}, nil
	}
	exact, prefix, err := s.reservedNames.ReservedNames(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "reserved-names provider failed: %v", err)
	}
	return &platformv1.GetReservedNamesResponse{
		Exact:  exact,
		Prefix: prefix,
	}, nil
}
