// Package admin — unavailable_plugin_admin.go
//
// unavailablePluginAdminServer is the boot-survival fallback registered by
// internal/server/daemon/grpc.go when the PluginAdminService dependency stack is
// incomplete (no IdP client, no broker audit writer, or secrets stack absent).
// It returns codes.Unavailable on every PluginAdminService RPC so the
// dashboard surfaces an actionable "service unavailable" message instead of
// the misleading codes.Unimplemented that an unregistered service would return.
//
// ADR-0039: gibson.tenant.v1.PluginAdminService. Closes gibson#565.
package admin

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	tenantv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/pluginadmin/v1"
)

type unavailablePluginAdminServer struct {
	tenantv1.UnimplementedPluginAdminServiceServer
}

// NewUnavailablePluginAdminServer returns a stub PluginAdminServiceServer that
// responds with codes.Unavailable on every RPC. Registered when the deps for
// PluginsAdminServer (IdP client, secrets service, broker audit writer) are not
// present at daemon startup.
func NewUnavailablePluginAdminServer() tenantv1.PluginAdminServiceServer {
	return &unavailablePluginAdminServer{}
}

func (s *unavailablePluginAdminServer) ListPluginInstalls(_ context.Context, _ *tenantv1.ListPluginInstallsRequest) (*tenantv1.ListPluginInstallsResponse, error) {
	return nil, status.Error(codes.Unavailable, "PluginAdminService: service unavailable — IdP client or secrets stack not initialised")
}

func (s *unavailablePluginAdminServer) GetPluginInstall(_ context.Context, _ *tenantv1.GetPluginInstallRequest) (*tenantv1.GetPluginInstallResponse, error) {
	return nil, status.Error(codes.Unavailable, "PluginAdminService: service unavailable — IdP client or secrets stack not initialised")
}

func (s *unavailablePluginAdminServer) RegisterPlugin(_ context.Context, _ *tenantv1.RegisterPluginRequest) (*tenantv1.RegisterPluginResponse, error) {
	return nil, status.Error(codes.Unavailable, "PluginAdminService: service unavailable — IdP client or secrets stack not initialised")
}

func (s *unavailablePluginAdminServer) EditPluginSecretBinding(_ context.Context, _ *tenantv1.EditPluginSecretBindingRequest) (*tenantv1.EditPluginSecretBindingResponse, error) {
	return nil, status.Error(codes.Unavailable, "PluginAdminService: service unavailable — IdP client or secrets stack not initialised")
}

func (s *unavailablePluginAdminServer) RevokePluginSecretBinding(_ context.Context, _ *tenantv1.RevokePluginSecretBindingRequest) (*tenantv1.RevokePluginSecretBindingResponse, error) {
	return nil, status.Error(codes.Unavailable, "PluginAdminService: service unavailable — IdP client or secrets stack not initialised")
}
