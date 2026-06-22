// Package admin — unavailable_secrets_admin.go
//
// unavailableSecretsServer is the boot-survival fallback registered by
// internal/server/daemon/grpc.go when the secrets stack (secrets.Service / registry /
// platform DB / authorizer) is not available. It returns codes.Unavailable on
// every RPC so the dashboard surfaces an actionable "secrets stack not
// initialised" message instead of the misleading codes.Unimplemented.
//
// ADR-0039: formerly backed by adminv1.SecretsAdminServiceServer; now backs
// tenantv1.SecretsServiceServer (which adds broker-config RPCs).
//
// Spec: gibson#564 (SecretsAdminService was never registered).
package admin

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	tenantv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/tenant/v1"
)

type unavailableSecretsServer struct {
	tenantv1.UnimplementedSecretsServiceServer
}

// NewUnavailableSecretsServer returns a stub SecretsServiceServer that responds
// with codes.Unavailable on every RPC. Used by grpc.go when the secrets stack
// did not initialise.
func NewUnavailableSecretsServer() tenantv1.SecretsServiceServer {
	return &unavailableSecretsServer{}
}

const unavailableSecretsMsg = "secrets stack not initialised"

func (*unavailableSecretsServer) ListSecrets(context.Context, *tenantv1.ListSecretsRequest) (*tenantv1.ListSecretsResponse, error) {
	return nil, status.Error(codes.Unavailable, unavailableSecretsMsg)
}
func (*unavailableSecretsServer) GetSecret(context.Context, *tenantv1.GetSecretRequest) (*tenantv1.GetSecretResponse, error) {
	return nil, status.Error(codes.Unavailable, unavailableSecretsMsg)
}
func (*unavailableSecretsServer) SetSecret(context.Context, *tenantv1.SetSecretRequest) (*tenantv1.SetSecretResponse, error) {
	return nil, status.Error(codes.Unavailable, unavailableSecretsMsg)
}
func (*unavailableSecretsServer) RotateSecret(context.Context, *tenantv1.RotateSecretRequest) (*tenantv1.RotateSecretResponse, error) {
	return nil, status.Error(codes.Unavailable, unavailableSecretsMsg)
}
func (*unavailableSecretsServer) DeleteSecret(context.Context, *tenantv1.DeleteSecretRequest) (*tenantv1.DeleteSecretResponse, error) {
	return nil, status.Error(codes.Unavailable, unavailableSecretsMsg)
}
func (*unavailableSecretsServer) GetMissionAudit(context.Context, *tenantv1.GetMissionAuditRequest) (*tenantv1.GetMissionAuditResponse, error) {
	return nil, status.Error(codes.Unavailable, unavailableSecretsMsg)
}
func (*unavailableSecretsServer) GetBrokerConfig(context.Context, *tenantv1.GetBrokerConfigRequest) (*tenantv1.GetBrokerConfigResponse, error) {
	return nil, status.Error(codes.Unavailable, unavailableSecretsMsg)
}
func (*unavailableSecretsServer) ProbeBrokerConfig(context.Context, *tenantv1.ProbeBrokerConfigRequest) (*tenantv1.ProbeBrokerConfigResponse, error) {
	return nil, status.Error(codes.Unavailable, unavailableSecretsMsg)
}
func (*unavailableSecretsServer) SetBrokerConfig(context.Context, *tenantv1.SetBrokerConfigRequest) (*tenantv1.SetBrokerConfigResponse, error) {
	return nil, status.Error(codes.Unavailable, unavailableSecretsMsg)
}
func (*unavailableSecretsServer) CountSecrets(context.Context, *tenantv1.CountSecretsRequest) (*tenantv1.CountSecretsResponse, error) {
	return nil, status.Error(codes.Unavailable, unavailableSecretsMsg)
}
