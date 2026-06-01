// Package admin — unavailable_secrets_admin.go
//
// unavailableSecretsAdminServer is the boot-survival fallback registered by
// internal/daemon/grpc.go when the secrets stack (secrets.Service / registry /
// platform DB / authorizer) is not available. It returns codes.Unavailable on
// every RPC so the dashboard surfaces an actionable "secrets stack not
// initialised" message instead of the misleading codes.Unimplemented (which
// looks like a daemon-version mismatch).
//
// Spec: gibson#564 (SecretsAdminService was never registered).
package admin

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	adminv1 "github.com/zeroroot-ai/platform-sdk/gen/gibson/admin/v1"
)

type unavailableSecretsAdminServer struct {
	adminv1.UnimplementedSecretsAdminServiceServer
}

// NewUnavailableSecretsAdminServer returns a stub server that responds with
// codes.Unavailable on every SecretsAdminService RPC. Used by grpc.go when the
// secrets stack did not initialise.
func NewUnavailableSecretsAdminServer() adminv1.SecretsAdminServiceServer {
	return &unavailableSecretsAdminServer{}
}

const unavailableSecretsMsg = "secrets stack not initialised"

func (*unavailableSecretsAdminServer) ListSecrets(context.Context, *adminv1.ListSecretsRequest) (*adminv1.ListSecretsResponse, error) {
	return nil, status.Error(codes.Unavailable, unavailableSecretsMsg)
}
func (*unavailableSecretsAdminServer) GetSecret(context.Context, *adminv1.GetSecretRequest) (*adminv1.GetSecretResponse, error) {
	return nil, status.Error(codes.Unavailable, unavailableSecretsMsg)
}
func (*unavailableSecretsAdminServer) SetSecret(context.Context, *adminv1.SetSecretRequest) (*adminv1.SetSecretResponse, error) {
	return nil, status.Error(codes.Unavailable, unavailableSecretsMsg)
}
func (*unavailableSecretsAdminServer) RotateSecret(context.Context, *adminv1.RotateSecretRequest) (*adminv1.RotateSecretResponse, error) {
	return nil, status.Error(codes.Unavailable, unavailableSecretsMsg)
}
func (*unavailableSecretsAdminServer) DeleteSecret(context.Context, *adminv1.DeleteSecretRequest) (*adminv1.DeleteSecretResponse, error) {
	return nil, status.Error(codes.Unavailable, unavailableSecretsMsg)
}
func (*unavailableSecretsAdminServer) GetMissionAudit(context.Context, *adminv1.GetMissionAuditRequest) (*adminv1.GetMissionAuditResponse, error) {
	return nil, status.Error(codes.Unavailable, unavailableSecretsMsg)
}
