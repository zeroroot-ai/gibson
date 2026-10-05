// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package admin — unavailable_secrets_admin.go
//
// unavailableSecretsServer is the boot-survival fallback registered by
// internal/server/daemon/grpc.go when the secrets stack (secrets.Service / registry /
// platform DB / authorizer) is not available. It returns codes.Unavailable on
// every RPC so the dashboard surfaces an actionable "secrets stack not
// initialised" message instead of the misleading codes.Unimplemented.
//
// ADR-0058: formerly backed by adminv1.SecretsAdminServiceServer; now backs
// secretsv1.SecretsServiceServer (which adds broker-config RPCs).
//
// Spec: gibson#564 (SecretsAdminService was never registered).
package admin

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	secretsv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/secrets/v1"
)

type unavailableSecretsServer struct {
	secretsv1.UnimplementedSecretsServiceServer
}

// NewUnavailableSecretsServer returns a stub SecretsServiceServer that responds
// with codes.Unavailable on every RPC. Used by grpc.go when the secrets stack
// did not initialise.
func NewUnavailableSecretsServer() secretsv1.SecretsServiceServer {
	return &unavailableSecretsServer{}
}

const unavailableSecretsMsg = "secrets stack not initialised"

func (*unavailableSecretsServer) ListSecrets(context.Context, *secretsv1.ListSecretsRequest) (*secretsv1.ListSecretsResponse, error) {
	return nil, status.Error(codes.Unavailable, unavailableSecretsMsg)
}
func (*unavailableSecretsServer) GetSecret(context.Context, *secretsv1.GetSecretRequest) (*secretsv1.GetSecretResponse, error) {
	return nil, status.Error(codes.Unavailable, unavailableSecretsMsg)
}
func (*unavailableSecretsServer) SetSecret(context.Context, *secretsv1.SetSecretRequest) (*secretsv1.SetSecretResponse, error) {
	return nil, status.Error(codes.Unavailable, unavailableSecretsMsg)
}
func (*unavailableSecretsServer) RotateSecret(context.Context, *secretsv1.RotateSecretRequest) (*secretsv1.RotateSecretResponse, error) {
	return nil, status.Error(codes.Unavailable, unavailableSecretsMsg)
}
func (*unavailableSecretsServer) DeleteSecret(context.Context, *secretsv1.DeleteSecretRequest) (*secretsv1.DeleteSecretResponse, error) {
	return nil, status.Error(codes.Unavailable, unavailableSecretsMsg)
}
func (*unavailableSecretsServer) GetMissionAudit(context.Context, *secretsv1.GetMissionAuditRequest) (*secretsv1.GetMissionAuditResponse, error) {
	return nil, status.Error(codes.Unavailable, unavailableSecretsMsg)
}
func (*unavailableSecretsServer) GetBrokerConfig(context.Context, *secretsv1.GetBrokerConfigRequest) (*secretsv1.GetBrokerConfigResponse, error) {
	return nil, status.Error(codes.Unavailable, unavailableSecretsMsg)
}
func (*unavailableSecretsServer) ProbeBrokerConfig(context.Context, *secretsv1.ProbeBrokerConfigRequest) (*secretsv1.ProbeBrokerConfigResponse, error) {
	return nil, status.Error(codes.Unavailable, unavailableSecretsMsg)
}
func (*unavailableSecretsServer) SetBrokerConfig(context.Context, *secretsv1.SetBrokerConfigRequest) (*secretsv1.SetBrokerConfigResponse, error) {
	return nil, status.Error(codes.Unavailable, unavailableSecretsMsg)
}
func (*unavailableSecretsServer) CountSecrets(context.Context, *secretsv1.CountSecretsRequest) (*secretsv1.CountSecretsResponse, error) {
	return nil, status.Error(codes.Unavailable, unavailableSecretsMsg)
}
