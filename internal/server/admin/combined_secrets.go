// Package admin — combined_secrets.go
//
// CombinedSecretsServer implements tenantv1.SecretsServiceServer by composing
// two existing handler structs (ADR-0039):
//
//   - broker-config RPCs (GetBrokerConfig / ProbeBrokerConfig / SetBrokerConfig
//     / CountSecrets) — delegated to *TenantAdminServer, which has always owned
//     this logic.
//   - secrets-CRUD RPCs (ListSecrets / GetSecret / SetSecret / RotateSecret /
//     DeleteSecret / GetMissionAudit) — delegated to *SecretsAdminServer.
//
// The two structs are kept separate (ADR-0039 says "re-point handler structs,
// swap types") so the existing FGA gating, probe logic, and audit pipelines
// are untouched.
//
// Production callers in grpc.go construct this via NewCombinedSecretsServer
// once both deps are available.
package admin

import (
	"context"

	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

// CombinedSecretsServer is the single server registered for
// gibson.tenant.v1.SecretsService on the daemon gRPC port.
type CombinedSecretsServer struct {
	tenantv1.UnimplementedSecretsServiceServer

	brokerConfig *TenantAdminServer
	secrets      *SecretsAdminServer
}

// NewCombinedSecretsServer returns a SecretsServiceServer that delegates broker-config
// RPCs to brokerConfig and secrets-CRUD RPCs to secrets.
func NewCombinedSecretsServer(brokerConfig *TenantAdminServer, secrets *SecretsAdminServer) *CombinedSecretsServer {
	return &CombinedSecretsServer{brokerConfig: brokerConfig, secrets: secrets}
}

// ---------------------------------------------------------------------------
// Broker-config RPCs — delegated to TenantAdminServer
// ---------------------------------------------------------------------------

func (s *CombinedSecretsServer) GetBrokerConfig(ctx context.Context, req *tenantv1.GetBrokerConfigRequest) (*tenantv1.GetBrokerConfigResponse, error) {
	return s.brokerConfig.GetBrokerConfig(ctx, req)
}

func (s *CombinedSecretsServer) ProbeBrokerConfig(ctx context.Context, req *tenantv1.ProbeBrokerConfigRequest) (*tenantv1.ProbeBrokerConfigResponse, error) {
	return s.brokerConfig.ProbeBrokerConfig(ctx, req)
}

func (s *CombinedSecretsServer) SetBrokerConfig(ctx context.Context, req *tenantv1.SetBrokerConfigRequest) (*tenantv1.SetBrokerConfigResponse, error) {
	return s.brokerConfig.SetBrokerConfig(ctx, req)
}

func (s *CombinedSecretsServer) CountSecrets(ctx context.Context, req *tenantv1.CountSecretsRequest) (*tenantv1.CountSecretsResponse, error) {
	return s.brokerConfig.CountSecrets(ctx, req)
}

// ---------------------------------------------------------------------------
// Secrets-CRUD RPCs — delegated to SecretsAdminServer
// ---------------------------------------------------------------------------

func (s *CombinedSecretsServer) ListSecrets(ctx context.Context, req *tenantv1.ListSecretsRequest) (*tenantv1.ListSecretsResponse, error) {
	return s.secrets.ListSecrets(ctx, req)
}

func (s *CombinedSecretsServer) GetSecret(ctx context.Context, req *tenantv1.GetSecretRequest) (*tenantv1.GetSecretResponse, error) {
	return s.secrets.GetSecret(ctx, req)
}

func (s *CombinedSecretsServer) SetSecret(ctx context.Context, req *tenantv1.SetSecretRequest) (*tenantv1.SetSecretResponse, error) {
	return s.secrets.SetSecret(ctx, req)
}

func (s *CombinedSecretsServer) RotateSecret(ctx context.Context, req *tenantv1.RotateSecretRequest) (*tenantv1.RotateSecretResponse, error) {
	return s.secrets.RotateSecret(ctx, req)
}

func (s *CombinedSecretsServer) DeleteSecret(ctx context.Context, req *tenantv1.DeleteSecretRequest) (*tenantv1.DeleteSecretResponse, error) {
	return s.secrets.DeleteSecret(ctx, req)
}

func (s *CombinedSecretsServer) GetMissionAudit(ctx context.Context, req *tenantv1.GetMissionAuditRequest) (*tenantv1.GetMissionAuditResponse, error) {
	return s.secrets.GetMissionAudit(ctx, req)
}
