package component

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// GetCredential retrieves a tenant-scoped credential by name.
func (s *ComponentServiceServer) GetCredential(ctx context.Context, req *componentpb.GetCredentialRequest) (*componentpb.GetCredentialResponse, error) {
	tenant := auth.TenantStringFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "tenant not found in context")
	}
	if s.credentialStore == nil {
		return nil, status.Error(codes.Unimplemented, "credential store not configured")
	}
	credJSON, err := s.credentialStore.GetCredential(ctx, tenant, req.GetName())
	if err != nil {
		s.logger.Error("GetCredential failed", "tenant", tenant, "name", req.GetName(), "error", err)
		return nil, status.Errorf(codes.Internal, "credential retrieval failed: %v", err)
	}
	return &componentpb.GetCredentialResponse{CredentialJson: credJSON}, nil
}

// GetTaxonomySchema returns the current taxonomy definition.
func (s *ComponentServiceServer) GetTaxonomySchema(ctx context.Context, req *componentpb.GetTaxonomySchemaRequest) (*componentpb.GetTaxonomySchemaResponse, error) {
	if s.taxonomyProvider == nil {
		return nil, status.Error(codes.Unimplemented, "taxonomy provider not configured")
	}
	schemaJSON, err := s.taxonomyProvider.GetTaxonomySchema(ctx)
	if err != nil {
		s.logger.Error("GetTaxonomySchema failed", "error", err)
		return nil, status.Errorf(codes.Internal, "taxonomy retrieval failed: %v", err)
	}
	return &componentpb.GetTaxonomySchemaResponse{SchemaJson: schemaJSON}, nil
}

// ReportStepHints reports planning step hints from an agent back to the orchestrator.
func (s *ComponentServiceServer) ReportStepHints(ctx context.Context, req *componentpb.ReportStepHintsRequest) (*componentpb.ReportStepHintsResponse, error) {
	tenant := auth.TenantStringFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "tenant not found in context")
	}
	if s.stepHintsReporter == nil {
		return nil, status.Error(codes.Unimplemented, "step hints reporting not configured")
	}
	if err := s.stepHintsReporter.ReportStepHints(ctx, tenant, req.GetWorkId(), req.GetHintsJson()); err != nil {
		s.logger.Error("ReportStepHints failed", "tenant", tenant, "error", err)
		return nil, status.Errorf(codes.Internal, "report failed: %v", err)
	}
	return &componentpb.ReportStepHintsResponse{}, nil
}
