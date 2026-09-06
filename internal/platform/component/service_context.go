// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// GetCredential retrieves a tenant-scoped credential by name.
//
// Per-secret authorization runs FIRST — before any request validation, before
// the store is touched, and before anything about the named credential (even
// whether a credential store is configured) is revealed. gibson#1245: this RPC
// previously did a bare store read after a tenant-presence check only, and the
// gateway cannot supply the missing decision either, so any caller that reached
// the handler could read any secret in its header-asserted tenant. The sibling
// HarnessCallbackService/GetCredential was fixed the same way in PR #1278.
func (s *ComponentServiceServer) GetCredential(ctx context.Context, req *componentpb.GetCredentialRequest) (*componentpb.GetCredentialResponse, error) {
	if err := s.authorizeCredentialResolve(ctx, req.GetName()); err != nil {
		return nil, err
	}

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
