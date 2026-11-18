// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package api — get_finding.go implements TenantService.GetFinding.
//
// The finding and all of its evidence come from Postgres through
// pgstore.Store.GetWithEvidence, the one function that reads the evidence of a
// finding. The graph is not read.
package api

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/zeroroot-ai/gibson/internal/engine/finding"
	"github.com/zeroroot-ai/gibson/internal/engine/finding/pgstore"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// GetFinding implements TenantService.GetFinding. It returns one finding of the
// tenant of the caller with all of its evidence. The tenant comes from the
// context that ext-authz set. The request carries no tenant.
func (s *DaemonServer) GetFinding(ctx context.Context, req *tenantv1.GetFindingRequest) (*tenantv1.GetFindingResponse, error) {
	if s.poolGetter == nil {
		return nil, status_grpc.Error(codes.Unavailable, "GetFinding: data-plane pool not configured")
	}
	pool := s.poolGetter()
	if pool == nil {
		return nil, status_grpc.Error(codes.Unavailable, "GetFinding: data-plane pool not yet ready")
	}
	tenantID, ok := auth.TenantFromContext(ctx)
	if !ok || tenantID.IsZero() {
		return nil, status_grpc.Error(codes.PermissionDenied, "GetFinding: missing tenant in context")
	}
	id, err := types.ParseID(req.GetFindingId())
	if err != nil {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "GetFinding: finding_id must be a UUID: %v", err)
	}

	store := pgstore.New(func() datapool.Pool { return pool })
	f, err := store.GetWithEvidence(ctx, tenantID.String(), id)
	if err != nil {
		var notProvisioned *datapool.NotProvisionedError
		var evicted *datapool.EvictedError
		switch {
		case errors.Is(err, finding.ErrNotFound):
			return nil, status_grpc.Error(codes.NotFound, "GetFinding: no such finding")
		case errors.As(err, &notProvisioned), errors.As(err, &evicted):
			return nil, datapool.MapPoolError(err)
		}
		return nil, status_grpc.Errorf(codes.Internal, "GetFinding: %v", err)
	}
	return &tenantv1.GetFindingResponse{Finding: findingToDetail(*f)}, nil
}

// findingToDetail maps a stored finding with its evidence to the response.
func findingToDetail(f finding.EnhancedFinding) *tenantv1.FindingDetail {
	detail := &tenantv1.FindingDetail{
		Id:          f.ID.String(),
		Title:       f.Title,
		Description: f.Description,
		Category:    f.Category,
		Severity:    string(f.Severity),
		Confidence:  f.Confidence,
		MissionId:   f.MissionID.String(),
		AgentName:   f.AgentName,
		SubmittedBy: f.SubmittedBy,
		Evidence:    f.Evidence,
	}
	if !f.CreatedAt.IsZero() {
		detail.CreatedAt = timestamppb.New(f.CreatedAt)
	}
	return detail
}
