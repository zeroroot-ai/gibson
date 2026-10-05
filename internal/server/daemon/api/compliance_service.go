// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/platform/audit/compliance"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// ComplianceService serves ListComplianceEvidence (ADR-0113, gibson#674).
// The reader does the work; this type maps the request and the response.
type ComplianceService struct {
	tenantv1.UnimplementedComplianceServiceServer

	reader *compliance.Reader
}

// NewComplianceService returns the service over reader.
func NewComplianceService(reader *compliance.Reader) *ComplianceService {
	return &ComplianceService{reader: reader}
}

// BrainEnabledPacks answers compliance.EnabledPacks from the World of each
// tenant: a pack is enabled when the World of the tenant holds it.
type BrainEnabledPacks struct {
	Registry *brain.Registry
}

// IsDomainPackEnabled implements compliance.EnabledPacks.
func (b BrainEnabledPacks) IsDomainPackEnabled(_ context.Context, tenant, pack string) (bool, error) {
	for _, p := range b.Registry.For(tenant).DomainPacks() {
		if p.Name == pack {
			return true, nil
		}
	}
	return false, nil
}

// ListComplianceEvidence returns the evidence of each control of an enabled
// framework pack for the tenant of the caller.
func (s *ComplianceService) ListComplianceEvidence(
	ctx context.Context, req *tenantv1.ListComplianceEvidenceRequest,
) (*tenantv1.ListComplianceEvidenceResponse, error) {
	tenantID, ok := auth.TenantFromContext(ctx)
	if !ok || tenantID.IsZero() {
		return nil, status_grpc.Error(codes.PermissionDenied, "ListComplianceEvidence: missing tenant in context")
	}
	q := compliance.Query{
		Tenant:    tenantID.String(),
		Pack:      req.GetPack(),
		PageSize:  int(req.GetPageSize()),
		PageToken: req.GetPageToken(),
	}
	if req.GetStartTime() != nil {
		q.Start = req.GetStartTime().AsTime()
	}
	if req.GetEndTime() != nil {
		q.End = req.GetEndTime().AsTime()
	}
	rep, err := s.reader.Evidence(ctx, q)
	if err != nil {
		return nil, complianceStatus(err)
	}
	return complianceResponse(rep), nil
}

// complianceStatus maps a reader error to a gRPC status.
func complianceStatus(err error) error {
	switch {
	case errors.Is(err, compliance.ErrInvalidQuery):
		return status_grpc.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, compliance.ErrUnknownPack), errors.Is(err, compliance.ErrNotAFramework):
		return status_grpc.Error(codes.NotFound, err.Error())
	case errors.Is(err, compliance.ErrPackNotEnabled):
		return status_grpc.Error(codes.FailedPrecondition, err.Error())
	default:
		return status_grpc.Error(codes.Internal, "ListComplianceEvidence: "+err.Error())
	}
}

var controlStates = map[compliance.State]tenantv1.ControlEvidence_State{
	compliance.StateNoRule:      tenantv1.ControlEvidence_STATE_NO_RULE,
	compliance.StateNoEvents:    tenantv1.ControlEvidence_STATE_NO_EVENTS,
	compliance.StateHasEvidence: tenantv1.ControlEvidence_STATE_HAS_EVIDENCE,
}

func complianceResponse(rep *compliance.Report) *tenantv1.ListComplianceEvidenceResponse {
	out := &tenantv1.ListComplianceEvidenceResponse{
		Pack:             rep.Pack,
		PackVersion:      int32Count(rep.PackVersion),
		ControlsWithRule: int32Count(rep.ControlsWithRule),
		ControlsTotal:    int32Count(rep.ControlsTotal),
		Controls:         make([]*tenantv1.ControlEvidence, 0, len(rep.Controls)),
		Events:           make([]*tenantv1.EvidenceEvent, 0, len(rep.Events)),
		NextPageToken:    rep.NextPageToken,
	}
	for _, c := range rep.Controls {
		ce := &tenantv1.ControlEvidence{
			ControlId:   c.ID,
			Title:       c.Title,
			Family:      c.Family,
			FamilyTitle: c.FamilyTitle,
			State:       controlStates[c.State],
			EventCount:  c.EventCount,
		}
		if !c.LastEventTime.IsZero() {
			ce.LastEventTime = timestamppb.New(c.LastEventTime)
		}
		out.Controls = append(out.Controls, ce)
	}
	for _, e := range rep.Events {
		out.Events = append(out.Events, &tenantv1.EvidenceEvent{
			AuditRecordId: e.AuditRecordID,
			Time:          timestamppb.New(e.Time),
			Action:        e.Action,
			ActorId:       e.ActorID,
			ResourceType:  e.ResourceType,
			ResourceId:    e.ResourceID,
			ControlIds:    append([]string(nil), e.ControlIDs...),
		})
	}
	return out
}
