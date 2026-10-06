// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"errors"
	"log/slog"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/audit"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// auditActionRetentionSet is the audit action of a change of the audit
// retention period of a tenant.
const auditActionRetentionSet = "audit.retention.set"

// WithAuditRetention wires the audit retention settings into DaemonServer.
func (s *DaemonServer) WithAuditRetention(rs *audit.RetentionSettings) *DaemonServer {
	s.auditRetention = rs
	return s
}

// retentionTenant returns the tenant of the caller, after it checks that
// the caller is a tenant admin and that the retention settings are wired.
func (s *DaemonServer) retentionTenant(ctx context.Context) (string, error) {
	tenantID := auth.TenantStringFromContext(ctx)
	if tenantID == "" {
		return "", status_grpc.Error(codes.InvalidArgument, "the caller has no tenant")
	}
	if err := s.requireTenantAdmin(ctx, tenantID); err != nil {
		return "", err
	}
	if s.auditRetention == nil {
		return "", status_grpc.Error(codes.Unavailable, "audit retention is not configured")
	}
	return tenantID, nil
}

// GetAuditRetention returns the audit retention period of the caller's
// tenant (gibson#676).
func (s *DaemonServer) GetAuditRetention(ctx context.Context, _ *tenantv1.GetAuditRetentionRequest) (*tenantv1.GetAuditRetentionResponse, error) {
	tenantID, err := s.retentionTenant(ctx)
	if err != nil {
		return nil, err
	}
	period, err := s.auditRetention.Period(ctx, tenantID)
	if err != nil {
		s.logger.ErrorContext(ctx, "GetAuditRetention: read failed",
			slog.String("tenant_id", tenantID), slog.String("error", err.Error()))
		return nil, status_grpc.Error(codes.Internal, "the audit retention period could not be read")
	}
	return &tenantv1.GetAuditRetentionResponse{Retention: retentionToProto(period)}, nil
}

// SetAuditRetention sets the audit retention period of the caller's tenant
// (gibson#676). The audit record is durable before the change. A failed
// change gets a second record with the result.
func (s *DaemonServer) SetAuditRetention(ctx context.Context, req *tenantv1.SetAuditRetentionRequest) (*tenantv1.SetAuditRetentionResponse, error) {
	tenantID, err := s.retentionTenant(ctx)
	if err != nil {
		return nil, err
	}
	if s.auditLogger == nil {
		return nil, status_grpc.Error(codes.Unavailable, "the audit log is not configured; nothing changed")
	}
	id, err := auth.IdentityFromContext(ctx)
	if err != nil || id.Subject == "" {
		return nil, status_grpc.Error(codes.Unauthenticated, "authentication required")
	}
	months := int(req.GetMonths())
	details := map[string]any{"tenant_id": tenantID, "months": months}

	if _, err := s.auditLogger.Record(ctx, auditActionRetentionSet, "tenant", tenantID, details); err != nil {
		s.logger.ErrorContext(ctx, "SetAuditRetention: durable audit write failed",
			slog.String("tenant_id", tenantID), slog.String("error", err.Error()))
		return nil, status_grpc.Error(codes.Unavailable, "the audit record of the change could not be written; nothing changed")
	}

	if err := s.auditRetention.SetTenantMonths(ctx, tenantID, months, id.Subject); err != nil {
		s.auditLogger.LogWithResult(ctx, auditActionRetentionSet, "tenant", tenantID, "failure", details)
		if errors.Is(err, audit.ErrRetentionUnderInstall) {
			return nil, status_grpc.Error(codes.InvalidArgument, err.Error())
		}
		s.logger.ErrorContext(ctx, "SetAuditRetention: write failed",
			slog.String("tenant_id", tenantID), slog.String("error", err.Error()))
		return nil, status_grpc.Error(codes.Internal, "the audit retention period could not be written")
	}

	period, err := s.auditRetention.Period(ctx, tenantID)
	if err != nil {
		s.logger.ErrorContext(ctx, "SetAuditRetention: read after write failed",
			slog.String("tenant_id", tenantID), slog.String("error", err.Error()))
		return nil, status_grpc.Error(codes.Internal, "the audit retention period was written but could not be read")
	}
	return &tenantv1.SetAuditRetentionResponse{Retention: retentionToProto(period)}, nil
}

func retentionToProto(p audit.RetentionPeriod) *tenantv1.AuditRetention {
	return &tenantv1.AuditRetention{
		InstallMonths:   int32(p.InstallMonths),   //nolint:gosec // G115: at most 1200, refused above by the request rule
		TenantMonths:    int32(p.TenantMonths),    //nolint:gosec // G115: at most 1200, refused above by the request rule
		EffectiveMonths: int32(p.EffectiveMonths), //nolint:gosec // G115: at most 1200, refused above by the request rule
	}
}
