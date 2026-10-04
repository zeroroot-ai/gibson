package api

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	daemonoperatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
)

// SetAgentEnrollmentLimits records the runtime cap an AgentEnrollment
// declares (spec.maxRuntime, gibson#597). The daemon cannot read the CR
// (ADR-0023), so the tenant-operator reports it on every enrollment pass and
// the dispatcher reads it back through AgentRunLimit when it launches that
// agent. Zero clears the cap.
//
// gibsoncheck:allow tenant-from-request — DaemonOperatorService: platform_operator on
// system_tenant at ext-authz, plus the SPIFFE peer allowlist.
func (s *DaemonServer) SetAgentEnrollmentLimits(ctx context.Context, req *daemonoperatorv1.SetAgentEnrollmentLimitsRequest) (*daemonoperatorv1.SetAgentEnrollmentLimitsResponse, error) {
	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id required")
	}
	if req.GetAgentName() == "" {
		return nil, status.Error(codes.InvalidArgument, "agent_name required")
	}
	if req.GetMaxRuntimeSeconds() < 0 {
		return nil, status.Error(codes.InvalidArgument, "max_runtime_seconds must not be negative")
	}
	db := s.entitlementsDB()
	if db == nil {
		return nil, status.Error(codes.Unavailable, "platform Postgres not configured")
	}
	const q = `
		INSERT INTO agent_enrollment_limits (tenant_id, agent_name, max_runtime_seconds, updated_at)
		VALUES ($1, $2, $3, NOW())
		ON CONFLICT (tenant_id, agent_name) DO UPDATE SET
			max_runtime_seconds = EXCLUDED.max_runtime_seconds,
			updated_at          = NOW()
		WHERE agent_enrollment_limits.max_runtime_seconds IS DISTINCT FROM EXCLUDED.max_runtime_seconds
	`
	if _, err := db.ExecContext(ctx, q, req.GetTenantId(), req.GetAgentName(), req.GetMaxRuntimeSeconds()); err != nil {
		return nil, status.Errorf(codes.Internal, "upsert agent_enrollment_limits: %v", err)
	}
	return &daemonoperatorv1.SetAgentEnrollmentLimitsResponse{}, nil
}

// AgentRunLimit reads the runtime cap recorded for one agent of one tenant.
// ok is false when no enrollment reported a cap, or the cap is zero.
func AgentRunLimit(ctx context.Context, db *sql.DB, tenantID, agentName string) (limit time.Duration, ok bool, err error) {
	const q = `SELECT max_runtime_seconds FROM agent_enrollment_limits WHERE tenant_id = $1 AND agent_name = $2`
	var seconds int64
	if err := db.QueryRowContext(ctx, q, tenantID, agentName).Scan(&seconds); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, false, nil
		}
		return 0, false, fmt.Errorf("read agent_enrollment_limits %s/%s: %w", tenantID, agentName, err)
	}
	if seconds <= 0 {
		return 0, false, nil
	}
	return time.Duration(seconds) * time.Second, true, nil
}
