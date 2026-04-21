package api

import (
	"context"
	"log/slog"
	"time"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	"github.com/zero-day-ai/gibson/internal/budget"
	"github.com/zero-day-ai/gibson/internal/identity"
	usagepb "github.com/zero-day-ai/sdk/api/gen/gibson/usage/v1"
)

// server_usage.go — DaemonServer implementation of
// gibson.usage.v1.UsageService. Dashboard-facing aggregation RPC the
// /usage page consumes so the dashboard never holds ClickHouse
// credentials directly.
//
// Spec: llm-user-attribution-governance (Requirement 2).
//
// Current implementation reads from the budget enforcer's per-period
// counters for user / team / tenant scopes (those are already a reliable
// source of truth for token attribution). Agent / mission scopes require
// ClickHouse queries against Langfuse that are not yet wired; those
// scopes return an empty-row response with a logged warning so dashboard
// callers render "no data yet" rather than an error.

// ListUsage dispatches to the scope-specific handler. Non-admins are
// narrowed to themselves regardless of subject_filter.
func (s *DaemonServer) ListUsage(ctx context.Context, req *usagepb.ListUsageRequest) (*usagepb.ListUsageResponse, error) {
	tenantID := identity.TenantFromContext(ctx)
	if tenantID == "" || tenantID == identity.SystemTenant {
		return nil, status_grpc.Error(codes.Unauthenticated, "tenant context required")
	}
	userID, admin, err := s.isTenantAdmin(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	switch req.GetScope() {
	case usagepb.UsageScope_USAGE_SCOPE_USER:
		return s.listUsageByUser(ctx, userID, admin, req)
	case usagepb.UsageScope_USAGE_SCOPE_TEAM:
		if !admin {
			return nil, status_grpc.Error(codes.PermissionDenied, "team usage is admin-only")
		}
		return s.listUsageByTeam(ctx, req)
	case usagepb.UsageScope_USAGE_SCOPE_AGENT:
		if !admin {
			return nil, status_grpc.Error(codes.PermissionDenied, "agent usage is admin-only")
		}
		return s.listUsageByAgent(ctx, req)
	case usagepb.UsageScope_USAGE_SCOPE_MISSION:
		if !admin {
			return nil, status_grpc.Error(codes.PermissionDenied, "mission usage is admin-only")
		}
		return s.listUsageByMission(ctx, req)
	}
	return nil, status_grpc.Error(codes.InvalidArgument, "scope must be user, team, agent, or mission")
}

// listUsageByUser reads per-user budget counters. Non-admins see only
// their own row.
func (s *DaemonServer) listUsageByUser(ctx context.Context, callerID string, admin bool, req *usagepb.ListUsageRequest) (*usagepb.ListUsageResponse, error) {
	enforcer, err := s.budgetEnforcerAdmin()
	if err != nil {
		// Budget not configured → return empty rows, not an error, so
		// the dashboard renders cleanly.
		return &usagepb.ListUsageResponse{}, nil
	}
	statuses, err := enforcer.ListStatusByScope(ctx, budget.ScopeUser)
	if err != nil {
		s.logger.WarnContext(ctx, "usage: ListStatusByScope(user) failed",
			slog.String("error", err.Error()))
		return &usagepb.ListUsageResponse{StaleAsOfUnix: time.Now().Unix()}, nil
	}

	filter := req.GetSubjectFilter()
	if !admin {
		filter = callerID
	}
	resp := &usagepb.ListUsageResponse{
		Rows: make([]*usagepb.UsageRow, 0, len(statuses)),
	}
	for _, st := range statuses {
		if filter != "" && st.SubjectID != filter {
			continue
		}
		resp.Rows = append(resp.Rows, &usagepb.UsageRow{
			SubjectId:    st.SubjectID,
			DisplayName:  st.SubjectID, // user-display-name lookup is a follow-up
			InputTokens:  st.CurrentTokens,
			OutputTokens: 0,
			CostUsdCents: st.CurrentSpendUSDCents,
			TraceCount:   0,
		})
	}
	return resp, nil
}

// listUsageByTeam reads per-team budget counters.
func (s *DaemonServer) listUsageByTeam(ctx context.Context, req *usagepb.ListUsageRequest) (*usagepb.ListUsageResponse, error) {
	enforcer, err := s.budgetEnforcerAdmin()
	if err != nil {
		return &usagepb.ListUsageResponse{}, nil
	}
	statuses, err := enforcer.ListStatusByScope(ctx, budget.ScopeTeam)
	if err != nil {
		s.logger.WarnContext(ctx, "usage: ListStatusByScope(team) failed",
			slog.String("error", err.Error()))
		return &usagepb.ListUsageResponse{StaleAsOfUnix: time.Now().Unix()}, nil
	}
	resp := &usagepb.ListUsageResponse{
		Rows: make([]*usagepb.UsageRow, 0, len(statuses)),
	}
	filter := req.GetSubjectFilter()
	for _, st := range statuses {
		if filter != "" && st.SubjectID != filter {
			continue
		}
		resp.Rows = append(resp.Rows, &usagepb.UsageRow{
			SubjectId:    st.SubjectID,
			DisplayName:  st.SubjectID,
			InputTokens:  st.CurrentTokens,
			CostUsdCents: st.CurrentSpendUSDCents,
		})
	}
	return resp, nil
}

// listUsageByAgent returns an empty response for now — agent-level
// rollups require a ClickHouse query against Langfuse grouped by
// agent_id which is not yet wired. Dashboard renders "no data" when
// Rows is empty rather than erroring.
func (s *DaemonServer) listUsageByAgent(_ context.Context, _ *usagepb.ListUsageRequest) (*usagepb.ListUsageResponse, error) {
	return &usagepb.ListUsageResponse{}, nil
}

// listUsageByMission returns an empty response for the same reason as
// listUsageByAgent.
func (s *DaemonServer) listUsageByMission(_ context.Context, _ *usagepb.ListUsageRequest) (*usagepb.ListUsageResponse, error) {
	return &usagepb.ListUsageResponse{}, nil
}
