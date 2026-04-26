package api

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	"github.com/zero-day-ai/gibson/internal/budget"
	"github.com/zero-day-ai/sdk/auth"
	budgetpb "github.com/zero-day-ai/sdk/api/gen/gibson/budget/v1"
)

// Package server_budget.go — DaemonServer implementation of
// gibson.budget.v1.BudgetService. Dashboard-facing API for configuring
// token/spend budgets and reading current usage.
//
// Spec: llm-user-attribution-governance (Requirement 3, 5). Admin-only
// mutations (gated via tenant#admin FGA check); non-admins can read only
// their own budget/status.

// budgetEnforcerAdminIface is the broader subset of internal/budget.Enforcer
// used by admin CRUD handlers (not just Check/Record).
type budgetEnforcerAdminIface interface {
	budgetEnforcerIface
	GetBudget(ctx context.Context, scope budget.Scope, subjectID string) (*budget.Budget, error)
	SetBudget(ctx context.Context, b *budget.Budget) error
	ListStatusByScope(ctx context.Context, scope budget.Scope) ([]*budget.Status, error)
}

// isTenantAdmin checks FGA tenant#admin@user:<caller>. Degrades to false
// (non-admin) when the authorizer is unwired or check errors.
func (s *DaemonServer) isTenantAdmin(ctx context.Context, tenantID string) (string, bool, error) {
	callerID, err := auth.IdentityFromContext(ctx)
	if err != nil {
		return "", false, status_grpc.Error(codes.Unauthenticated, "user identity not found")
	}
	userID := callerID.Subject
	if userID == "" {
		return "", false, status_grpc.Error(codes.Unauthenticated, "user identity missing subject")
	}
	if s.authorizer == nil {
		return userID, false, nil
	}
	ok, err := s.authorizer.Check(ctx,
		fmt.Sprintf("user:%s", userID), "admin",
		fmt.Sprintf("tenant:%s", tenantID),
	)
	if err != nil {
		s.logger.WarnContext(ctx, "budget: admin check failed",
			slog.String("tenant_id", tenantID), slog.String("user_id", userID), slog.String("error", err.Error()))
		return userID, false, nil
	}
	return userID, ok, nil
}

// budgetEnforcerAdmin returns the enforcer cast to the admin iface, or
// an error when no admin-capable enforcer is wired. Keeps handlers
// from taking a nil-deref when the platform hasn't enabled budgets.
func (s *DaemonServer) budgetEnforcerAdmin() (budgetEnforcerAdminIface, error) {
	if s.budgetEnforcer == nil {
		return nil, status_grpc.Error(codes.FailedPrecondition, "budget enforcement is not configured")
	}
	admin, ok := s.budgetEnforcer.(budgetEnforcerAdminIface)
	if !ok {
		return nil, status_grpc.Error(codes.FailedPrecondition, "budget enforcer does not support admin operations")
	}
	return admin, nil
}

// scopeFromProto maps the wire enum to the internal Scope.
func scopeFromProto(s budgetpb.BudgetScope) (budget.Scope, error) {
	switch s {
	case budgetpb.BudgetScope_BUDGET_SCOPE_USER:
		return budget.ScopeUser, nil
	case budgetpb.BudgetScope_BUDGET_SCOPE_TEAM:
		return budget.ScopeTeam, nil
	case budgetpb.BudgetScope_BUDGET_SCOPE_TENANT:
		return budget.ScopeTenant, nil
	}
	return "", status_grpc.Error(codes.InvalidArgument, "scope must be user, team, or tenant")
}

func budgetToProto(b *budget.Budget) *budgetpb.Budget {
	if b == nil {
		return nil
	}
	return &budgetpb.Budget{
		TenantId:             b.TenantID,
		Scope:                budgetScopeToProto(b.Scope),
		SubjectId:            b.SubjectID,
		MonthlyTokens:        b.MonthlyTokens,
		MonthlySpendUsdCents: b.MonthlySpendUSDCents,
		OverrideDeny:         b.OverrideDeny,
		WarningThreshold:     b.WarningThreshold,
	}
}

func budgetFromProto(p *budgetpb.Budget) (*budget.Budget, error) {
	if p == nil {
		return nil, status_grpc.Error(codes.InvalidArgument, "budget must not be nil")
	}
	scope, err := scopeFromProto(p.GetScope())
	if err != nil {
		return nil, err
	}
	return &budget.Budget{
		TenantID:             p.GetTenantId(),
		Scope:                scope,
		SubjectID:            p.GetSubjectId(),
		MonthlyTokens:        p.GetMonthlyTokens(),
		MonthlySpendUSDCents: p.GetMonthlySpendUsdCents(),
		OverrideDeny:         p.GetOverrideDeny(),
		WarningThreshold:     p.GetWarningThreshold(),
	}, nil
}

func statusToProto(s *budget.Status) *budgetpb.BudgetStatus {
	if s == nil {
		return nil
	}
	return &budgetpb.BudgetStatus{
		Scope:                budgetScopeToProto(s.Scope),
		SubjectId:            s.SubjectID,
		CurrentTokens:        s.CurrentTokens,
		CurrentSpendUsdCents: s.CurrentSpendUSDCents,
		TokenLimit:           s.TokenLimit,
		SpendLimitUsdCents:   s.SpendLimitUSDCents,
		PeriodResetAtUnix:    s.PeriodResetAt.Unix(),
		WarningCrossed:       s.WarningCrossed,
	}
}

// ---------------------------------------------------------------------------
// RPC handlers
// ---------------------------------------------------------------------------

// GetBudget returns the configured budget for the given (scope, subject).
// Non-admins may only read their own user-scope budget. Tenant defaults
// are readable by any authenticated caller within the tenant.
func (s *DaemonServer) GetBudget(ctx context.Context, req *budgetpb.GetBudgetRequest) (*budgetpb.GetBudgetResponse, error) {
	tenantID := auth.TenantStringFromContext(ctx)
	if tenantID == "" || tenantID == auth.SystemTenantString {
		return nil, status_grpc.Error(codes.Unauthenticated, "tenant context required")
	}

	scope, err := scopeFromProto(req.GetScope())
	if err != nil {
		return nil, err
	}

	userID, admin, err := s.isTenantAdmin(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	// Non-admin narrowing: can only read own user-scope budget.
	if !admin && scope == budget.ScopeUser && req.GetSubjectId() != userID {
		return nil, status_grpc.Error(codes.PermissionDenied, "non-admin users can only read their own budget")
	}
	if !admin && scope == budget.ScopeTeam {
		return nil, status_grpc.Error(codes.PermissionDenied, "team budgets are admin-only")
	}

	admin2, err := s.budgetEnforcerAdmin()
	if err != nil {
		return nil, err
	}
	b, err := admin2.GetBudget(ctx, scope, req.GetSubjectId())
	if err != nil {
		s.logger.WarnContext(ctx, "budget: GetBudget failed",
			slog.String("error", err.Error()), slog.String("tenant", tenantID))
		return nil, status_grpc.Error(codes.Internal, "failed to read budget")
	}
	return &budgetpb.GetBudgetResponse{
		Budget: budgetToProto(b),
		Found:  b != nil,
	}, nil
}

// SetBudget persists a budget. Tenant-admin only.
func (s *DaemonServer) SetBudget(ctx context.Context, req *budgetpb.SetBudgetRequest) (*budgetpb.SetBudgetResponse, error) {
	tenantID := auth.TenantStringFromContext(ctx)
	if tenantID == "" || tenantID == auth.SystemTenantString {
		return nil, status_grpc.Error(codes.Unauthenticated, "tenant context required")
	}
	if err := s.requireTenantAdmin(ctx, tenantID); err != nil {
		return nil, err
	}
	b, err := budgetFromProto(req.GetBudget())
	if err != nil {
		return nil, err
	}
	b.TenantID = tenantID // ignore client-provided TenantID to prevent cross-tenant writes

	admin, err := s.budgetEnforcerAdmin()
	if err != nil {
		return nil, err
	}
	if err := admin.SetBudget(ctx, b); err != nil {
		s.logger.WarnContext(ctx, "budget: SetBudget failed",
			slog.String("error", err.Error()), slog.String("tenant", tenantID))
		return nil, status_grpc.Error(codes.Internal, "failed to persist budget")
	}
	return &budgetpb.SetBudgetResponse{Budget: budgetToProto(b)}, nil
}

// ListBudgets returns all configured budgets in the given scope. Admin-only
// for user and team scopes; any caller can list tenant defaults.
func (s *DaemonServer) ListBudgets(ctx context.Context, req *budgetpb.ListBudgetsRequest) (*budgetpb.ListBudgetsResponse, error) {
	tenantID := auth.TenantStringFromContext(ctx)
	if tenantID == "" || tenantID == auth.SystemTenantString {
		return nil, status_grpc.Error(codes.Unauthenticated, "tenant context required")
	}
	scope, err := scopeFromProto(req.GetScope())
	if err != nil {
		return nil, err
	}
	if scope != budget.ScopeTenant {
		if err := s.requireTenantAdmin(ctx, tenantID); err != nil {
			return nil, err
		}
	}

	admin, err := s.budgetEnforcerAdmin()
	if err != nil {
		return nil, err
	}
	statuses, err := admin.ListStatusByScope(ctx, scope)
	if err != nil {
		s.logger.WarnContext(ctx, "budget: ListStatusByScope failed",
			slog.String("error", err.Error()), slog.String("tenant", tenantID))
		return nil, status_grpc.Error(codes.Internal, "failed to list budgets")
	}
	// Materialise Budget records from the statuses so the dashboard has
	// the configured limits without a second round-trip per subject.
	resp := &budgetpb.ListBudgetsResponse{Budgets: make([]*budgetpb.Budget, 0, len(statuses))}
	for _, st := range statuses {
		b, err := admin.GetBudget(ctx, st.Scope, st.SubjectID)
		if err != nil || b == nil {
			continue
		}
		resp.Budgets = append(resp.Budgets, budgetToProto(b))
	}
	return resp, nil
}

// ListStatus returns current usage for every subject in scope. Same
// narrowing rules as ListBudgets.
func (s *DaemonServer) ListStatus(ctx context.Context, req *budgetpb.ListStatusRequest) (*budgetpb.ListStatusResponse, error) {
	tenantID := auth.TenantStringFromContext(ctx)
	if tenantID == "" || tenantID == auth.SystemTenantString {
		return nil, status_grpc.Error(codes.Unauthenticated, "tenant context required")
	}
	scope, err := scopeFromProto(req.GetScope())
	if err != nil {
		return nil, err
	}
	userID, admin, err := s.isTenantAdmin(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	enforcer, err := s.budgetEnforcerAdmin()
	if err != nil {
		return nil, err
	}
	statuses, err := enforcer.ListStatusByScope(ctx, scope)
	if err != nil {
		s.logger.WarnContext(ctx, "budget: ListStatusByScope failed",
			slog.String("error", err.Error()), slog.String("tenant", tenantID))
		return nil, status_grpc.Error(codes.Internal, "failed to list status")
	}

	resp := &budgetpb.ListStatusResponse{Status: make([]*budgetpb.BudgetStatus, 0, len(statuses))}
	for _, st := range statuses {
		// Non-admin narrowing: user-scope list filters to self.
		if !admin && scope == budget.ScopeUser && st.SubjectID != userID {
			continue
		}
		if !admin && scope == budget.ScopeTeam {
			// Team-scope list is admin-only for now.
			continue
		}
		resp.Status = append(resp.Status, statusToProto(st))
	}
	return resp, nil
}

// GetTenantDefaults returns the tenant-level defaults. Any tenant member
// can read (so they can see what applies to them by default).
func (s *DaemonServer) GetTenantDefaults(ctx context.Context, _ *budgetpb.GetTenantDefaultsRequest) (*budgetpb.GetTenantDefaultsResponse, error) {
	tenantID := auth.TenantStringFromContext(ctx)
	if tenantID == "" || tenantID == auth.SystemTenantString {
		return nil, status_grpc.Error(codes.Unauthenticated, "tenant context required")
	}
	admin, err := s.budgetEnforcerAdmin()
	if err != nil {
		return nil, err
	}
	b, err := admin.GetBudget(ctx, budget.ScopeTenant, "")
	if err != nil {
		s.logger.WarnContext(ctx, "budget: GetTenantDefaults failed",
			slog.String("error", err.Error()), slog.String("tenant", tenantID))
		return nil, status_grpc.Error(codes.Internal, "failed to read tenant defaults")
	}
	resp := &budgetpb.GetTenantDefaultsResponse{}
	if b != nil {
		// "Tenant defaults" share the Budget shape; monthly_tokens /
		// monthly_spend_usd_cents apply to any user without an explicit
		// override.
		resp.DefaultUserMonthlyTokens = b.MonthlyTokens
		resp.DefaultUserMonthlySpendUsdCents = b.MonthlySpendUSDCents
		resp.DefaultWarningThreshold = b.WarningThreshold
	}
	return resp, nil
}

// SetTenantDefaults persists the tenant-level defaults. Tenant-admin only.
func (s *DaemonServer) SetTenantDefaults(ctx context.Context, req *budgetpb.SetTenantDefaultsRequest) (*budgetpb.SetTenantDefaultsResponse, error) {
	tenantID := auth.TenantStringFromContext(ctx)
	if tenantID == "" || tenantID == auth.SystemTenantString {
		return nil, status_grpc.Error(codes.Unauthenticated, "tenant context required")
	}
	if err := s.requireTenantAdmin(ctx, tenantID); err != nil {
		return nil, err
	}
	admin, err := s.budgetEnforcerAdmin()
	if err != nil {
		return nil, err
	}
	// Tenant defaults stored as a synthetic tenant-scope Budget.
	b := &budget.Budget{
		TenantID:             tenantID,
		Scope:                budget.ScopeTenant,
		MonthlyTokens:        req.GetDefaultUserMonthlyTokens(),
		MonthlySpendUSDCents: req.GetDefaultUserMonthlySpendUsdCents(),
		WarningThreshold:     req.GetDefaultWarningThreshold(),
	}
	if err := admin.SetBudget(ctx, b); err != nil {
		s.logger.WarnContext(ctx, "budget: SetTenantDefaults failed",
			slog.String("error", err.Error()), slog.String("tenant", tenantID))
		return nil, status_grpc.Error(codes.Internal, "failed to persist tenant defaults")
	}
	return &budgetpb.SetTenantDefaultsResponse{
		AppliedAtUnix: time.Now().Unix(),
	}, nil
}
