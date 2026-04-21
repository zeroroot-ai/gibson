// Package budget implements per-user, per-team, and per-tenant token and
// spend budget enforcement around LLM execution.
//
// Spec: llm-user-attribution-governance (Requirement 3). Complementary to
// the existing per-tenant quota system at internal/component/quota.go —
// that one counts missions / agents / memory; this one counts tokens and
// dollars.
package budget

import (
	"errors"
	"time"
)

// Scope identifies the subject class a budget applies to. Tenant is the
// rollup ceiling; user and team are subdivisions within a tenant.
type Scope string

const (
	ScopeUser   Scope = "user"
	ScopeTeam   Scope = "team"
	ScopeTenant Scope = "tenant"
)

// Budget is the configured ceiling for a single (tenant, scope, subject)
// triple. Zero values on numeric limits mean "unlimited on this
// dimension" — callers interpret accordingly.
type Budget struct {
	// TenantID scopes the budget to one tenant's namespace.
	TenantID string

	// Scope is User, Team, or Tenant.
	Scope Scope

	// SubjectID is the user or team ID. Empty string when Scope is
	// ScopeTenant.
	SubjectID string

	// MonthlyTokens is the hard ceiling on tokens consumed per billing
	// period. 0 means unlimited.
	MonthlyTokens int64

	// MonthlySpendUSDCents is the hard ceiling on LLM spend per billing
	// period, in USD cents (to avoid float arithmetic). 0 means
	// unlimited.
	MonthlySpendUSDCents int64

	// OverrideDeny, when true on a user-scope budget, causes exceedance
	// to be logged and audited but NOT denied. Emergency bypass for
	// on-call operators; admin-only in the dashboard.
	OverrideDeny bool

	// WarningThreshold is the fraction (0.0–1.0) of either limit at
	// which a one-shot warning event fires per period. 0 defaults to
	// DefaultWarningThreshold.
	WarningThreshold float64
}

// DefaultWarningThreshold is the fraction at which a one-shot warning
// fires when a Budget has no explicit WarningThreshold.
const DefaultWarningThreshold = 0.80

// Status reports current usage for a single subject. Returned by
// Enforcer.Check and Enforcer.ListStatusByScope for the dashboard.
type Status struct {
	Scope                Scope
	SubjectID            string
	CurrentTokens        int64
	CurrentSpendUSDCents int64
	TokenLimit           int64
	SpendLimitUSDCents   int64
	PeriodResetAt        time.Time
	WarningCrossed       bool
}

// Error sentinels returned by Enforcer.Check when a call would exceed a
// budget. Mapped to gRPC codes.ResourceExhausted with a
// gibson.budget.v1.BudgetExceeded status detail at the daemon edge.
var (
	ErrTokenBudgetExceededUser    = errors.New("user token budget exceeded")
	ErrTokenBudgetExceededTeam    = errors.New("team token budget exceeded")
	ErrTokenBudgetExceededTenant  = errors.New("tenant token budget exceeded")
	ErrSpendCapExceededUser       = errors.New("user spend cap exceeded")
	ErrSpendCapExceededTeam       = errors.New("team spend cap exceeded")
	ErrSpendCapExceededTenant     = errors.New("tenant spend cap exceeded")
)

// ErrorDetail is populated by the daemon edge when mapping a budget
// error to a gRPC status detail. Kept in this package so the daemon's
// server_provider_exec.go can read the limiting fields uniformly.
type ErrorDetail struct {
	Scope         Scope
	Dimension     string // "tokens" | "spend"
	CurrentUsage  int64
	Limit         int64
	PeriodResetAt time.Time
	SubjectID     string
}

// PeriodID returns the Redis hash key for the given time's billing
// period. Periods are UTC calendar months; format YYYYMM. Separating this
// into a helper keeps the period boundary testable and lets the
// rollover job compute future/past period IDs deterministically.
func PeriodID(t time.Time) string {
	return t.UTC().Format("200601")
}

// PeriodResetAt returns the UTC time the given period's counters roll
// over (midnight on day 1 of the following month).
func PeriodResetAt(t time.Time) time.Time {
	y, m, _ := t.UTC().Date()
	return time.Date(y, m+1, 1, 0, 0, 0, 0, time.UTC)
}
