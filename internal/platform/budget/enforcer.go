package budget

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/zeroroot-ai/gibson/internal/billing/entitlements"
	"github.com/zeroroot-ai/sdk/auth"
)

// Enforcer is the surface the daemon's ExecuteLLM handler calls to gate
// LLM dispatch against configured budgets. Implementations are safe for
// concurrent use.
//
// Check/Record precedence: user → team(s) → tenant. Check returns the
// most-constrained error; Record updates every applicable scope
// atomically via a single Lua script.
type Enforcer interface {
	// Check returns an error when the projected-post-call usage would
	// exceed any applicable budget. estimatedTokens is a conservative
	// estimate (prompt_tokens + max_tokens). The returned Status carries
	// the most-constrained scope's current numbers so callers can write
	// a warning span attribute when the threshold is approached without
	// being denied.
	Check(ctx context.Context, estimatedTokens int64) (*Status, error)

	// Record atomically increments counters on every applicable scope
	// with the authoritative usage returned by the provider. Called
	// after a successful LLM call.
	Record(ctx context.Context, actualTokens int64, actualCostUSDCents int64) error

	// GetBudget returns the stored budget for (scope, subjectID) in the
	// tenant taken from ctx. Returns (nil, nil) when no explicit budget
	// is set — callers treat absence as "tenant default applies".
	GetBudget(ctx context.Context, scope Scope, subjectID string) (*Budget, error)

	// SetBudget persists a budget. tenantID is taken from budget.TenantID
	// when non-empty, else from ctx.
	SetBudget(ctx context.Context, b *Budget) error

	// ListStatusByScope returns current usage for every subject with a
	// configured budget in the given scope. Tenant taken from ctx.
	ListStatusByScope(ctx context.Context, scope Scope) ([]*Status, error)
}

// TeamMembershipResolver returns the team IDs the current user belongs
// to within the tenant. Injected at Enforcer construction so the budget
// package does not depend on FGA directly.
//
// Default (nil resolver): team-scope checks are no-ops — Check/Record
// still work at user + tenant scope.
type TeamMembershipResolver func(ctx context.Context, tenantID, userID string) ([]string, error)

// Clock is the time source used by the enforcer. Pluggable for tests;
// production uses time.Now.
type Clock func() time.Time

// redisEnforcer is the Redis-backed Enforcer implementation. Fields are
// unexported because callers should not depend on the concrete type.
type redisEnforcer struct {
	rdb      redis.UniversalClient
	logger   *slog.Logger
	teams    TeamMembershipResolver
	clock    Clock
	provider entitlements.Provider
	checkLs  *redis.Script
	recLs    *redis.Script
}

// NewEnforcer constructs an Enforcer backed by the given Redis client.
// Pass teamResolver=nil to disable team-scope enforcement.
//
// Limits flow through the ADR-0003 entitlements seam: explicit admin-set
// budgets (the Redis budget:* config) always win, and when no explicit
// tenant-scope budget exists the enforcer falls back to the entitlements
// Provider's per-tenant default token/spend ceilings. A nil Provider (or the
// OSS default's zero Limits) means "no provider-supplied ceiling" — i.e.
// unlimited unless an admin set one. The enforcer therefore never reads
// plans or Stripe directly.
func NewEnforcer(rdb redis.UniversalClient, logger *slog.Logger, teamResolver TeamMembershipResolver, clock Clock, provider entitlements.Provider) Enforcer {
	if logger == nil {
		logger = slog.Default()
	}
	if clock == nil {
		clock = time.Now
	}
	return &redisEnforcer{
		rdb:      rdb,
		logger:   logger.With("component", "budget_enforcer"),
		teams:    teamResolver,
		clock:    clock,
		provider: entitlements.Resolve(provider),
		checkLs:  redis.NewScript(luaCheck),
		recLs:    redis.NewScript(luaRecord),
	}
}

// Redis key layout (all keys are tenant-scoped already via the prefix):
//
//	budget:tenant:{tenant}:user:{user}:config          JSON Budget
//	budget:tenant:{tenant}:team:{team}:config          JSON Budget
//	budget:tenant:{tenant}:defaults                    JSON Budget (tenant defaults)
//	budget:tenant:{tenant}:user:{user}:period:{YYYYMM} HASH {tokens, cost_cents}
//	budget:tenant:{tenant}:team:{team}:period:{YYYYMM} HASH {tokens, cost_cents}
//	budget:tenant:{tenant}:period:{YYYYMM}             HASH {tokens, cost_cents}
//	budget:tenant:{tenant}:user:{user}:period:{YYYYMM}:warn  "1" 35-day TTL
//	budget:tenant:{tenant}:team:{team}:period:{YYYYMM}:warn
//	budget:tenant:{tenant}:period:{YYYYMM}:warn
func configKey(tenantID string, scope Scope, subjectID string) string {
	switch scope {
	case ScopeTenant:
		return fmt.Sprintf("budget:tenant:%s:defaults", tenantID)
	case ScopeUser:
		return fmt.Sprintf("budget:tenant:%s:user:%s:config", tenantID, subjectID)
	case ScopeTeam:
		return fmt.Sprintf("budget:tenant:%s:team:%s:config", tenantID, subjectID)
	}
	return ""
}

func counterKey(tenantID string, scope Scope, subjectID, period string) string {
	switch scope {
	case ScopeTenant:
		return fmt.Sprintf("budget:tenant:%s:period:%s", tenantID, period)
	case ScopeUser:
		return fmt.Sprintf("budget:tenant:%s:user:%s:period:%s", tenantID, subjectID, period)
	case ScopeTeam:
		return fmt.Sprintf("budget:tenant:%s:team:%s:period:%s", tenantID, subjectID, period)
	}
	return ""
}

func warnKey(counter string) string { return counter + ":warn" }

// luaCheck runs a single-read check: for a counter key, returns the
// current tokens + cost. Atomicity against concurrent Record calls is
// delivered by the Record Lua script's INCR, not by Check — Check is
// read-only (projection happens in Go). We still use a Lua script to
// read both fields in one RTT and to be consistent with Record.
//
// KEYS[1] = counter key (hash)
// returns: {tokens, cost_cents}
const luaCheck = `
local vals = redis.call('HMGET', KEYS[1], 'tokens', 'cost_cents')
local t = tonumber(vals[1]) or 0
local c = tonumber(vals[2]) or 0
return {t, c}
`

// luaRecord atomically increments tokens and cost_cents on the counter
// hash, sets an EXPIRE if the hash was just created (TTL = 40 days; covers
// the current period + a retention margin for reconciliation), and
// returns the post-increment values so callers can surface warning
// thresholds.
//
// KEYS[1] = counter key (hash)
// ARGV[1] = tokens delta
// ARGV[2] = cost_cents delta
// returns: {tokens_after, cost_after}
const luaRecord = `
local tok = redis.call('HINCRBY', KEYS[1], 'tokens', ARGV[1])
local cost = redis.call('HINCRBY', KEYS[1], 'cost_cents', ARGV[2])
local ttl = redis.call('TTL', KEYS[1])
if ttl < 0 then
  redis.call('EXPIRE', KEYS[1], 3456000)
end
return {tok, cost}
`

// scopeSubject resolves the (scope, subjectID) pair for the calling user
// in the given scope. For ScopeTenant returns ("", true). For ScopeUser
// returns the ActingUser. For ScopeTeam callers should iterate the
// resolver result.
func scopeSubject(ctx context.Context, scope Scope) (string, bool) {
	switch scope {
	case ScopeTenant:
		return "", true
	case ScopeUser:
		if uid, ok := auth.ActingUserFromContext(ctx); ok && uid != "" {
			return uid, true
		}
		// Fall back to the initiator user when Acting is unset — this
		// happens on scheduled / autonomous mission goroutines where the
		// caller context is no longer synchronous.
		if uid, ok := auth.InitiatorUserFromContext(ctx); ok && uid != "" {
			return uid, true
		}
	}
	return "", false
}

// resolveTeams returns the team IDs applicable to the current user, or
// nil if no team resolver is wired. Errors are logged and treated as
// "no teams" to fail open rather than blocking the call.
func (e *redisEnforcer) resolveTeams(ctx context.Context, tenantID, userID string) []string {
	if e.teams == nil {
		return nil
	}
	teams, err := e.teams(ctx, tenantID, userID)
	if err != nil {
		e.logger.WarnContext(ctx, "budget: team membership resolution failed; skipping team-scope enforcement",
			slog.String("error", err.Error()),
			slog.String("tenant_id", tenantID),
			slog.String("user_id", userID),
		)
		return nil
	}
	return teams
}

// loadTenantBudget returns the tenant-scope budget. An explicit admin-set
// tenant default (Redis budget:tenant:{t}:defaults) always wins; when absent,
// the enforcer falls back to the entitlements Provider's per-tenant default
// token/spend ceilings (ADR-0003 seam). Returns nil when neither source sets
// a ceiling — meaning unlimited at tenant scope.
func (e *redisEnforcer) loadTenantBudget(ctx context.Context, tenantID string) *Budget {
	if b, _ := e.loadBudget(ctx, configKey(tenantID, ScopeTenant, "")); b != nil {
		return b
	}
	lim, err := e.provider.Limits(ctx, tenantID)
	if err != nil {
		e.logger.WarnContext(ctx, "budget: entitlements provider lookup failed; treating tenant as unlimited",
			slog.String("error", err.Error()),
			slog.String("tenant_id", tenantID),
		)
		return nil
	}
	if lim.MonthlyTokens == 0 && lim.MonthlySpendUSDCents == 0 {
		return nil
	}
	return &Budget{
		TenantID:             tenantID,
		Scope:                ScopeTenant,
		MonthlyTokens:        lim.MonthlyTokens,
		MonthlySpendUSDCents: lim.MonthlySpendUSDCents,
	}
}

// loadBudget reads a config entry; returns (nil, nil) when absent.
func (e *redisEnforcer) loadBudget(ctx context.Context, key string) (*Budget, error) {
	raw, err := e.rdb.Get(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get budget %s: %w", key, err)
	}
	var b Budget
	if err := json.Unmarshal([]byte(raw), &b); err != nil {
		return nil, fmt.Errorf("unmarshal budget %s: %w", key, err)
	}
	return &b, nil
}

// readCounter reads a period hash; returns (0, 0) on MISS or error (fail
// open — we don't want to block LLM calls because Redis flaked).
func (e *redisEnforcer) readCounter(ctx context.Context, key string) (tokens int64, cost int64) {
	res, err := e.checkLs.Run(ctx, e.rdb, []string{key}).Result()
	if err != nil {
		e.logger.WarnContext(ctx, "budget: counter read failed; treating as zero",
			slog.String("error", err.Error()),
			slog.String("key", key),
		)
		return 0, 0
	}
	vals, ok := res.([]any)
	if !ok || len(vals) != 2 {
		return 0, 0
	}
	if v, ok := vals[0].(int64); ok {
		tokens = v
	}
	if v, ok := vals[1].(int64); ok {
		cost = v
	}
	return tokens, cost
}

// Check implements Enforcer.Check. Read-only against Redis: projects
// (current + estimated) against each applicable budget and returns the
// most-constrained error.
func (e *redisEnforcer) Check(ctx context.Context, estimatedTokens int64) (*Status, error) {
	tenantID := auth.TenantStringFromContext(ctx)
	now := e.clock()
	period := PeriodID(now)
	resetAt := PeriodResetAt(now)

	// Tenant check. The tenant-scope ceiling comes from the explicit admin
	// default if set, else the entitlements provider (ADR-0003 seam).
	tenantBudget := e.loadTenantBudget(ctx, tenantID)
	tenantTokens, tenantCost := e.readCounter(ctx, counterKey(tenantID, ScopeTenant, "", period))
	if err := exceedsTokens(tenantBudget, tenantTokens+estimatedTokens); err != nil {
		return nil, wrapExceed(ScopeTenant, "", tenantTokens, estimatedTokens, tenantBudget, resetAt, err)
	}

	// Team check(s).
	userID, userOK := scopeSubject(ctx, ScopeUser)
	if userOK {
		for _, teamID := range e.resolveTeams(ctx, tenantID, userID) {
			teamBudget, _ := e.loadBudget(ctx, configKey(tenantID, ScopeTeam, teamID))
			tt, _ := e.readCounter(ctx, counterKey(tenantID, ScopeTeam, teamID, period))
			if err := exceedsTokens(teamBudget, tt+estimatedTokens); err != nil {
				return nil, wrapExceed(ScopeTeam, teamID, tt, estimatedTokens, teamBudget, resetAt, err)
			}
		}
	}

	// User check.
	var userStatus *Status
	if userOK {
		userBudget, _ := e.loadBudget(ctx, configKey(tenantID, ScopeUser, userID))
		ut, uc := e.readCounter(ctx, counterKey(tenantID, ScopeUser, userID, period))
		if err := exceedsTokens(userBudget, ut+estimatedTokens); err != nil {
			// OverrideDeny flag: log + audit, pass the call through.
			if userBudget != nil && userBudget.OverrideDeny {
				e.logger.WarnContext(ctx, "budget: user override_deny=true, allowing call despite exceedance",
					slog.String("user_id", userID),
					slog.Int64("projected", ut+estimatedTokens),
					slog.Int64("limit", userBudget.MonthlyTokens),
				)
			} else {
				return nil, wrapExceed(ScopeUser, userID, ut, estimatedTokens, userBudget, resetAt, err)
			}
		}
		userStatus = buildStatus(ScopeUser, userID, ut, uc, userBudget, resetAt)
	}
	if userStatus != nil {
		return userStatus, nil
	}
	return buildStatus(ScopeTenant, "", tenantTokens, tenantCost, tenantBudget, resetAt), nil
}

// Record implements Enforcer.Record. Atomically increments each
// applicable scope's counter.
func (e *redisEnforcer) Record(ctx context.Context, actualTokens, actualCostUSDCents int64) error {
	tenantID := auth.TenantStringFromContext(ctx)
	period := PeriodID(e.clock())

	// Tenant counter.
	e.recordOne(ctx, counterKey(tenantID, ScopeTenant, "", period), actualTokens, actualCostUSDCents)

	// User counter.
	userID, userOK := scopeSubject(ctx, ScopeUser)
	if userOK {
		e.recordOne(ctx, counterKey(tenantID, ScopeUser, userID, period), actualTokens, actualCostUSDCents)
		for _, teamID := range e.resolveTeams(ctx, tenantID, userID) {
			e.recordOne(ctx, counterKey(tenantID, ScopeTeam, teamID, period), actualTokens, actualCostUSDCents)
		}
	}
	return nil
}

func (e *redisEnforcer) recordOne(ctx context.Context, key string, tokens, cost int64) {
	if _, err := e.recLs.Run(ctx, e.rdb, []string{key}, tokens, cost).Result(); err != nil {
		// Fail open — log and move on. Budget counters are advisory;
		// blocking an LLM response because Redis blipped is worse than
		// a transient under-count.
		e.logger.WarnContext(ctx, "budget: record increment failed",
			slog.String("error", err.Error()),
			slog.String("key", key),
		)
	}
}

// GetBudget implements Enforcer.GetBudget.
func (e *redisEnforcer) GetBudget(ctx context.Context, scope Scope, subjectID string) (*Budget, error) {
	tenantID := auth.TenantStringFromContext(ctx)
	return e.loadBudget(ctx, configKey(tenantID, scope, subjectID))
}

// SetBudget implements Enforcer.SetBudget.
func (e *redisEnforcer) SetBudget(ctx context.Context, b *Budget) error {
	if b == nil {
		return errors.New("budget must not be nil")
	}
	if b.TenantID == "" {
		b.TenantID = auth.TenantStringFromContext(ctx)
	}
	data, err := json.Marshal(b)
	if err != nil {
		return fmt.Errorf("marshal budget: %w", err)
	}
	key := configKey(b.TenantID, b.Scope, b.SubjectID)
	if err := e.rdb.Set(ctx, key, data, 0).Err(); err != nil {
		return fmt.Errorf("set budget %s: %w", key, err)
	}
	return nil
}

// ListStatusByScope implements Enforcer.ListStatusByScope. Scans the
// tenant's configured budgets in the requested scope and returns
// current period usage for each. Used by the dashboard's usage page.
func (e *redisEnforcer) ListStatusByScope(ctx context.Context, scope Scope) ([]*Status, error) {
	tenantID := auth.TenantStringFromContext(ctx)
	now := e.clock()
	period := PeriodID(now)
	resetAt := PeriodResetAt(now)

	var pattern string
	switch scope {
	case ScopeUser:
		pattern = fmt.Sprintf("budget:tenant:%s:user:*:config", tenantID)
	case ScopeTeam:
		pattern = fmt.Sprintf("budget:tenant:%s:team:*:config", tenantID)
	case ScopeTenant:
		pattern = fmt.Sprintf("budget:tenant:%s:defaults", tenantID)
	default:
		return nil, fmt.Errorf("unsupported scope: %q", scope)
	}

	var result []*Status
	iter := e.rdb.Scan(ctx, 0, pattern, 0).Iterator()
	for iter.Next(ctx) {
		key := iter.Val()
		b, err := e.loadBudget(ctx, key)
		if err != nil || b == nil {
			continue
		}
		tokens, cost := e.readCounter(ctx, counterKey(tenantID, scope, b.SubjectID, period))
		result = append(result, buildStatus(scope, b.SubjectID, tokens, cost, b, resetAt))
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("scan budgets: %w", err)
	}
	return result, nil
}

// exceedsTokens returns the appropriate sentinel error when projected
// exceeds budget.MonthlyTokens; returns nil otherwise. Nil budget
// (unconfigured) always returns nil — no budget = unlimited.
func exceedsTokens(b *Budget, projected int64) error {
	if b == nil || b.MonthlyTokens == 0 || projected <= b.MonthlyTokens {
		return nil
	}
	return errSentinelForScope(b.Scope, "tokens")
}

func errSentinelForScope(scope Scope, dim string) error {
	switch {
	case scope == ScopeUser && dim == "tokens":
		return ErrTokenBudgetExceededUser
	case scope == ScopeTeam && dim == "tokens":
		return ErrTokenBudgetExceededTeam
	case scope == ScopeTenant && dim == "tokens":
		return ErrTokenBudgetExceededTenant
	case scope == ScopeUser && dim == "spend":
		return ErrSpendCapExceededUser
	case scope == ScopeTeam && dim == "spend":
		return ErrSpendCapExceededTeam
	case scope == ScopeTenant && dim == "spend":
		return ErrSpendCapExceededTenant
	}
	return fmt.Errorf("budget exceeded")
}

// wrapExceed bundles an exceedance error with a detail-carrying wrapper
// so the daemon edge can populate the gRPC status detail.
func wrapExceed(scope Scope, subjectID string, current, est int64, budget *Budget, resetAt time.Time, err error) error {
	d := ErrorDetail{
		Scope:         scope,
		Dimension:     "tokens",
		CurrentUsage:  current + est,
		Limit:         0,
		PeriodResetAt: resetAt,
		SubjectID:     subjectID,
	}
	if budget != nil {
		d.Limit = budget.MonthlyTokens
	}
	return &exceedError{Detail: d, inner: err}
}

// exceedError bundles a sentinel error with an ErrorDetail. The daemon
// edge uses errors.As to extract Detail and map it to the proto
// BudgetExceeded status detail.
type exceedError struct {
	Detail ErrorDetail
	inner  error
}

func (e *exceedError) Error() string { return e.inner.Error() }
func (e *exceedError) Unwrap() error { return e.inner }

// DetailFromError returns the ErrorDetail embedded in an exceedance
// error, or (zero, false) if the error is not a budget exceedance.
// Used by the daemon's ExecuteLLM handler to build the gRPC status.
func DetailFromError(err error) (ErrorDetail, bool) {
	var e *exceedError
	if errors.As(err, &e) {
		return e.Detail, true
	}
	return ErrorDetail{}, false
}

// buildStatus builds a Status from observed counters + the configured
// budget. warningCrossed is true when either dimension is at or above
// the configured warning threshold.
func buildStatus(scope Scope, subjectID string, tokens, cost int64, b *Budget, resetAt time.Time) *Status {
	s := &Status{
		Scope:                scope,
		SubjectID:            subjectID,
		CurrentTokens:        tokens,
		CurrentSpendUSDCents: cost,
		PeriodResetAt:        resetAt,
	}
	if b == nil {
		return s
	}
	s.TokenLimit = b.MonthlyTokens
	s.SpendLimitUSDCents = b.MonthlySpendUSDCents
	threshold := b.WarningThreshold
	if threshold == 0 {
		threshold = DefaultWarningThreshold
	}
	if b.MonthlyTokens > 0 && float64(tokens)/float64(b.MonthlyTokens) >= threshold {
		s.WarningCrossed = true
	}
	if b.MonthlySpendUSDCents > 0 && float64(cost)/float64(b.MonthlySpendUSDCents) >= threshold {
		s.WarningCrossed = true
	}
	return s
}
