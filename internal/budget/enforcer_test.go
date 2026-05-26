package budget

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/sdk/auth"
)

// fixedClock returns a deterministic time for period-boundary tests.
func fixedClock(t time.Time) Clock { return func() time.Time { return t } }

// newEnforcer spins up a miniredis-backed enforcer for a single test.
// Tenant + user identity is baked into the returned ctx so subtests
// don't have to re-wire the same context chain.
func newEnforcer(t *testing.T, tenantID, userID string) (Enforcer, context.Context, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	// All assertions use the default clock (time.Now) unless noted.
	e := NewEnforcer(rdb, nil, nil, nil)

	ctx := auth.ContextWithTenantString(context.Background(), tenantID)
	ctx = auth.ContextWithActingUser(ctx, userID)
	return e, ctx, mr
}

func TestEnforcer_Check_NoBudget_AllowsUnlimited(t *testing.T) {
	e, ctx, _ := newEnforcer(t, "acme", "user-1")
	status, err := e.Check(ctx, 100_000)
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.Equal(t, int64(0), status.CurrentTokens)
	assert.Equal(t, int64(0), status.TokenLimit, "no budget = unlimited")
}

func TestEnforcer_SetGet_RoundTrip(t *testing.T) {
	e, ctx, _ := newEnforcer(t, "acme", "user-1")
	b := &Budget{
		TenantID:      "acme",
		Scope:         ScopeUser,
		SubjectID:     "user-1",
		MonthlyTokens: 10000,
	}
	require.NoError(t, e.SetBudget(ctx, b))

	got, err := e.GetBudget(ctx, ScopeUser, "user-1")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, int64(10000), got.MonthlyTokens)
	assert.Equal(t, ScopeUser, got.Scope)
}

func TestEnforcer_Check_UnderLimit_Allows(t *testing.T) {
	e, ctx, _ := newEnforcer(t, "acme", "user-1")
	require.NoError(t, e.SetBudget(ctx, &Budget{
		Scope: ScopeUser, SubjectID: "user-1", MonthlyTokens: 10000,
	}))

	status, err := e.Check(ctx, 1000)
	require.NoError(t, err)
	assert.False(t, status.WarningCrossed)
}

func TestEnforcer_Check_OverUserLimit_ReturnsErrUser(t *testing.T) {
	e, ctx, _ := newEnforcer(t, "acme", "user-1")
	require.NoError(t, e.SetBudget(ctx, &Budget{
		Scope: ScopeUser, SubjectID: "user-1", MonthlyTokens: 1000,
	}))

	_, err := e.Check(ctx, 1500)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTokenBudgetExceededUser)

	detail, ok := DetailFromError(err)
	require.True(t, ok, "expected ErrorDetail wrapped on exceedance")
	assert.Equal(t, ScopeUser, detail.Scope)
	assert.Equal(t, "tokens", detail.Dimension)
	assert.Equal(t, int64(1000), detail.Limit)
	assert.Equal(t, "user-1", detail.SubjectID)
}

func TestEnforcer_Check_OverTenantLimit_ReturnsErrTenant(t *testing.T) {
	e, ctx, _ := newEnforcer(t, "acme", "user-1")
	require.NoError(t, e.SetBudget(ctx, &Budget{
		Scope: ScopeTenant, SubjectID: "", MonthlyTokens: 500,
	}))

	_, err := e.Check(ctx, 1000)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTokenBudgetExceededTenant)
}

func TestEnforcer_Check_OverrideDeny_AllowsWithWarning(t *testing.T) {
	e, ctx, _ := newEnforcer(t, "acme", "user-1")
	require.NoError(t, e.SetBudget(ctx, &Budget{
		Scope:         ScopeUser,
		SubjectID:     "user-1",
		MonthlyTokens: 1000,
		OverrideDeny:  true,
	}))

	// Even though we project over the limit, override_deny passes the
	// call through. No error returned.
	status, err := e.Check(ctx, 5000)
	require.NoError(t, err)
	require.NotNil(t, status)
}

func TestEnforcer_Record_IncrementsCounter(t *testing.T) {
	e, ctx, mr := newEnforcer(t, "acme", "user-1")
	require.NoError(t, e.Record(ctx, 100, 50))

	// Verify the counter hash got populated.
	period := PeriodID(time.Now())
	key := counterKey("acme", ScopeUser, "user-1", period)
	assert.Equal(t, "100", mr.HGet(key, "tokens"))
	assert.Equal(t, "50", mr.HGet(key, "cost_cents"))
}

func TestEnforcer_Record_Then_Check_ProjectsCorrectly(t *testing.T) {
	e, ctx, _ := newEnforcer(t, "acme", "user-1")
	require.NoError(t, e.SetBudget(ctx, &Budget{
		Scope: ScopeUser, SubjectID: "user-1", MonthlyTokens: 1000,
	}))
	require.NoError(t, e.Record(ctx, 800, 0))

	// Next call of 300 should exceed (800 + 300 = 1100 > 1000).
	_, err := e.Check(ctx, 300)
	assert.ErrorIs(t, err, ErrTokenBudgetExceededUser)

	// But 150 should still pass (800 + 150 = 950 < 1000).
	_, err = e.Check(ctx, 150)
	assert.NoError(t, err)
}

func TestEnforcer_Record_UpdatesBothTenantAndUser(t *testing.T) {
	e, ctx, mr := newEnforcer(t, "acme", "user-1")
	require.NoError(t, e.Record(ctx, 200, 10))

	period := PeriodID(time.Now())
	userKey := counterKey("acme", ScopeUser, "user-1", period)
	tenantKey := counterKey("acme", ScopeTenant, "", period)

	assert.Equal(t, "200", mr.HGet(userKey, "tokens"))
	assert.Equal(t, "200", mr.HGet(tenantKey, "tokens"), "tenant rollup must match user's counter")
}

func TestEnforcer_TeamResolver_EnforcesTeamBudget(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	resolver := func(ctx context.Context, tenantID, userID string) ([]string, error) {
		return []string{"team-a"}, nil
	}
	e := NewEnforcer(rdb, nil, resolver, nil)

	ctx := auth.ContextWithTenantString(context.Background(), "acme")
	ctx = auth.ContextWithActingUser(ctx, "user-1")

	require.NoError(t, e.SetBudget(ctx, &Budget{
		Scope: ScopeTeam, SubjectID: "team-a", MonthlyTokens: 500,
	}))

	_, err := e.Check(ctx, 1000)
	assert.ErrorIs(t, err, ErrTokenBudgetExceededTeam)
}

func TestEnforcer_WarningThreshold_SurfacesInStatus(t *testing.T) {
	e, ctx, _ := newEnforcer(t, "acme", "user-1")
	require.NoError(t, e.SetBudget(ctx, &Budget{
		Scope: ScopeUser, SubjectID: "user-1", MonthlyTokens: 1000,
	}))
	require.NoError(t, e.Record(ctx, 850, 0)) // 85% of 1000

	status, err := e.Check(ctx, 1)
	require.NoError(t, err)
	assert.True(t, status.WarningCrossed, "85% usage should cross default 80% threshold")
}

func TestEnforcer_PeriodRollover_ResetsCounters(t *testing.T) {
	// Set the clock to late in March; record some usage.
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	march31 := time.Date(2026, 3, 31, 23, 0, 0, 0, time.UTC)
	e := NewEnforcer(rdb, nil, nil, fixedClock(march31))

	ctx := auth.ContextWithTenantString(context.Background(), "acme")
	ctx = auth.ContextWithActingUser(ctx, "user-1")
	require.NoError(t, e.SetBudget(ctx, &Budget{
		Scope: ScopeUser, SubjectID: "user-1", MonthlyTokens: 1000,
	}))
	require.NoError(t, e.Record(ctx, 900, 0))

	// 900 + 200 = 1100 > 1000 — exceeds in March.
	_, err := e.Check(ctx, 200)
	assert.ErrorIs(t, err, ErrTokenBudgetExceededUser)

	// Roll the clock forward to April 1 — period ID changes, counter
	// is fresh (no usage recorded in April).
	april1 := time.Date(2026, 4, 1, 0, 30, 0, 0, time.UTC)
	e = NewEnforcer(rdb, nil, nil, fixedClock(april1))
	ctx = auth.ContextWithTenantString(context.Background(), "acme")
	ctx = auth.ContextWithActingUser(ctx, "user-1")

	// Now the same 200-token check should pass — April's counter is 0.
	_, err = e.Check(ctx, 200)
	assert.NoError(t, err, "new period should start with zero counter")
}

func TestEnforcer_ListStatusByScope_ReturnsConfiguredUsers(t *testing.T) {
	e, ctx, _ := newEnforcer(t, "acme", "user-1")
	require.NoError(t, e.SetBudget(ctx, &Budget{
		Scope: ScopeUser, SubjectID: "alice", MonthlyTokens: 1000,
	}))
	require.NoError(t, e.SetBudget(ctx, &Budget{
		Scope: ScopeUser, SubjectID: "bob", MonthlyTokens: 2000,
	}))

	got, err := e.ListStatusByScope(ctx, ScopeUser)
	require.NoError(t, err)
	assert.Len(t, got, 2)

	subjects := map[string]bool{}
	for _, s := range got {
		subjects[s.SubjectID] = true
	}
	assert.True(t, subjects["alice"])
	assert.True(t, subjects["bob"])
}

func TestEnforcer_Check_WithoutUserContext_FallsBackToTenantOnly(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	e := NewEnforcer(rdb, nil, nil, nil)

	// Tenant-only context — no ActingUser / InitiatorUser.
	ctx := auth.ContextWithTenantString(context.Background(), "acme")

	require.NoError(t, e.SetBudget(ctx, &Budget{
		Scope: ScopeTenant, MonthlyTokens: 1_000_000,
	}))

	status, err := e.Check(ctx, 500)
	require.NoError(t, err)
	// Fell back to tenant-scoped status since no user is available.
	assert.Equal(t, ScopeTenant, status.Scope)
}

func TestEnforcer_Concurrent_Records_DontLose(t *testing.T) {
	e, ctx, mr := newEnforcer(t, "acme", "user-1")

	const N = 100
	const perCall = 10
	done := make(chan struct{}, N)
	for i := 0; i < N; i++ {
		go func() {
			_ = e.Record(ctx, perCall, 0)
			done <- struct{}{}
		}()
	}
	for i := 0; i < N; i++ {
		<-done
	}

	period := PeriodID(time.Now())
	key := counterKey("acme", ScopeUser, "user-1", period)
	assert.Equal(t, "1000", mr.HGet(key, "tokens"), "100 concurrent records of 10 tokens each should sum to 1000 with no loss")
}
