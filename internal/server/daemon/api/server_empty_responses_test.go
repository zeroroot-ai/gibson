package api

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/platform/budget"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// adminTenantCtx is a tenant-scoped context whose caller holds admin on the
// tenant in the fake authorizer.
func adminTenantCtx(az *fakeAuthorizer, tenantID, subject string) context.Context {
	az.allow("user:"+subject, "admin", "tenant:"+tenantID)
	// The tenant rides inside the Identity (auth.TenantFromContext reads
	// id.Tenant), so the identity carries both.
	return auth.WithIdentity(context.Background(), auth.Identity{Subject: subject, Tenant: auth.MustNewTenantID(tenantID)})
}

// TestRevokeAccess_DeletesTheGrantAndAnswersEmpty proves the revoke is the
// FGA delete and the cache invalidation, not the response: the response
// carries no timestamp (gibson#502).
func TestRevokeAccess_DeletesTheGrantAndAnswersEmpty(t *testing.T) {
	az := newFakeAuthorizer()
	inv := &countingInvalidator{}
	srv := NewDaemonServer(&mockDaemon{}, nil, nil).WithAuthorizer(az)
	srv.modelGateInvalidator = inv

	resp, err := srv.RevokeAccess(adminTenantCtx(az, "acme", "owner-1"), &tenantv1.RevokeAccessRequest{
		SubjectKind: tenantv1.GrantSubjectKind_GRANT_SUBJECT_KIND_USER, SubjectId: "u-2",
		TargetKind: tenantv1.GrantTargetKind_GRANT_TARGET_KIND_MODEL, TargetId: "gpt-5",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, 1, inv.calls, "the model gate cache is invalidated once")
}

type countingInvalidator struct{ calls int }

func (c *countingInvalidator) InvalidateCache() { c.calls++ }

// adminBudgetEnforcer is stubBudgetEnforcer plus the admin surface, so the
// handler's SetBudget call is observable.
type adminBudgetEnforcer struct {
	stubBudgetEnforcer
	set []*budget.Budget
}

func (e *adminBudgetEnforcer) GetBudget(context.Context, budget.Scope, string) (*budget.Budget, error) {
	return nil, nil
}

func (e *adminBudgetEnforcer) SetBudget(_ context.Context, b *budget.Budget) error {
	e.set = append(e.set, b)
	return nil
}

func (e *adminBudgetEnforcer) ListStatusByScope(context.Context, budget.Scope) ([]*budget.Status, error) {
	return nil, nil
}

// TestSetTenantBudgetDefaults_PersistsTheTenantScopeBudget proves the
// defaults land as a tenant-scope Budget; the response carries no applied-at
// stamp (gibson#502), so the enforcer's captured write is the observable.
func TestSetTenantBudgetDefaults_PersistsTheTenantScopeBudget(t *testing.T) {
	az := newFakeAuthorizer()
	enf := &adminBudgetEnforcer{}
	srv := NewDaemonServer(&mockDaemon{}, nil, nil).WithAuthorizer(az)
	srv.budgetEnforcer = enf

	resp, err := srv.SetTenantBudgetDefaults(adminTenantCtx(az, "acme", "owner-1"), &tenantv1.SetTenantBudgetDefaultsRequest{
		DefaultUserMonthlyTokens: 1000, DefaultUserMonthlySpendUsdCents: 500, DefaultWarningThreshold: 0.8,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Len(t, enf.set, 1)
	assert.Equal(t, "acme", enf.set[0].TenantID)
	assert.Equal(t, budget.ScopeTenant, enf.set[0].Scope)
	assert.Equal(t, int64(1000), enf.set[0].MonthlyTokens)
}
