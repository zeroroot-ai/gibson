// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/brain/braintest"
	"github.com/zeroroot-ai/gibson/internal/platform/budget"
	"github.com/zeroroot-ai/gibson/internal/platform/principal"
	"github.com/zeroroot-ai/gibson/internal/server/daemon/api"
	"github.com/zeroroot-ai/sdk/auth"
)

// recordingEnforcer keeps what Record receives. It fails the first failures calls.
type recordingEnforcer struct {
	budget.Enforcer
	failures int
	tokens   []int64
	cents    []int64
	users    []string
}

func (r *recordingEnforcer) Record(ctx context.Context, tokens, cents int64) error {
	if r.failures > 0 {
		r.failures--
		return errors.New("the counter store is down")
	}
	user, _ := auth.InitiatorUserFromContext(ctx)
	r.tokens, r.cents, r.users = append(r.tokens, tokens), append(r.cents, cents), append(r.users, user)
	return nil
}

func usageOn(t *testing.T, enf budget.Enforcer, reg *brain.Registry) (*budgetUsage, *redis.Client) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return newBudgetUsage(enf, rdb, reg), rdb
}

func TestBudgetUsage_ACostThatIsNotANumberFailsBeforeTheCount(t *testing.T) {
	enf := &recordingEnforcer{}
	u, _ := usageOn(t, enf, nil)
	err := u.RecordModelCall(context.Background(), api.ModelCallUsage{
		Tenant: "acme", CallID: "c1", Tokens: 5, CostKnown: true, CostUSD: "free",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read the cost of call c1")
	assert.Empty(t, enf.tokens)
}

func TestBudgetUsage_ARedisThatIsDownFailsTheCall(t *testing.T) {
	enf := &recordingEnforcer{}
	u, rdb := usageOn(t, enf, nil)
	require.NoError(t, rdb.Close())
	err := u.RecordModelCall(context.Background(), api.ModelCallUsage{Tenant: "acme", CallID: "c1", Tokens: 5})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mark the call c1")
}

// A failed record removes the mark, so the next delivery of the span counts the call.
func TestBudgetUsage_AFailedRecordIsRetriedOnTheNextDelivery(t *testing.T) {
	enf := &recordingEnforcer{failures: 1}
	u, _ := usageOn(t, enf, nil)
	call := api.ModelCallUsage{Tenant: "acme", CallID: "c1", Tokens: 50, CostKnown: true, CostUSD: "0.01"}

	err := u.RecordModelCall(context.Background(), call)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "record the usage of call c1")

	require.NoError(t, u.RecordModelCall(context.Background(), call))
	assert.Equal(t, []int64{50}, enf.tokens)
	assert.Equal(t, []int64{1}, enf.cents)
}

func TestBudgetUsage_TheUserWhoCreatedTheMissionIsTheInitiator(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	reg := brain.NewRegistry(ctx, braintest.StoreFactory())
	eng := reg.For("acme")
	eng.Submit(brain.MissionCreated{ID: "m-user", Name: "a", CreatedBy: principal.Principal{Kind: principal.User, ID: "u-1"}})
	eng.Submit(brain.MissionCreated{ID: "m-svc", Name: "b", CreatedBy: principal.Principal{Kind: principal.Service, ID: "svc-1"}})
	eng.Tick()

	enf := &recordingEnforcer{}
	u, _ := usageOn(t, enf, reg)
	for i, mission := range []string{"m-user", "m-svc", "m-none", ""} {
		call := api.ModelCallUsage{Tenant: "acme", CallID: "c" + string(rune('a'+i)), Mission: mission, Tokens: 1}
		require.NoError(t, u.RecordModelCall(context.Background(), call))
	}
	assert.Equal(t, []string{"u-1", "", "", ""}, enf.users,
		"only a mission that a person created counts at the user scope")
}
