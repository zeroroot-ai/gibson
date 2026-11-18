// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/platform/budget"
	"github.com/zeroroot-ai/gibson/internal/platform/principal"
	"github.com/zeroroot-ai/gibson/internal/server/daemon/api"
	"github.com/zeroroot-ai/sdk/auth"
)

// budgetCallTTL is how long the platform budget remembers a call id. The
// collector sends a span again within minutes, so a day is far more than needed.
const budgetCallTTL = 24 * time.Hour

// budgetUsage records the usage of each model call in the platform budget
// (tenant, user and team scopes). The LLM layer that called Record is gone. The
// gateway now sends each model call to the model provider, and the trace receiver
// sees each call, so the trace receiver is the one feed. Without it the counters
// would read zero for ever, and no limit would ever apply.
//
// This budget is not the budget of a mission. The mission budget limits the
// tokens of one mission in the World (brain.TokenUsed). This budget limits the
// usage of a tenant, a user or a team in a period, and the usage report reads it.
type budgetUsage struct {
	enforcer budget.Enforcer
	rdb      redis.UniversalClient
	registry *brain.Registry
}

var _ api.UsageRecorder = (*budgetUsage)(nil)

func newBudgetUsage(e budget.Enforcer, rdb redis.UniversalClient, reg *brain.Registry) *budgetUsage {
	return &budgetUsage{enforcer: e, rdb: rdb, registry: reg}
}

// RecordModelCall records one call, one time. A second delivery of the same
// call id records nothing.
func (b *budgetUsage) RecordModelCall(ctx context.Context, u api.ModelCallUsage) error {
	if u.Tenant == "" || u.CallID == "" {
		return errors.New("a model call needs a tenant and a call id")
	}
	first, err := b.rdb.SetNX(ctx, "budget:call:"+u.Tenant+":"+u.CallID, 1, budgetCallTTL).Result()
	if err != nil {
		return fmt.Errorf("mark the call %s: %w", u.CallID, err)
	}
	if !first {
		return nil
	}
	cents, err := budget.CostCents(u.CostKnown, u.CostUSD)
	if err != nil {
		return fmt.Errorf("read the cost of call %s: %w", u.CallID, err)
	}
	rctx := auth.ContextWithTenantString(ctx, u.Tenant)
	// The user scope and the team scopes count the person who created the
	// mission. A call with no mission, or a mission that no person created,
	// counts at the tenant scope only.
	if user := b.initiatorOf(u.Tenant, u.Mission); user != "" {
		rctx = auth.ContextWithInitiatorUser(rctx, user)
	}
	if err := b.enforcer.Record(rctx, u.Tokens, cents); err != nil {
		// The call is marked, so a second delivery would not retry it. Remove
		// the mark, so that it does.
		_ = b.rdb.Del(ctx, "budget:call:"+u.Tenant+":"+u.CallID).Err()
		return fmt.Errorf("record the usage of call %s: %w", u.CallID, err)
	}
	return nil
}

// initiatorOf returns the user who created the mission, or an empty string.
func (b *budgetUsage) initiatorOf(tenant, mission string) string {
	if mission == "" {
		return ""
	}
	eng, ok := api.TenantEngine(b.registry, tenant)
	if !ok {
		return ""
	}
	for _, m := range eng.Missions() {
		if m.ID == mission && m.CreatedBy.Kind == principal.User {
			return m.CreatedBy.ID
		}
	}
	return ""
}
