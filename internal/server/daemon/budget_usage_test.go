// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/zeroroot-ai/gibson/internal/platform/budget"
	"github.com/zeroroot-ai/gibson/internal/server/daemon/api"
)

func newUsage(t *testing.T) (*budgetUsage, budget.Enforcer) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	enf := budget.NewEnforcer(rdb, nil, nil, nil, nil)
	return newBudgetUsage(enf, rdb, nil), enf
}

// A call counts one time at the tenant scope, however many times the collector
// sends its span.
func TestBudgetUsage_CountsACallOnce(t *testing.T) {
	u, enf := newUsage(t)
	call := api.ModelCallUsage{Tenant: "acme", CallID: "c1", Tokens: 100, CostKnown: true, CostUSD: "0.0123"}
	for range 3 {
		if err := u.RecordModelCall(context.Background(), call); err != nil {
			t.Fatal(err)
		}
	}
	tokens, cost, _ := enf.TenantPeriodUsage(context.Background(), "acme")
	if tokens != 100 || cost != 2 {
		t.Fatalf("usage = %d tokens, %d cents, want 100 and 2", tokens, cost)
	}
	call.CallID = "c2"
	if err := u.RecordModelCall(context.Background(), call); err != nil {
		t.Fatal(err)
	}
	if tokens, _, _ := enf.TenantPeriodUsage(context.Background(), "acme"); tokens != 200 {
		t.Fatalf("tokens = %d, want 200", tokens)
	}
}

func TestBudgetUsage_RefusesACallWithNoTenantOrID(t *testing.T) {
	u, _ := newUsage(t)
	if err := u.RecordModelCall(context.Background(), api.ModelCallUsage{CallID: "c"}); err == nil {
		t.Error("no tenant must fail")
	}
	if err := u.RecordModelCall(context.Background(), api.ModelCallUsage{Tenant: "acme"}); err == nil {
		t.Error("no call id must fail")
	}
}
