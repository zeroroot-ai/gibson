// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package incidentreport

import (
	"context"
	"errors"
	"testing"
)

type fakeTenantGraph struct {
	tenant string
	err    error
}

func (f *fakeTenantGraph) ReadGraph(_ context.Context, tenant, _ string, _ map[string]any) ([]map[string]any, error) {
	f.tenant = tenant
	return []map[string]any{{"k": "v"}}, f.err
}

// The graph read takes the tenant from the context, and never from the
// caller. With no tenant, no querier or a failed read, it answers an error.
func TestQuerierGraph_ReadsTheGraphOfTheTenantOfTheContext(t *testing.T) {
	g := &fakeTenantGraph{}
	r := QuerierGraph{Graph: func() TenantGraph { return g }}
	rows, err := r.Read(tenantCtx(t), "MATCH (n) RETURN n", nil)
	if err != nil || len(rows) != 1 || g.tenant != "acme" {
		t.Fatalf("rows = %v, err = %v, tenant = %q", rows, err, g.tenant)
	}
	if _, err := r.Read(context.Background(), "q", nil); !errors.Is(err, ErrNoTenant) {
		t.Errorf("no tenant: err = %v", err)
	}
	if _, err := (QuerierGraph{Graph: func() TenantGraph { return nil }}).Read(tenantCtx(t), "q", nil); err == nil {
		t.Error("no querier: want an error")
	}
	g.err = errors.New("down")
	if _, err := r.Read(tenantCtx(t), "q", nil); err == nil {
		t.Error("a failed read: want an error")
	}
}
