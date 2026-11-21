// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package incidentreport

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/brain/braintest"
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

// The history read takes the tenant from the context and reads the Timeline
// of that tenant.
func TestBrainHistory_ReadsTheTimelineOfTheTenantOfTheContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	reg := brain.NewRegistry(ctx, braintest.StoreFactory())
	if err := reg.For("acme").SubmitAndWait(ctx, brain.FindingRaised{ID: "f1"}); err != nil {
		t.Fatal(err)
	}
	evs, _, err := BrainHistory{Registry: reg}.HistoryFrom(tenantCtx(t), time.Time{})
	if err != nil || len(evs) != 1 {
		t.Fatalf("history = %v, %v", evs, err)
	}
	if _, _, err := (BrainHistory{Registry: reg}).HistoryFrom(context.Background(), time.Time{}); !errors.Is(err, ErrNoTenant) {
		t.Errorf("no tenant: err = %v", err)
	}
}
