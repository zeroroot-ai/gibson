// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/brain/braintest"
	"github.com/zeroroot-ai/gibson/internal/engine/finding"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

type fakeRecordSetter struct {
	calls []string
	err   error
}

func (f *fakeRecordSetter) SetPriority(
	_ context.Context, tenant string, id types.ID, p finding.Priority, rule string,
) (bool, error) {
	f.calls = append(f.calls, tenant+"/"+id.String()+" priority="+string(p)+" rule="+rule)
	return true, f.err
}

func (f *fakeRecordSetter) SetStatus(
	_ context.Context, tenant string, id types.ID, status finding.FindingStatus,
) (bool, error) {
	f.calls = append(f.calls, tenant+"/"+id.String()+"="+string(status))
	return true, f.err
}

func TestFindingRecordProjector_WritesAChangeOnce(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx, braintest.StoreFactory())
	eng := reg.For("acme")
	id := types.NewID().String()
	seedFindingsWorld(t, eng, 2,
		brain.MissionCreated{ID: "run-1", TenantID: "acme", TargetID: "t"},
		brain.FindingRaised{ID: id, ScopeID: "t", Title: "x", Status: brain.FindingStatusFixing},
		brain.FindingRaised{ID: "anomaly-host-3", ScopeID: "t", Title: "y"},
	)

	set := &fakeRecordSetter{}
	p := NewFindingRecordProjector(reg, set, 0, nil)
	p.project(ctx)
	p.project(ctx) // the second pass has nothing new
	if want := "acme/" + id + "=fixing"; len(set.calls) != 1 || set.calls[0] != want {
		t.Fatalf("writes = %v, want only %q (the anomaly finding has no row)", set.calls, want)
	}

	eng.Submit(brain.FindingStatusChanged{ID: id, Status: brain.FindingStatusFixed})
	waitStatus(t, eng, id, brain.FindingStatusFixed)
	p.project(ctx)
	if len(set.calls) != 2 || set.calls[1] != "acme/"+id+"=fixed" {
		t.Fatalf("writes = %v, want the change to fixed as the second write", set.calls)
	}
}

func TestFindingRecordProjector_RetriesAFailedWrite(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx, braintest.StoreFactory())
	id := types.NewID().String()
	seedFindingsWorld(t, reg.For("acme"), 1,
		brain.MissionCreated{ID: "run-1", TenantID: "acme", TargetID: "t"},
		brain.FindingRaised{ID: id, ScopeID: "t", Title: "x"},
	)
	set := &fakeRecordSetter{err: errors.New("db down")}
	p := NewFindingRecordProjector(reg, set, 0, nil)
	p.project(ctx)
	set.err = nil
	p.project(ctx)
	if len(set.calls) != 2 {
		t.Fatalf("writes = %v, want the failed write retried", set.calls)
	}
}

func waitStatus(t *testing.T, eng *brain.Engine, id, status string) {
	t.Helper()
	for i := 0; i < 400; i++ {
		for _, f := range eng.Findings() {
			if f.ID == id && f.Status == status {
				return
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("finding %s did not reach %s", id, status)
}

func TestFindingRecordProjector_WritesPriorityOnlyWhenSet(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx, braintest.StoreFactory())
	eng := reg.For("acme")
	id := types.NewID().String()
	seedFindingsWorld(t, eng, 1,
		brain.MissionCreated{ID: "run-1", TenantID: "acme", TargetID: "t"},
		brain.FindingRaised{ID: id, ScopeID: "t", Title: "x"},
	)
	set := &fakeRecordSetter{}
	p := NewFindingRecordProjector(reg, set, 0, nil)
	p.project(ctx)
	if len(set.calls) != 1 { // the status only
		t.Fatalf("writes = %v, want the status write only", set.calls)
	}
	eng.Submit(brain.FindingPrioritized{ID: id, Priority: "P1", Rule: "kev"})
	for i := 0; i < 400; i++ {
		if eng.Findings()[0].Priority == "P1" {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	p.project(ctx)
	p.project(ctx)
	want := "acme/" + id + " priority=P1 rule=kev"
	if len(set.calls) != 2 || set.calls[1] != want {
		t.Fatalf("writes = %v, want the priority written once as %q", set.calls, want)
	}
}
