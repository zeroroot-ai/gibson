// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/mission"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// errTargetNotFoundForTest is what a fake target store returns for an id it does
// not hold. It stands in for the real store's not-found, which is also what a
// cross-tenant read gets — resolveTargetUUID does not leak existence.
type errNotFoundForTest struct{}

func (errNotFoundForTest) Error() string { return "target not found" }

var errTargetNotFoundForTest error = errNotFoundForTest{}

// resolveForEachTargets turns the run's target set into what expansion takes, in
// TargetSet() order — primary first, then AdditionalTargetIDs. The order is what
// makes instance identity and the concurrency chain stable between runs
// (gibson#525).
func TestResolveForEachTargets_ResolvesTheWholeSetInOrder(t *testing.T) {
	primary := types.NewID()
	extra := types.NewID()
	m := &missionManager{
		logger: slog.New(slog.DiscardHandler),
		targetStore: &fakeTargetStore{get: func(_ context.Context, got types.ID) (*types.Target, error) {
			switch got {
			case primary:
				return &types.Target{ID: primary, TenantID: "tenant-a", Name: "p", URL: "https://10.0.0.1:6443"}, nil
			case extra:
				return &types.Target{ID: extra, TenantID: "tenant-a", Name: "e", URL: "https://10.0.0.2:6443"}, nil
			}
			return nil, errTargetNotFoundForTest
		}},
	}
	active := &activeMission{mission: &mission.Mission{
		ID:                  types.NewID(),
		TenantID:            "tenant-a",
		TargetID:            primary,
		AdditionalTargetIDs: []types.ID{extra},
	}}

	got, err := m.resolveForEachTargets(tenantCtx(t, "tenant-a"), active)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("resolved %d targets, want 2", len(got))
	}
	if got[0].ID != primary.String() {
		t.Errorf("first resolved target is %q, want the primary %q", got[0].ID, primary)
	}
	if got[1].ID != extra.String() {
		t.Errorf("second resolved target is %q, want %q", got[1].ID, extra)
	}
	for _, ft := range got {
		if ft.Target == nil {
			t.Errorf("target %q resolved to nil, which expansion refuses later rather than here", ft.ID)
		}
	}
}

// A target in the set that will not resolve fails the whole resolution. Expanding
// over the ones that did resolve would run a fan-out that silently covered less
// than the author asked for.
func TestResolveForEachTargets_OneUnresolvableTargetFailsTheSet(t *testing.T) {
	primary := types.NewID()
	missing := types.NewID()
	m := &missionManager{
		logger: slog.New(slog.DiscardHandler),
		targetStore: &fakeTargetStore{get: func(_ context.Context, got types.ID) (*types.Target, error) {
			if got == primary {
				return &types.Target{ID: primary, TenantID: "tenant-a", Name: "p", URL: "https://10.0.0.1:6443"}, nil
			}
			return nil, errTargetNotFoundForTest
		}},
	}
	active := &activeMission{mission: &mission.Mission{
		ID:                  types.NewID(),
		TenantID:            "tenant-a",
		TargetID:            primary,
		AdditionalTargetIDs: []types.ID{missing},
	}}

	_, err := m.resolveForEachTargets(tenantCtx(t, "tenant-a"), active)
	if err == nil {
		t.Fatal("want a failure when a target in the set does not resolve")
	}
	if !strings.Contains(err.Error(), missing.String()) {
		t.Errorf("the error does not name the target that failed: %v", err)
	}
}

// A single-target run resolves to one element, which expands a for_each to one
// instance and is indistinguishable from the pre-fan-out behaviour.
func TestResolveForEachTargets_SingleTargetRun(t *testing.T) {
	primary := types.NewID()
	m := &missionManager{
		logger: slog.New(slog.DiscardHandler),
		targetStore: &fakeTargetStore{get: func(_ context.Context, got types.ID) (*types.Target, error) {
			if got == primary {
				return &types.Target{ID: primary, TenantID: "tenant-a", Name: "p", URL: "https://10.0.0.1:6443"}, nil
			}
			return nil, errTargetNotFoundForTest
		}},
	}
	active := &activeMission{mission: &mission.Mission{
		ID: types.NewID(), TenantID: "tenant-a", TargetID: primary,
	}}

	got, err := m.resolveForEachTargets(tenantCtx(t, "tenant-a"), active)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(got) != 1 || got[0].ID != primary.String() {
		t.Fatalf("resolved %+v, want exactly the primary", got)
	}
}
