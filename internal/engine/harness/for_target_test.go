// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"testing"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// ForTarget is what makes a fan-out instance's findings land on the right host.
// Every scope reader in the callback surface resolves the finding's scope from
// h.Target().ID, so a view that failed to redirect would attribute every
// instance's findings to the mission's primary target (gibson#526).
func TestForTarget_RedirectsTheScope(t *testing.T) {
	primary := types.NewID()
	instance := types.NewID()
	h := &DefaultAgentHarness{targetInfo: TargetInfo{ID: primary, Name: "goat-a", Connection: map[string]any{"url": "https://10.0.0.1:6443"}}}

	view := h.ForTarget(instance.String())

	if got := view.Target().ID; got != instance {
		t.Errorf("view scope = %q, want the instance's target %q", got, instance)
	}
	if got := h.Target().ID; got != primary {
		t.Errorf("the original harness was mutated: scope = %q, want %q — a view "+
			"that rewrites its parent would corrupt every later instance", got, primary)
	}
}

// An empty id returns the harness itself, so an ordinary node's dispatch needs
// no branch at the call site and behaves exactly as before this method existed.
func TestForTarget_EmptyIDIsIdentity(t *testing.T) {
	h := &DefaultAgentHarness{targetInfo: TargetInfo{ID: types.NewID()}}
	if got := h.ForTarget(""); got != AgentHarness(h) {
		t.Error("ForTarget(\"\") must return the same harness, not a copy")
	}
}

// Asking for the target the harness already has is also identity: a single-target
// mission's for_each produces one instance whose target IS the primary, and
// allocating a view for it would be waste with a second object to reason about.
func TestForTarget_SameIDIsIdentity(t *testing.T) {
	id := types.NewID()
	h := &DefaultAgentHarness{targetInfo: TargetInfo{ID: id}}
	if got := h.ForTarget(id.String()); got != AgentHarness(h) {
		t.Error("ForTarget(own id) must return the same harness")
	}
}

// The view shares the mission's state rather than copying it. Copying the token
// tracker would unbound the mission budget — every instance would get a fresh
// allowance — and copying the callback manager would orphan in-flight
// registrations.
func TestForTarget_SharesMissionState(t *testing.T) {
	h := &DefaultAgentHarness{
		targetInfo: TargetInfo{ID: types.NewID()},
		missionCtx: MissionContext{ID: types.NewID(), Name: "fanout", CurrentAgent: "recon"},
	}

	view := h.ForTarget(types.NewID().String())
	scoped, ok := view.(*targetScopedHarness)
	if !ok {
		t.Fatalf("ForTarget returned %T, want a *targetScopedHarness view", view)
	}
	if scoped.AgentHarness != AgentHarness(h) {
		t.Fatal("the view must delegate to the harness it came from, not to a copy " +
			"of it: a copy duplicates inFlightTasksMu while sharing the map it " +
			"guards, and the agent-concurrency quota then races")
	}
	if view.Mission().ID != h.Mission().ID {
		t.Error("the view must carry the same mission; a different one would file " +
			"findings against nothing")
	}
	if view.Mission().CurrentAgent != h.Mission().CurrentAgent {
		t.Error("the view must keep the dispatching agent: it is the same turn")
	}
}

// Re-scoping a view scopes from its parent rather than wrapping the view again.
// A chain would grow one link per re-scope, and each link would be another
// Target() that could disagree.
func TestForTarget_ReScopingDoesNotNest(t *testing.T) {
	h := &DefaultAgentHarness{targetInfo: TargetInfo{ID: types.NewID()}}
	second := types.NewID()

	again := h.ForTarget(types.NewID().String()).ForTarget(second.String())

	scoped, ok := again.(*targetScopedHarness)
	if !ok {
		t.Fatalf("re-scope returned %T, want a *targetScopedHarness", again)
	}
	if scoped.AgentHarness != AgentHarness(h) {
		t.Errorf("the re-scoped view delegates to %T, want the original harness", scoped.AgentHarness)
	}
	if got := again.Target().ID; got != second {
		t.Errorf("re-scoped target = %q, want %q", got, second)
	}
}

// Re-scoping a view to the target it already reports returns that same view, so
// the identity rule holds one level down too.
func TestForTarget_ReScopingToTheSameTargetIsIdentity(t *testing.T) {
	h := &DefaultAgentHarness{targetInfo: TargetInfo{ID: types.NewID()}}
	id := types.NewID()
	view := h.ForTarget(id.String())
	if got := view.ForTarget(id.String()); got != view {
		t.Error("re-scoping a view to its own target must return that view")
	}
}
