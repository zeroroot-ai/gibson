// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"log/slog"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
)

// TestCallbackManager_SetBeliefSubstrate proves the manager-level setter
// reaches the underlying callback service (ADR-0122, gibson#273/#278) — the
// same wiring contract as SetToolCallSink, exercised here before Start()
// (construction alone is enough: NewCallbackServerWithRegistry builds the
// service eagerly). Without this, PlaceBet has no substrate on any daemon
// that only calls CallbackManager (every real daemon) and always answers
// Unavailable.
func TestCallbackManager_SetBeliefSubstrate(t *testing.T) {
	m := NewCallbackManager(CallbackConfig{ServiceOptions: []CallbackServiceOption{testEventBus()}, ListenAddress: "127.0.0.1:0"}, slog.Default())

	substrate := newFakeBeliefSubstrate()
	m.SetBeliefSubstrate(substrate)

	if m.server == nil || m.server.service == nil {
		t.Fatal("manager must construct its server/service eagerly")
	}
	if m.server.service.beliefSubstrate == nil {
		t.Fatal("SetBeliefSubstrate must reach the underlying callback service")
	}
	ref := brain.NodeRef{Kind: brain.NodeKindClaim, ID: "acme/hyp-1"}
	if err := m.server.service.beliefSubstrate.SetBelief(context.Background(), ref, brain.NodeBelief{}); err != nil {
		t.Fatalf("SetBelief: %v", err)
	}
	if _, ok, _ := substrate.Belief(context.Background(), ref); !ok {
		t.Fatal("the substrate reached by the setter is not the one passed in")
	}
}

// TestCallbackManager_SetBeliefSubstrate_NilServerIsNoOp proves the setter is
// safe to call on a manager with no server (defensive guard, same shape as
// the other Set* methods).
func TestCallbackManager_SetBeliefSubstrate_NilServerIsNoOp(_ *testing.T) {
	m := &CallbackManager{logger: slog.Default()}
	m.SetBeliefSubstrate(newFakeBeliefSubstrate())
}

// TestCallbackManager_BeliefSubstrate proves the getter is the read half of
// SetBeliefSubstrate: nil before anything is wired, and the exact value
// passed to SetBeliefSubstrate afterward. Unlike the setter, the getter is a
// request-path method that assumes a manager built through
// NewCallbackManager (ADR-0003) — it is not exercised against the bare,
// no-server construction the setter's own nil-safety test uses.
func TestCallbackManager_BeliefSubstrate(t *testing.T) {
	m := NewCallbackManager(CallbackConfig{ServiceOptions: []CallbackServiceOption{testEventBus()}, ListenAddress: "127.0.0.1:0"}, slog.Default())
	if got := m.BeliefSubstrate(); got != nil {
		t.Fatalf("BeliefSubstrate() before SetBeliefSubstrate = %v, want nil", got)
	}

	substrate := newFakeBeliefSubstrate()
	m.SetBeliefSubstrate(substrate)
	if got := m.BeliefSubstrate(); got != brain.BeliefSubstrate(substrate) {
		t.Fatalf("BeliefSubstrate() = %v, want the exact value passed to SetBeliefSubstrate", got)
	}
}
