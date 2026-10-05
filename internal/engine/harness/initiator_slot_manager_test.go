// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"testing"

	"github.com/zeroroot-ai/sdk/auth"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	"github.com/zeroroot-ai/gibson/internal/platform/principal"
)

// initiatorRecorder is a slot manager that records the mission initiator of
// each context it receives.
type initiatorRecorder struct{ seen []string }

func (r *initiatorRecorder) record(ctx context.Context) {
	u, _ := auth.InitiatorUserFromContext(ctx)
	r.seen = append(r.seen, u)
}

func (r *initiatorRecorder) ResolveSlot(ctx context.Context, _ agent.SlotDefinition, _ *agent.SlotConfig) (llm.LLMProvider, llm.ModelInfo, error) {
	r.record(ctx)
	return nil, llm.ModelInfo{}, nil
}

func (r *initiatorRecorder) ValidateSlot(ctx context.Context, _ agent.SlotDefinition) error {
	r.record(ctx)
	return nil
}

// TestWithMissionInitiator_APersonReachesEverySlotResolution: when a person
// created the mission, each slot resolution and each slot validation carries
// that person as the mission initiator, from a context that named nobody.
func TestWithMissionInitiator_APersonReachesEverySlotResolution(t *testing.T) {
	rec := &initiatorRecorder{}
	sm := withMissionInitiator(rec, principal.Principal{Kind: principal.User, ID: "alice"})

	if _, _, err := sm.ResolveSlot(context.Background(), agent.SlotDefinition{}, nil); err != nil {
		t.Fatalf("ResolveSlot: %v", err)
	}
	if err := sm.ValidateSlot(context.Background(), agent.SlotDefinition{}); err != nil {
		t.Fatalf("ValidateSlot: %v", err)
	}
	if len(rec.seen) != 2 || rec.seen[0] != "alice" || rec.seen[1] != "alice" {
		t.Fatalf("initiators seen = %q, want alice on both calls", rec.seen)
	}
}

// TestWithMissionInitiator_NoPersonNoInitiator: a mission that a service or a
// component created, or one with no recorded creator, gets no initiator. The
// model gate then decides for the calling identity or for the tenant's members.
func TestWithMissionInitiator_NoPersonNoInitiator(t *testing.T) {
	for name, p := range map[string]principal.Principal{
		"a service":   {Kind: principal.Service, ID: "scheduler"},
		"a component": {Kind: principal.Component, ID: "agent_principal:scanner"},
		"nobody":      {},
		"empty id":    {Kind: principal.User},
	} {
		rec := &initiatorRecorder{}
		sm := withMissionInitiator(rec, p)
		if _, _, err := sm.ResolveSlot(context.Background(), agent.SlotDefinition{}, nil); err != nil {
			t.Fatalf("%s: ResolveSlot: %v", name, err)
		}
		if len(rec.seen) != 1 || rec.seen[0] != "" {
			t.Errorf("%s: initiators seen = %q, want none", name, rec.seen)
		}
	}
	if withMissionInitiator(nil, principal.Principal{Kind: principal.User, ID: "alice"}) != nil {
		t.Error("a nil slot manager must stay nil")
	}
}

// TestMissionContext_WithCreatedBy: the creator travels on the MissionContext.
func TestMissionContext_WithCreatedBy(t *testing.T) {
	p := principal.Principal{Kind: principal.User, ID: "alice"}
	if got := (MissionContext{}).WithCreatedBy(p).CreatedBy; got != p {
		t.Errorf("CreatedBy = %+v, want %+v", got, p)
	}
}
