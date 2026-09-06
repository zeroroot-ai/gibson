// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package daemon

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/llm"
)

// fakeSlotManager records the slot it was asked to resolve and answers with a
// fixed model, so the floor's translation into a slot constraint is observable
// without a provider store.
type fakeSlotManager struct {
	info llm.ModelInfo
	err  error

	gotSlot     agent.SlotDefinition
	gotOverride *agent.SlotConfig
	calls       int
}

func (f *fakeSlotManager) ResolveSlot(_ context.Context, slot agent.SlotDefinition, override *agent.SlotConfig) (llm.LLMProvider, llm.ModelInfo, error) {
	f.calls++
	f.gotSlot = slot
	f.gotOverride = override
	if f.err != nil {
		return nil, llm.ModelInfo{}, f.err
	}
	return nil, f.info, nil
}

func (f *fakeSlotManager) ValidateSlot(context.Context, agent.SlotDefinition) error { return nil }

func resolverWith(m *fakeSlotManager, err error) *slotModelResolver {
	return &slotModelResolver{
		forTenant: func(context.Context, string) (llm.SlotManager, llm.LLMRegistry, error) {
			if err != nil {
				return nil, nil, err
			}
			return m, nil, nil
		},
	}
}

// The floor is expressed as the slot's own constraint, so the existing
// constraint search enforces it. Passing it any other way — resolving first and
// comparing after — would let a tenant with several models resolve a small one
// and then fail, instead of picking the large one it has.
func TestResolveAgentModel_FloorBecomesTheSlotConstraint(t *testing.T) {
	t.Parallel()

	m := &fakeSlotManager{info: llm.ModelInfo{Name: "big", ContextWindow: 200000}}
	r := resolverWith(m, nil)

	model, window, err := r.ResolveAgentModel(context.Background(), "acme", "", 32000)
	if err != nil {
		t.Fatalf("ResolveAgentModel: %v", err)
	}
	if model != "big" || window != 200000 {
		t.Fatalf("got (%q, %d); want (big, 200000)", model, window)
	}
	if m.gotSlot.Constraints.MinContextWindow != 32000 {
		t.Errorf("slot constraint = %d; want the manifest floor 32000", m.gotSlot.Constraints.MinContextWindow)
	}
	if m.gotSlot.Name != agentFloorSlotName {
		t.Errorf("slot name = %q; want %q so an agent and a mission node resolve under the same tenant policy",
			m.gotSlot.Name, agentFloorSlotName)
	}
	if m.gotOverride != nil {
		t.Errorf("override = %+v; want nil when the manifest pins no model", m.gotOverride)
	}
}

// A manifest that pins a model passes it as an explicit override: pinning names
// WHICH model, and the caller still measures the answer against the floor.
func TestResolveAgentModel_PinnedModelBecomesTheOverride(t *testing.T) {
	t.Parallel()

	m := &fakeSlotManager{info: llm.ModelInfo{Name: "pinned", ContextWindow: 100000}}
	r := resolverWith(m, nil)

	if _, _, err := r.ResolveAgentModel(context.Background(), "acme", "pinned", 32000); err != nil {
		t.Fatalf("ResolveAgentModel: %v", err)
	}
	if m.gotOverride == nil || m.gotOverride.Model != "pinned" {
		t.Fatalf("override = %+v; want the manifest's pinned model", m.gotOverride)
	}
}

// A tenant whose models are all too small must surface the constraint search's
// own refusal, not a substituted best effort: the caller cannot see the
// truncation a smaller model would cause.
func TestResolveAgentModel_NoModelMeetsTheFloor(t *testing.T) {
	t.Parallel()

	want := errors.New("no matching provider")
	r := resolverWith(&fakeSlotManager{err: want}, nil)

	if _, _, err := r.ResolveAgentModel(context.Background(), "acme", "", 32000); !errors.Is(err, want) {
		t.Fatalf("error = %v; want it to surface %v unchanged", err, want)
	}
}

// A tenant with no resolvable providers is a different failure from a tenant
// whose models are too small, and needs a different fix, so the message names
// the tenant and keeps the cause.
func TestResolveAgentModel_ProviderResolutionFailureNamesTheTenant(t *testing.T) {
	t.Parallel()

	want := errors.New("pool unavailable")
	r := resolverWith(nil, want)

	_, _, err := r.ResolveAgentModel(context.Background(), "acme", "", 32000)
	if !errors.Is(err, want) {
		t.Fatalf("error = %v; want it to wrap %v", err, want)
	}
	if !strings.Contains(err.Error(), "acme") {
		t.Errorf("error %q does not name the tenant whose providers failed", err.Error())
	}
}

// An unwired resolver must say so rather than panic: the dispatch path treats
// this as a refusal, and a nil dereference there would read as a crash instead.
func TestResolveAgentModel_UnwiredIsAnErrorNotAPanic(t *testing.T) {
	t.Parallel()

	var r *slotModelResolver
	if _, _, err := r.ResolveAgentModel(context.Background(), "acme", "", 32000); err == nil {
		t.Fatal("an unwired resolver must return an error")
	}
	if _, _, err := (&slotModelResolver{}).ResolveAgentModel(context.Background(), "acme", "", 32000); err == nil {
		t.Fatal("a resolver with no tenant factory must return an error")
	}
}
