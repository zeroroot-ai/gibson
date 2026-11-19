// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
)

// stubSlotManager is a SlotManager for tests. It resolves each slot to one
// fixed provider and model, and it records the last override that it got.
type stubSlotManager struct {
	picked       SlotModel
	err          error
	lastOverride *agent.SlotConfig
	calls        int
}

var _ SlotManager = (*stubSlotManager)(nil)

// newStubSlotManager returns a stub that resolves to provider "stub" and
// model "stub-model".
func newStubSlotManager() *stubSlotManager {
	return &stubSlotManager{picked: SlotModel{Provider: "stub", Model: "stub-model", ContextWindow: 100000}}
}

// ResolveSlot returns the fixed pick or the fixed error.
func (s *stubSlotManager) ResolveSlot(
	_ context.Context, _ agent.SlotDefinition, override *agent.SlotConfig,
) (SlotModel, error) {
	s.calls++
	s.lastOverride = override
	if s.err != nil {
		return SlotModel{}, s.err
	}
	return s.picked, nil
}

// ValidateSlot succeeds when the stub has no error.
func (s *stubSlotManager) ValidateSlot(context.Context, agent.SlotDefinition) error {
	return s.err
}

// fixedSlotManager returns a per-tenant resolver that gives the same slot
// manager to each tenant.
func fixedSlotManager(sm SlotManager) func(context.Context, string) (SlotManager, error) {
	return func(context.Context, string) (SlotManager, error) { return sm, nil }
}
