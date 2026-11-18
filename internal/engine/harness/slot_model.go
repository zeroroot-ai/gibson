// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
)

// ResolveSlotModel resolves a slot to the provider and the exact model name
// that the slot uses. It honors the per-node binding (gibson#539), and the slot
// manager applies the model access gate.
func (h *DefaultAgentHarness) ResolveSlotModel(ctx context.Context, slot string) (SlotModel, error) {
	slotDef := agent.NewSlotDefinition(slot, "LLM slot for a gateway call", true)
	picked, err := h.slotManager.ResolveSlot(ctx, slotDef, h.slotOverride(slot))
	if err != nil {
		return SlotModel{}, fmt.Errorf("failed to resolve slot %s: %w", slot, err)
	}
	picked.MaxOutputTokens = agent.MinLimit(picked.MaxOutputTokens, h.maxTokensPerCall)
	return picked, nil
}
