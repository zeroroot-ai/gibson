// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"

	"github.com/zeroroot-ai/sdk/auth"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	"github.com/zeroroot-ai/gibson/internal/platform/principal"
)

// initiatorSlotManager puts the mission initiator on the context of every
// slot resolution, so the model gate decides for the person who created the
// mission (hosted#358).
//
// The initiator travels this way, and not on the context of each caller,
// because a slot resolution starts from many contexts in one run: the brain's
// dispatch, an agent's callback from its sandbox, a delegated child. Each of
// them reaches the model gate through the harness's slot manager, so this is
// the one place that all of them pass.
type initiatorSlotManager struct {
	next   llm.SlotManager
	userID string
}

// withMissionInitiator wraps next when a person created the mission. A
// mission that a service or a component created has no initiator: the model
// gate then decides for the calling identity, or for the tenant's members.
func withMissionInitiator(next llm.SlotManager, createdBy principal.Principal) llm.SlotManager {
	if next == nil || createdBy.Kind != principal.User || createdBy.ID == "" {
		return next
	}
	return &initiatorSlotManager{next: next, userID: createdBy.ID}
}

func (m *initiatorSlotManager) ResolveSlot(ctx context.Context, slot agent.SlotDefinition, override *agent.SlotConfig) (llm.LLMProvider, llm.ModelInfo, error) {
	//nolint:wrapcheck // a decorator returns the slot manager's own error, which callers match by code
	return m.next.ResolveSlot(auth.ContextWithInitiatorUser(ctx, m.userID), slot, override)
}

func (m *initiatorSlotManager) ValidateSlot(ctx context.Context, slot agent.SlotDefinition) error {
	//nolint:wrapcheck // a decorator returns the slot manager's own error, which callers match by code
	return m.next.ValidateSlot(auth.ContextWithInitiatorUser(ctx, m.userID), slot)
}
