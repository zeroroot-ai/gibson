// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package llm

import (
	"context"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
)

// SlotManager manages LLM slot resolution and validation.
// It matches slot requirements against available providers and models,
// ensuring constraints are satisfied.
type SlotManager interface {
	// ResolveSlot resolves a slot definition to a specific provider and model
	// that satisfies the slot's constraints and configuration.
	// Returns ErrNoMatchingProvider if no provider/model combination meets the requirements.
	ResolveSlot(ctx context.Context, slot agent.SlotDefinition, override *agent.SlotConfig) (LLMProvider, ModelInfo, error)

	// ValidateSlot validates that a slot configuration can be satisfied by available providers
	ValidateSlot(ctx context.Context, slot agent.SlotDefinition) error
}
