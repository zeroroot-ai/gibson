// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// Error codes of slot resolution.
const (
	// ErrInvalidSlotConfig means the model of a slot does not meet its constraints.
	ErrInvalidSlotConfig types.ErrorCode = "LLM_INVALID_SLOT_CONFIG"
	// ErrNoMatchingProvider means no provider record can serve the slot.
	ErrNoMatchingProvider types.ErrorCode = "LLM_NO_MATCHING_PROVIDER"
	// ErrProviderNotFound means the provider that a slot names does not exist.
	ErrProviderNotFound types.ErrorCode = "LLM_PROVIDER_NOT_FOUND"
)

// SlotManager resolves a slot to one provider and one exact model name. It
// reads the provider records of the tenant and calls no provider. The model
// access gate runs in the resolution.
type SlotManager interface {
	// ResolveSlot resolves a slot. A node pin in override names a provider and
	// a model, and its failure is the answer: a pin never falls back.
	ResolveSlot(ctx context.Context, slot agent.SlotDefinition, override *agent.SlotConfig) (SlotModel, error)
	// ValidateSlot checks that the slot can be resolved with its own config.
	ValidateSlot(ctx context.Context, slot agent.SlotDefinition) error
}
