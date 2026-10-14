// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package llmtest holds test doubles for the llm package. Production resolves
// slots with the daemon slot manager only.
package llmtest

import (
	"context"
	"errors"
	"sort"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/llm"
)

// SlotManager is a minimal llm.SlotManager for tests that need a slot manager
// value. It picks the override provider, else the slot default provider, else
// the first provider by name, and the saved model of that provider. It checks
// no constraint.
type SlotManager struct {
	registry llm.LLMRegistry
}

// NewSlotManager returns a SlotManager over the registry.
func NewSlotManager(registry llm.LLMRegistry) *SlotManager {
	return &SlotManager{registry: registry}
}

// ResolveSlot resolves the slot to a provider and its saved model.
func (m *SlotManager) ResolveSlot(_ context.Context, slot agent.SlotDefinition, override *agent.SlotConfig) (llm.LLMProvider, llm.ModelInfo, error) {
	if m.registry == nil {
		return nil, llm.ModelInfo{}, errors.New("llmtest: no registry")
	}
	cfg := slot.MergeConfig(override)
	name := cfg.Provider
	if name == "" {
		names := m.registry.ListProviders()
		if len(names) == 0 {
			return nil, llm.ModelInfo{}, errors.New("llmtest: no provider registered")
		}
		sort.Strings(names)
		name = names[0]
	}
	p, err := m.registry.GetProvider(name)
	if err != nil {
		return nil, llm.ModelInfo{}, err //nolint:wrapcheck // a test double
	}
	model := cfg.Model
	if model == "" {
		model = llm.SavedModel(p)
	}
	return p, llm.ModelInfo{Name: model, ContextWindowUnreported: true, FeaturesUnreported: true}, nil
}

// ValidateSlot resolves the slot and reports the error.
func (m *SlotManager) ValidateSlot(ctx context.Context, slot agent.SlotDefinition) error {
	_, _, err := m.ResolveSlot(ctx, slot, nil)
	return err
}
