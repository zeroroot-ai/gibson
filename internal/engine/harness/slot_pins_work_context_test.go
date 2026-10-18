// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/platform/component"
)

// The slot pins of an agent node go on its work item, so the ComponentService
// can resolve them for the agent's completions (gibson#1203).
func TestSlotPinsWorkContext_CarriesTheNodePins(t *testing.T) {
	ctx, err := slotPinsWorkContext(map[string]*agent.SlotConfig{
		"fast":    {Provider: "fast-p", Model: "f-large"},
		"ignored": nil,
	})
	require.NoError(t, err)

	var pins map[string]agent.SlotConfig
	require.NoError(t, json.Unmarshal([]byte(ctx[component.SlotPinsWorkKey]), &pins))
	assert.Equal(t, map[string]agent.SlotConfig{"fast": {Provider: "fast-p", Model: "f-large"}}, pins)
}

// A node with no pins adds nothing to the work item.
func TestSlotPinsWorkContext_NoPinsAddsNothing(t *testing.T) {
	for _, overrides := range []map[string]*agent.SlotConfig{nil, {}, {"fast": nil}} {
		ctx, err := slotPinsWorkContext(overrides)
		require.NoError(t, err)
		assert.Nil(t, ctx)
	}
}
