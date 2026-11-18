// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// slot_manager_node_override_test.go tests that the DaemonSlotManager
// correctly honors per-node, per-slot overrides (gibson#539).
//
// These tests verify the three acceptance-criteria from the issue:
//
//  1. A node pinning slot X to a non-default provider resolves to THAT provider/model.
//  2. Two slots pinned to different providers on one node resolve independently.
//  3. An unpinned slot (no entry / nil override) falls through to the tenant default.
//
// The FGA model-access gate is verified separately (it runs inside
// applyModelGate → resolveExplicitConfig after override resolution, so a
// permit-all nil filter passes transparently here).
package daemon

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
)

// twoProviders returns two providers: "alpha" (saved model "alpha-model") and
// "beta" (saved model "beta-model"). Both satisfy the default primary slot
// constraints (200k context).
func twoProviders() []SlotProvider {
	return []SlotProvider{provWithModel("alpha", "alpha-model"), provWithModel("beta", "beta-model")}
}

func newSilentManager(providers []SlotProvider) *DaemonSlotManager {
	return NewDaemonSlotManager(providers, slotTestLogger())
}

// TestOverride_HonorsExplicitNodeBinding verifies that a per-node override for
// slot "primary" routes to the pinned provider/model even when a tenant default
// exists pointing to a different provider.
func TestOverride_HonorsExplicitNodeBinding(t *testing.T) {
	providers := twoProviders()
	// Tenant default is "alpha"; override pins "primary" to "beta/beta-model".
	mgr := newSilentManager(providers).WithDefaultProvider("alpha")

	slotDef := agent.NewSlotDefinition("primary", "primary slot", true)
	override := &agent.SlotConfig{Provider: "beta", Model: "beta-model"}

	picked, err := mgr.ResolveSlot(context.Background(), slotDef, override)
	require.NoError(t, err)
	assert.Equal(t, "beta", picked.Provider,
		"expected the per-node override to win over the tenant default")
	assert.Equal(t, "beta-model", picked.Model)
}

// TestOverride_TwoSlotsIndependent verifies that two slots pinned to different
// providers on the same node resolve independently and do not interfere.
func TestOverride_TwoSlotsIndependent(t *testing.T) {
	providers := twoProviders()
	mgr := newSilentManager(providers)

	primarySlot := agent.NewSlotDefinition("primary", "primary slot", true)
	fastSlot := agent.NewSlotDefinition("fast", "fast slot", true)

	primaryOverride := &agent.SlotConfig{Provider: "alpha", Model: "alpha-model"}
	fastOverride := &agent.SlotConfig{Provider: "beta", Model: "beta-model"}

	primary, err := mgr.ResolveSlot(context.Background(), primarySlot, primaryOverride)
	require.NoError(t, err)
	assert.Equal(t, "alpha", primary.Provider)
	assert.Equal(t, "alpha-model", primary.Model)

	fast, err := mgr.ResolveSlot(context.Background(), fastSlot, fastOverride)
	require.NoError(t, err)
	assert.Equal(t, "beta", fast.Provider)
	assert.Equal(t, "beta-model", fast.Model)
}

// TestOverride_UnpinnedSlotFallsThroughToDefault verifies that when no override
// is supplied (nil), resolution falls through to the tenant default exactly as
// before the per-node override feature was introduced.
func TestOverride_UnpinnedSlotFallsThroughToDefault(t *testing.T) {
	providers := twoProviders()
	// Tenant default is "beta"; nil override should yield "beta".
	mgr := newSilentManager(providers).WithDefaultProvider("beta")

	slotDef := agent.NewSlotDefinition("primary", "primary slot", true)

	picked, err := mgr.ResolveSlot(context.Background(), slotDef, nil)
	require.NoError(t, err)
	assert.Equal(t, "beta", picked.Provider,
		"expected nil override to fall through to the tenant default provider")
}

// TestOverride_EmptyProviderFallsThroughToDefault verifies that a SlotConfig
// with an empty Provider string (i.e. the caller included the slot but left it
// blank) is treated as no-override and falls through to the tenant default.
func TestOverride_EmptyProviderFallsThroughToDefault(t *testing.T) {
	providers := twoProviders()
	mgr := newSilentManager(providers).WithDefaultProvider("beta")

	slotDef := agent.NewSlotDefinition("primary", "primary slot", true)
	// Empty provider should fall through.
	emptyOverride := &agent.SlotConfig{Provider: "", Model: ""}

	picked, err := mgr.ResolveSlot(context.Background(), slotDef, emptyOverride)
	require.NoError(t, err)
	// With an empty provider, the slot manager falls into resolveByConstraints
	// which should pick the tenant default "beta".
	assert.Equal(t, "beta", picked.Provider,
		"empty provider override must fall through to the tenant default")
}
