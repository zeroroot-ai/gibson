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
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/agent"
	"github.com/zeroroot-ai/gibson/internal/llm"
)

// setupTwoProviderRegistry returns a registry with two providers: "alpha" (with
// model "alpha-model") and "beta" (with model "beta-model"). Both satisfy the
// default primary slot constraints (200k context).
func setupTwoProviderRegistry(t *testing.T) llm.LLMRegistry {
	t.Helper()
	reg := llm.NewLLMRegistry()
	require.NoError(t, reg.RegisterProvider(provWithModel("alpha", "alpha-model")))
	require.NoError(t, reg.RegisterProvider(provWithModel("beta", "beta-model")))
	return reg
}

func newSilentManager(reg llm.LLMRegistry) *DaemonSlotManager {
	return NewDaemonSlotManager(reg, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

// TestOverride_HonorsExplicitNodeBinding verifies that a per-node override for
// slot "primary" routes to the pinned provider/model even when a tenant default
// exists pointing to a different provider.
func TestOverride_HonorsExplicitNodeBinding(t *testing.T) {
	reg := setupTwoProviderRegistry(t)
	// Tenant default is "alpha"; override pins "primary" to "beta/beta-model".
	mgr := newSilentManager(reg).WithDefaultProvider("alpha")

	slotDef := agent.NewSlotDefinition("primary", "primary slot", true)
	override := &agent.SlotConfig{Provider: "beta", Model: "beta-model"}

	provider, model, err := mgr.ResolveSlot(context.Background(), slotDef, override)
	require.NoError(t, err)
	assert.Equal(t, "beta", provider.Name(),
		"expected the per-node override to win over the tenant default")
	assert.Equal(t, "beta-model", model.Name)
}

// TestOverride_TwoSlotsIndependent verifies that two slots pinned to different
// providers on the same node resolve independently and do not interfere.
func TestOverride_TwoSlotsIndependent(t *testing.T) {
	reg := setupTwoProviderRegistry(t)
	mgr := newSilentManager(reg)

	primarySlot := agent.NewSlotDefinition("primary", "primary slot", true)
	fastSlot := agent.NewSlotDefinition("fast", "fast slot", true)

	primaryOverride := &agent.SlotConfig{Provider: "alpha", Model: "alpha-model"}
	fastOverride := &agent.SlotConfig{Provider: "beta", Model: "beta-model"}

	pPrimary, mPrimary, err := mgr.ResolveSlot(context.Background(), primarySlot, primaryOverride)
	require.NoError(t, err)
	assert.Equal(t, "alpha", pPrimary.Name())
	assert.Equal(t, "alpha-model", mPrimary.Name)

	pFast, mFast, err := mgr.ResolveSlot(context.Background(), fastSlot, fastOverride)
	require.NoError(t, err)
	assert.Equal(t, "beta", pFast.Name())
	assert.Equal(t, "beta-model", mFast.Name)
}

// TestOverride_UnpinnedSlotFallsThroughToDefault verifies that when no override
// is supplied (nil), resolution falls through to the tenant default exactly as
// before the per-node override feature was introduced.
func TestOverride_UnpinnedSlotFallsThroughToDefault(t *testing.T) {
	reg := setupTwoProviderRegistry(t)
	// Tenant default is "beta"; nil override should yield "beta".
	mgr := newSilentManager(reg).WithDefaultProvider("beta")

	slotDef := agent.NewSlotDefinition("primary", "primary slot", true)

	provider, _, err := mgr.ResolveSlot(context.Background(), slotDef, nil)
	require.NoError(t, err)
	assert.Equal(t, "beta", provider.Name(),
		"expected nil override to fall through to the tenant default provider")
}

// TestOverride_EmptyProviderFallsThroughToDefault verifies that a SlotConfig
// with an empty Provider string (i.e. the caller included the slot but left it
// blank) is treated as no-override and falls through to the tenant default.
func TestOverride_EmptyProviderFallsThroughToDefault(t *testing.T) {
	reg := setupTwoProviderRegistry(t)
	mgr := newSilentManager(reg).WithDefaultProvider("beta")

	slotDef := agent.NewSlotDefinition("primary", "primary slot", true)
	// Empty provider should fall through.
	emptyOverride := &agent.SlotConfig{Provider: "", Model: ""}

	provider, _, err := mgr.ResolveSlot(context.Background(), slotDef, emptyOverride)
	require.NoError(t, err)
	// With an empty provider, the slot manager falls into resolveByConstraints
	// which should pick the tenant default "beta".
	assert.Equal(t, "beta", provider.Name(),
		"empty provider override must fall through to the tenant default")
}
