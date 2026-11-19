// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// multi_slot_override_e2e_test.go is the integration/e2e lock-in test for the
// per-node, per-slot LLM override pipeline introduced by gibson#539.
//
// It exercises the real resolution seam end-to-end:
//
//	provider records → slot providers → per-tenant DaemonSlotManager →
//	ResolveSlot with per-node overrides supplied directly (as they arrive from
//	the orchestrator).
//
// The four guarantees locked in here:
//
//  1. A node binding pinning slot X to a NON-DEFAULT provider resolves to
//     that provider/model, not the tenant default.
//  2. Two slots pinned to different providers on the same node resolve
//     independently and do not interfere.
//  3. An unpinned slot (nil override) falls through to the tenant default.
//  4. A pinned-but-ungranted provider/model is DENIED by the FGA model-access
//     gate (fail-closed) — pinning must never bypass ACL scoping.
//
// The test is deterministic across repeated runs (go test -race -count=3)
// because provider preference order in the resolver is deterministic-sorted
// (no map-iteration dependence, per gibson#531).
//
// Prior art:
//   - internal/server/daemon/per_tenant_resolution_int_test.go (provider record seam)
//   - internal/server/daemon/slot_manager_gate_test.go (modelgate.Filter wiring pattern)
//   - internal/server/daemon/slot_manager_node_override_test.go (unit-level override guarantees)
package daemon

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/platform/modelgate"
	"github.com/zeroroot-ai/gibson/internal/platform/providerconfig"
)

// ── helpers ──────────────────────────────────────────────────────────────────

// e2eStore holds the provider records of each tenant for the e2e tests.
type e2eStore struct {
	configs map[string][]*providerconfig.ProviderConfig
}

func (s *e2eStore) List(_ context.Context, tenant string) ([]*providerconfig.ProviderConfig, error) {
	return s.configs[tenant], nil
}

// e2eManager builds a DaemonSlotManager from the provider records of the given
// tenant, optionally with a modelgate.Filter. Each provider has one saved model
// named "<provider>-model" with a 200k context window. That window satisfies
// every default slot constraint.
func e2eManager(t *testing.T, store *e2eStore, tenantID string, filter modelgate.Filter) *DaemonSlotManager {
	t.Helper()
	recs, err := store.List(context.Background(), tenantID)
	require.NoError(t, err)
	providers, defaultName := SlotProvidersFromRecords(recs)

	mgr := NewDaemonSlotManager(providers, slotTestLogger()).WithDefaultProvider(defaultName)
	if filter != nil {
		mgr.WithModelFilter(filter)
	}
	return mgr
}

// allowProviderFilter is a modelgate.Filter that permits candidates only when
// their Provider matches one of the allowed providers in the set. This mirrors
// the FGA "user has can_use on model:<model>" shape — we key the grant by
// provider name for test readability, but the gate path through applyModelGate
// is identical: Permitted() is called with a single Candidate, and an empty
// returned slice means denied.
type allowProviderFilter struct {
	allowedProviders map[string]struct{}
}

func newAllowProviderFilter(providers ...string) *allowProviderFilter {
	m := make(map[string]struct{}, len(providers))
	for _, p := range providers {
		m[p] = struct{}{}
	}
	return &allowProviderFilter{allowedProviders: m}
}

func (f *allowProviderFilter) Permitted(_ context.Context, cands []modelgate.Candidate) ([]modelgate.Candidate, error) {
	out := make([]modelgate.Candidate, 0, len(cands))
	for _, c := range cands {
		if _, ok := f.allowedProviders[c.Provider]; ok {
			out = append(out, c)
		}
	}
	return out, nil
}

func (f *allowProviderFilter) InvalidateCache() {}

// ── test store setup ──────────────────────────────────────────────────────────

// newE2ETwoProviderStore returns a store with a tenant that has two providers:
// "anthropic" (default) and "openai". This mirrors a real tenant with two
// configured providers where one is set as the org default.
func newE2ETwoProviderStore() *e2eStore {
	return &e2eStore{
		configs: map[string][]*providerconfig.ProviderConfig{
			"tenant-e2e": {
				{Name: "anthropic", Type: providerconfig.ProviderAnthropic, Enabled: true, IsDefault: true,
					DefaultModel: "anthropic-model", DefaultModelContextWindow: 200000},
				{Name: "openai", Type: providerconfig.ProviderOpenAI, Enabled: true, IsDefault: false,
					DefaultModel: "openai-model", DefaultModelContextWindow: 200000},
			},
		},
	}
}

// ── tests ─────────────────────────────────────────────────────────────────────

// TestMultiSlotOverrideE2E is the integration lock-in for the full per-node,
// per-slot override pipeline (resolver → DaemonSlotManager → ResolveSlot).
// Each subtest is independent; the manager is rebuilt from the resolver to
// exercise the full wiring path on every case.
func TestMultiSlotOverrideE2E(t *testing.T) {
	store := newE2ETwoProviderStore()
	ctx := context.Background()

	// AC1: A node binding pinning slot X to a NON-DEFAULT provider resolves to
	// that provider/model — not the tenant default ("anthropic").
	t.Run("pinned_slot_resolves_to_override_not_tenant_default", func(t *testing.T) {
		mgr := e2eManager(t, store, "tenant-e2e", nil)

		primarySlot := agent.NewSlotDefinition("primary", "primary slot", true)
		// Pin "primary" to "openai" — the non-default provider.
		override := &agent.SlotConfig{Provider: "openai", Model: "openai-model"}

		picked, err := mgr.ResolveSlot(ctx, primarySlot, override)
		require.NoError(t, err)
		assert.Equal(t, "openai", picked.Provider,
			"per-node override must win over the tenant default provider")
		assert.Equal(t, "openai-model", picked.Model)
	})

	// AC2: Two slots pinned to different providers on one node resolve
	// independently — neither pollutes the other.
	t.Run("two_slots_pinned_to_different_providers_resolve_independently", func(t *testing.T) {
		mgr := e2eManager(t, store, "tenant-e2e", nil)

		primarySlot := agent.NewSlotDefinition("primary", "primary slot", true)
		fastSlot := agent.NewSlotDefinition("fast", "fast slot", false)

		// Inverse of the tenant default: "primary" → "openai", "fast" → "anthropic".
		primaryOverride := &agent.SlotConfig{Provider: "openai", Model: "openai-model"}
		fastOverride := &agent.SlotConfig{Provider: "anthropic", Model: "anthropic-model"}

		primary, err := mgr.ResolveSlot(ctx, primarySlot, primaryOverride)
		require.NoError(t, err, "primary slot with override must resolve")
		assert.Equal(t, "openai", primary.Provider, "primary slot must resolve to the pinned 'openai' provider")
		assert.Equal(t, "openai-model", primary.Model)

		fast, err := mgr.ResolveSlot(ctx, fastSlot, fastOverride)
		require.NoError(t, err, "fast slot with override must resolve")
		assert.Equal(t, "anthropic", fast.Provider, "fast slot must resolve to the pinned 'anthropic' provider")
		assert.Equal(t, "anthropic-model", fast.Model)

		// Verify independence: providers are distinct.
		assert.NotEqual(t, primary.Provider, fast.Provider,
			"two independently-pinned slots must not resolve to the same provider")
	})

	// AC3: An unpinned slot (nil override) falls through to the tenant default.
	t.Run("unpinned_slot_falls_through_to_tenant_default", func(t *testing.T) {
		mgr := e2eManager(t, store, "tenant-e2e", nil)

		primarySlot := agent.NewSlotDefinition("primary", "primary slot", true)

		picked, err := mgr.ResolveSlot(ctx, primarySlot, nil)
		require.NoError(t, err, "unpinned slot must resolve via the tenant default")
		assert.Equal(t, "anthropic", picked.Provider,
			"nil override must fall through to the tenant default provider 'anthropic'")
	})

	// AC4: A pinned-but-ungranted provider/model is DENIED by the FGA
	// model-access gate (fail-closed). The filter grants only "anthropic"; a pin
	// to "openai" must be rejected with model_access_denied, even though "openai"
	// is a valid registered provider for the tenant.
	t.Run("pinned_ungranted_provider_denied_by_model_gate", func(t *testing.T) {
		// Wire a gate that grants only "anthropic"; "openai" is ungranted.
		filter := newAllowProviderFilter("anthropic")
		mgr := e2eManager(t, store, "tenant-e2e", filter)

		primarySlot := agent.NewSlotDefinition("primary", "primary slot", true)
		// Override pins to the UNGRANTED provider.
		override := &agent.SlotConfig{Provider: "openai", Model: "openai-model"}

		_, err := mgr.ResolveSlot(ctx, primarySlot, override)
		require.Error(t, err, "pinning to an ungranted provider must be denied")
		assert.True(t,
			strings.Contains(err.Error(), "model_access_denied"),
			"error must carry the model_access_denied sentinel; got: %v", err,
		)
	})

	// AC4 complement: the same gate permits the granted provider when pinned.
	t.Run("pinned_granted_provider_resolves_with_model_gate", func(t *testing.T) {
		// Grant only "anthropic" — the same setup as the denial case above.
		filter := newAllowProviderFilter("anthropic")
		mgr := e2eManager(t, store, "tenant-e2e", filter)

		primarySlot := agent.NewSlotDefinition("primary", "primary slot", true)
		override := &agent.SlotConfig{Provider: "anthropic", Model: "anthropic-model"}

		picked, err := mgr.ResolveSlot(ctx, primarySlot, override)
		require.NoError(t, err, "pinning to a granted provider must succeed")
		assert.Equal(t, "anthropic", picked.Provider)
		assert.Equal(t, "anthropic-model", picked.Model)
	})
}

// TestMultiSlotOverrideE2E_Determinism verifies that repeated resolution with
// the same override configuration always returns the same provider/model, with
// no map-iteration-order dependence. This is the AC5 (determinism) check;
// running with -race -count=3 exercises the ordering guarantee.
func TestMultiSlotOverrideE2E_Determinism(t *testing.T) {
	store := newE2ETwoProviderStore()
	ctx := context.Background()

	const repetitions = 20
	primarySlot := agent.NewSlotDefinition("primary", "primary slot", true)
	override := &agent.SlotConfig{Provider: "openai", Model: "openai-model"}

	for i := 0; i < repetitions; i++ {
		// Rebuild the manager from the resolver on every iteration so we don't
		// benefit from any state sharing between calls.
		mgr := e2eManager(t, store, "tenant-e2e", nil)

		picked, err := mgr.ResolveSlot(ctx, primarySlot, override)
		require.NoError(t, err, "iteration %d: unexpected error", i)
		assert.Equal(t, "openai", picked.Provider,
			"iteration %d: provider must be deterministically 'openai'", i)
		assert.Equal(t, "openai-model", picked.Model,
			"iteration %d: model must be deterministically 'openai-model'", i)
	}
}
