// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/harness"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/platform/modelgate"
	"github.com/zeroroot-ai/gibson/internal/platform/providerconfig"
)

// SlotProvider is what slot resolution needs of one provider record: the
// name, the saved default model and the context window that was stored with it.
type SlotProvider struct {
	Name          string
	DefaultModel  string
	ContextWindow int
}

// DaemonSlotManager resolves a slot to one provider and one exact model name.
// It reads provider records and calls no provider. It adds constraint defaults
// for common slot names: "primary" 100k, "fast" 8k, "vision" 50k and
// "reasoning" 150k context window.
type DaemonSlotManager struct {
	providers map[string]SlotProvider
	logger    *slog.Logger
	mu        sync.RWMutex // Protects concurrent access to slot resolution

	// modelFilter gates the resolved (provider, model) against the
	// request's subject (modelgate). Both production builders always install
	// one. Nil means no gate, and occurs only in a test that builds a slot
	// manager by hand.
	modelFilter modelgate.Filter

	// onResolve is fired after every successful slot resolution. Used
	// by the daemon to emit model_resolved audit events.
	onResolve func(ctx context.Context, picked modelgate.Candidate, allowed bool)

	// defaultProvider is the tenant's default provider name. When a slot has no
	// explicit provider, resolution prefers this provider before falling back to
	// a deterministic (sorted) scan of the remaining providers.
	defaultProvider string
}

var _ harness.SlotManager = (*DaemonSlotManager)(nil)

// NewDaemonSlotManager creates a slot manager over the given provider records.
func NewDaemonSlotManager(records []SlotProvider, logger *slog.Logger) *DaemonSlotManager {
	m := &DaemonSlotManager{providers: make(map[string]SlotProvider, len(records)), logger: logger}
	for _, r := range records {
		m.providers[r.Name] = r
	}
	return m
}

// SlotProvidersFromRecords turns the provider records of a tenant into the
// providers that a chat slot can use, and names the default one. A disabled
// record and a record that serves only embeddings are left out.
func SlotProvidersFromRecords(recs []*providerconfig.ProviderConfig) (out []SlotProvider, defaultName string) {
	for _, r := range recs {
		if r == nil || !r.Enabled || !servesChat(r) {
			continue
		}
		out = append(out, SlotProvider{Name: r.Name, DefaultModel: r.DefaultModel, ContextWindow: r.DefaultModelContextWindow})
		if r.IsDefault {
			defaultName = r.Name
		}
	}
	return out, defaultName
}

// servesChat reports whether a record serves chat. An empty capability list
// means the chat only default.
func servesChat(r *providerconfig.ProviderConfig) bool {
	if len(r.Capabilities) == 0 {
		return true
	}
	for _, c := range r.Capabilities {
		if c == providerconfig.CapabilityChat {
			return true
		}
	}
	return false
}

func (m *DaemonSlotManager) providerNames() []string {
	names := make([]string, 0, len(m.providers))
	for n := range m.providers {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// WithDefaultProvider sets the tenant's default provider, preferred when a slot
// has no explicit provider (gibson#531).
func (m *DaemonSlotManager) WithDefaultProvider(name string) *DaemonSlotManager {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.defaultProvider = name
	return m
}

// WithModelFilter wires a modelgate.Filter so slot resolution checks the
// request's subject against the picked (provider, model).
func (m *DaemonSlotManager) WithModelFilter(f modelgate.Filter) *DaemonSlotManager {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.modelFilter = f
	return m
}

// WithResolveCallback wires a callback fired after every slot resolution
// with the picked candidate and whether access was permitted.
func (m *DaemonSlotManager) WithResolveCallback(cb func(ctx context.Context, picked modelgate.Candidate, allowed bool)) *DaemonSlotManager {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onResolve = cb
	return m
}

// applyModelGate runs the configured modelgate.Filter on the picked
// (provider, model) and fires the optional resolve callback. It returns nil
// when access is permitted or no filter is wired. Otherwise it returns
// ErrNoMatchingProvider with the model_access_denied reason.
func (m *DaemonSlotManager) applyModelGate(ctx context.Context, slot agent.SlotDefinition, picked harness.SlotModel) error {
	cand := modelgate.Candidate{Provider: picked.Provider, Model: picked.Model}
	allowed := true
	if m.modelFilter != nil {
		permitted, ferr := m.modelFilter.Permitted(ctx, []modelgate.Candidate{cand})
		if ferr != nil {
			// Fail closed (gibson#527): a model access gate is a hard security
			// boundary. An FGA error must not become an open door to a model.
			if m.onResolve != nil {
				m.onResolve(ctx, cand, false)
			}
			// Only an outage marks the error as retryable (gibson#1219).
			mark := modelgate.ErrDenied
			if modelgate.CouldNotDecide(ferr) {
				mark = modelgate.ErrUnavailable
			}
			return types.WrapError(
				harness.ErrNoMatchingProvider,
				fmt.Sprintf("model_access_denied: authorization check failed for model %q on provider %q (slot %q)",
					picked.Model, picked.Provider, slot.Name),
				fmt.Errorf("%w: %w", mark, ferr),
			)
		}
		allowed = len(permitted) == 1
	}
	if m.onResolve != nil {
		m.onResolve(ctx, cand, allowed)
	}
	if !allowed {
		return types.WrapError(
			harness.ErrNoMatchingProvider,
			fmt.Sprintf("model_access_denied: user not permitted to use model %q on provider %q for slot %q",
				picked.Model, picked.Provider, slot.Name),
			modelgate.ErrDenied,
		)
	}
	return nil
}

// ResolveSlot resolves a slot definition to one provider and one exact model
// name that satisfy the constraints and the configuration of the slot.
//
// Resolution process:
//  1. Fail when the tenant has no provider record that serves chat
//  2. Apply constraint defaults by slot name
//  3. Merge the slot default config with the override
//  4. A node pin that names a provider resolves on that provider only, and
//     its failure is the answer: a pin never falls back (gibson#1203)
//  5. Otherwise try the named provider, the tenant default, then the rest in
//     sorted order
//
// It returns ErrNoMatchingProvider when no provider and model meet the slot.
func (m *DaemonSlotManager) ResolveSlot(ctx context.Context, slot agent.SlotDefinition, override *agent.SlotConfig) (harness.SlotModel, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(m.providers) == 0 {
		return harness.SlotModel{}, types.NewError(
			harness.ErrNoMatchingProvider,
			fmt.Sprintf("no LLM provider configured for this tenant (slot %q) — add one in Settings → Providers", slot.Name),
		)
	}

	hasExplicitProvider := slot.Default.Provider != "" || (override != nil && override.Provider != "")
	effectiveSlot := m.applySlotNameDefaults(slot)
	config := effectiveSlot.MergeConfig(override)

	if config.Provider != "" && config.Model != "" {
		picked, err := m.resolveExplicitConfig(ctx, effectiveSlot, config)
		if err == nil {
			return picked, nil
		}
		// Fall back to the constraint search only when the provider is missing
		// and the slot name set it as a preference. A provider that the user
		// asked for, or a model below the constraints, is the answer.
		if !isProviderNotFoundError(err) || hasExplicitProvider {
			return harness.SlotModel{}, err
		}
	}

	if override != nil && override.Provider != "" {
		return m.resolvePinnedProvider(ctx, effectiveSlot, config)
	}
	return m.resolveByConstraints(ctx, effectiveSlot, config)
}

// resolvePinnedProvider resolves a slot on the one provider that a node pin
// names, with the pinned model or the saved default model of the provider.
func (m *DaemonSlotManager) resolvePinnedProvider(ctx context.Context, slot agent.SlotDefinition, config agent.SlotConfig) (harness.SlotModel, error) {
	return m.tryProvider(ctx, config.Provider, slot, config.Model)
}

// ValidateSlot validates that a slot configuration can be satisfied.
func (m *DaemonSlotManager) ValidateSlot(ctx context.Context, slot agent.SlotDefinition) error {
	_, err := m.ResolveSlot(ctx, slot, nil)
	return err
}

// applySlotNameDefaults applies constraint defaults based on common slot names.
func (m *DaemonSlotManager) applySlotNameDefaults(slot agent.SlotDefinition) agent.SlotDefinition {
	if slot.Default.Provider != "" && slot.Default.Model != "" {
		return slot
	}
	defaults := map[string]int{"primary": 100000, "fast": 8192, "vision": 50000, "reasoning": 150000}
	if w, ok := defaults[slot.Name]; ok && slot.Constraints.MinContextWindow == 0 {
		slot.Constraints.MinContextWindow = w
	}
	return slot
}

// resolveExplicitConfig resolves a slot when provider and model are named.
func (m *DaemonSlotManager) resolveExplicitConfig(ctx context.Context, slot agent.SlotDefinition, config agent.SlotConfig) (harness.SlotModel, error) {
	p, ok := m.providers[config.Provider]
	if !ok {
		return harness.SlotModel{}, types.NewError(
			harness.ErrProviderNotFound,
			fmt.Sprintf("provider %q not found for slot %q. Configure it in the tenant's provider configuration or pick another provider",
				config.Provider, slot.Name),
		)
	}
	picked := savedModel(p, config.Model)
	if err := m.validateConstraints(slot, picked); err != nil {
		return harness.SlotModel{}, types.WrapError(
			harness.ErrNoMatchingProvider,
			fmt.Sprintf("model %q from provider %q does not meet constraints for slot %q",
				config.Model, config.Provider, slot.Name),
			err,
		)
	}
	if err := m.applyModelGate(ctx, slot, picked); err != nil {
		return harness.SlotModel{}, err
	}
	return picked, nil
}

// savedModel describes a model for a slot check. The saved default model of the
// provider carries the context window stored with it at save time. Any other
// model has an unknown window (zero).
func savedModel(p SlotProvider, name string) harness.SlotModel {
	out := harness.SlotModel{Provider: p.Name, Model: name}
	if name == p.DefaultModel && p.ContextWindow > 0 {
		out.ContextWindow = p.ContextWindow
	}
	return out
}

// resolveByConstraints searches the providers for a model that meets the slot.
func (m *DaemonSlotManager) resolveByConstraints(ctx context.Context, slot agent.SlotDefinition, config agent.SlotConfig) (harness.SlotModel, error) {
	names := m.providerNames()
	// Provider preference: an explicit slot provider first, then the tenant
	// default (gibson#531). Never a hardcoded preference.
	var order []string
	if config.Provider != "" {
		order = append(order, config.Provider)
	}
	if m.defaultProvider != "" && m.defaultProvider != config.Provider {
		order = append(order, m.defaultProvider)
	}
	for _, n := range names {
		if n != config.Provider && n != m.defaultProvider {
			order = append(order, n)
		}
	}
	var lastErr error
	for i, name := range order {
		picked, err := m.tryProvider(ctx, name, slot, m.modelFor(name, config, len(names)))
		if err == nil {
			if config.Provider == "" && m.defaultProvider == "" && i == 0 && m.logger != nil {
				m.logger.Info("no explicit provider configured, using first available",
					"slot", slot.Name, "provider", picked.Provider, "model", picked.Model)
			}
			return picked, nil
		}
		lastErr = err
	}
	return harness.SlotModel{}, types.WrapError(
		harness.ErrNoMatchingProvider,
		fmt.Sprintf("no provider found with model meeting constraints for slot %q (min_context: %d)",
			slot.Name, slot.Constraints.MinContextWindow),
		lastErr,
	)
}

// tryProvider resolves a slot on one provider. The model is the preferred
// model when the slot names one for this provider, else the default model that
// the tenant saved for the provider. A provider with neither fails.
func (m *DaemonSlotManager) tryProvider(ctx context.Context, providerName string, slot agent.SlotDefinition, preferredModel string) (harness.SlotModel, error) {
	p, ok := m.providers[providerName]
	if !ok {
		return harness.SlotModel{}, types.NewError(harness.ErrProviderNotFound, fmt.Sprintf("provider %q not found", providerName))
	}
	name := preferredModel
	if name == "" {
		name = p.DefaultModel
	}
	if name == "" {
		return harness.SlotModel{}, types.NewError(
			harness.ErrNoMatchingProvider,
			fmt.Sprintf("provider %q has no saved default model. Set one in Settings → Providers", providerName),
		)
	}
	picked := savedModel(p, name)
	if err := m.validateConstraints(slot, picked); err != nil {
		return harness.SlotModel{}, err
	}
	if err := m.applyModelGate(ctx, slot, picked); err != nil {
		return harness.SlotModel{}, err
	}
	return picked, nil
}

// modelFor returns the model that config names for the provider, or "". An
// explicit provider owns the model. With no provider named, the model goes to
// the tenant default provider, or to the only provider.
func (m *DaemonSlotManager) modelFor(providerName string, config agent.SlotConfig, providerCount int) string {
	switch {
	case config.Model == "":
		return ""
	case config.Provider == providerName:
		return config.Model
	case config.Provider == "" && (providerName == m.defaultProvider || providerCount == 1):
		return config.Model
	default:
		return ""
	}
}

// isProviderNotFoundError checks if an error or its cause chain holds a
// provider not found error.
func isProviderNotFoundError(err error) bool {
	var gibsonErr *types.GibsonError
	if errors.As(err, &gibsonErr) {
		if gibsonErr.Code == harness.ErrProviderNotFound {
			return true
		}
		if gibsonErr.Cause != nil {
			return isProviderNotFoundError(gibsonErr.Cause)
		}
	}
	return false
}

// validateConstraints checks if a model meets the constraints of the slot. An
// unknown context window (zero) passes. A known window that falls short fails.
func (m *DaemonSlotManager) validateConstraints(slot agent.SlotDefinition, model harness.SlotModel) error {
	minWindow := slot.Constraints.MinContextWindow
	if model.ContextWindow > 0 && model.ContextWindow < minWindow {
		return types.NewError(
			harness.ErrInvalidSlotConfig,
			fmt.Sprintf("model %q context window %d is less than required %d for slot %q",
				model.Model, model.ContextWindow, minWindow, slot.Name),
		)
	}
	return nil
}
