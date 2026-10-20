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
	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	"github.com/zeroroot-ai/gibson/internal/engine/llm/modelgate"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// DaemonSlotManager implements llm.SlotManager with intelligent slot-to-provider
// resolution based on slot name conventions and provider capabilities.
//
// It extends the default slot manager behavior by providing constraint defaults for
// common slot names:
//   - "primary": MinContextWindow 100k (high-capability model for main agent reasoning)
//   - "fast": MinContextWindow 8k (low-latency model for quick operations)
//   - "vision": MinContextWindow 50k
//   - "reasoning": MinContextWindow 150k (large context window for complex reasoning)
//
// The manager queries the LLM registry to find available providers that match
// slot requirements, selecting models based on constraints rather than hardcoded defaults.
type DaemonSlotManager struct {
	registry llm.LLMRegistry
	logger   *slog.Logger
	mu       sync.RWMutex // Protects concurrent access to slot resolution

	// modelFilter gates the resolved (provider, model) against the
	// request's subject (modelgate). Both production builders always install
	// one (buildSlotManagerForSet, grpc.go). Nil means no gate, and occurs
	// only in a test that builds a slot manager by hand.
	// Spec: llm-user-attribution-governance (Requirement 4).
	modelFilter modelgate.Filter

	// onResolve is fired after every successful slot resolution. Used
	// by the daemon to emit model_resolved audit events.
	onResolve func(ctx context.Context, picked modelgate.Candidate, allowed bool)

	// defaultProvider is the tenant's default provider name. When a slot has no
	// explicit provider, resolution prefers this provider before falling back to
	// a deterministic (sorted) scan of the remaining providers. Empty = no
	// default. Set per-tenant via WithDefaultProvider (gibson#531).
	defaultProvider string
}

// NewDaemonSlotManager creates a new DaemonSlotManager with the given LLM registry.
//
// The manager uses the registry to discover available providers and their capabilities,
// enabling dynamic slot resolution based on runtime provider availability.
func NewDaemonSlotManager(registry llm.LLMRegistry, logger *slog.Logger) *DaemonSlotManager {
	return &DaemonSlotManager{
		registry: registry,
		logger:   logger,
	}
}

// WithModelFilter wires a modelgate.Filter so slot resolution checks the
// request's subject against the picked (provider, model). See modelgate for
// the rule and for the subject.
// Spec: llm-user-attribution-governance Requirement 4.
// WithDefaultProvider sets the tenant's default provider, preferred when a slot
// has no explicit provider (gibson#531). Makes resolution deterministic and
// default-respecting instead of arbitrary "first available".
func (m *DaemonSlotManager) WithDefaultProvider(name string) *DaemonSlotManager {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.defaultProvider = name
	return m
}

func (m *DaemonSlotManager) WithModelFilter(f modelgate.Filter) *DaemonSlotManager {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.modelFilter = f
	return m
}

// WithResolveCallback wires a callback fired after every slot resolution
// with the picked candidate + whether access was permitted. Daemon
// bootstrap uses this to emit model_resolved audit events from a single
// point (rather than having every caller emit).
// Spec: llm-user-attribution-governance Requirement 4.7.
func (m *DaemonSlotManager) WithResolveCallback(cb func(ctx context.Context, picked modelgate.Candidate, allowed bool)) *DaemonSlotManager {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onResolve = cb
	return m
}

// applyModelGate runs the configured modelgate.Filter on the picked
// (provider, model) and emits the optional resolve callback. Returns
// nil when access is permitted or no filter is wired; otherwise
// returns an ErrNoMatchingProvider signaling model_access_denied.
func (m *DaemonSlotManager) applyModelGate(ctx context.Context, slot agent.SlotDefinition, provider llm.LLMProvider, model llm.ModelInfo) error {
	picked := modelgate.Candidate{
		Provider: provider.Name(),
		Model:    model.Name,
	}
	allowed := true
	if m.modelFilter != nil {
		permitted, ferr := m.modelFilter.Permitted(ctx, []modelgate.Candidate{picked})
		if ferr != nil {
			// Fail closed (gibson#527): a model-access gate is a hard security
			// boundary. If the authorizer cannot confirm permission, deny rather
			// than allow — an FGA error must not become an open door to a model.
			if m.onResolve != nil {
				m.onResolve(ctx, picked, false)
			}
			// Only an outage marks the error as retryable. A permanent error
			// (no authorizer, a bad request, a short answer) cannot succeed on
			// a retry, so a pinned Decider must stop on it (gibson#1219).
			mark := modelgate.ErrDenied
			if modelgate.CouldNotDecide(ferr) {
				mark = modelgate.ErrUnavailable
			}
			cause := fmt.Errorf("%w: %w", mark, ferr)
			return types.WrapError(
				llm.ErrNoMatchingProvider,
				fmt.Sprintf("model_access_denied: authorization check failed for model %q on provider %q (slot %q)",
					model.Name, provider.Name(), slot.Name),
				cause,
			)
		}
		allowed = len(permitted) == 1
	}
	if m.onResolve != nil {
		m.onResolve(ctx, picked, allowed)
	}
	if !allowed {
		return types.WrapError(
			llm.ErrNoMatchingProvider,
			fmt.Sprintf("model_access_denied: user not permitted to use model %q on provider %q for slot %q",
				model.Name, provider.Name(), slot.Name),
			modelgate.ErrDenied,
		)
	}
	return nil
}

// ResolveSlot resolves a slot definition to a specific provider and model that
// satisfies the slot's constraints and configuration.
//
// Resolution process:
//  1. Check if any providers are available
//  2. Apply slot name-based defaults if no explicit config is provided
//  3. Merge slot default config with any override
//  4. A node pin that names a provider resolves on that provider only, and
//     its failure is the answer: a pin never falls back (gibson#1203)
//  5. Otherwise query registry for available providers
//  6. Find a model that meets all constraints (context window)
//  7. Return the provider and model info
//
// Returns ErrNoMatchingProvider if:
//   - No providers are available in the registry
//   - No provider has a model meeting the slot constraints
//   - The specified provider/model doesn't exist or meet requirements
func (m *DaemonSlotManager) ResolveSlot(ctx context.Context, slot agent.SlotDefinition, override *agent.SlotConfig) (llm.LLMProvider, llm.ModelInfo, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Check if any providers are registered before proceeding
	providerNames := m.registry.ListProviders()
	if len(providerNames) == 0 {
		return nil, llm.ModelInfo{}, types.NewError(
			llm.ErrNoMatchingProvider,
			fmt.Sprintf("no LLM provider configured for this tenant (slot %q) — add one in Settings → Providers", slot.Name),
		)
	}

	// Track if the slot had an explicit provider config before applying defaults
	hasExplicitProvider := slot.Default.Provider != "" || (override != nil && override.Provider != "")

	// Apply intelligent defaults based on slot name if no override specified
	effectiveSlot := m.applySlotNameDefaults(slot)

	// Merge configuration (default + override)
	config := effectiveSlot.MergeConfig(override)

	// If provider and model are explicitly specified, try to resolve directly
	if config.Provider != "" && config.Model != "" {
		provider, model, err := m.resolveExplicitConfig(ctx, effectiveSlot, config)
		if err == nil {
			return provider, model, nil
		}

		// Only fall back to constraint-based search if:
		// 1. The provider isn't available (provider not found error)
		// 2. The provider was set by slot name defaults (not explicitly by user)
		// If the user explicitly requested a provider that doesn't exist, return the error
		if isProviderNotFoundError(err) && !hasExplicitProvider {
			// Provider not available but was just a default preference, try fallback
		} else {
			// Error should be returned: either user explicitly requested this provider,
			// or the model doesn't meet constraints
			return nil, llm.ModelInfo{}, err
		}
	}

	// A node pin that names a provider (gibson#1203) allows that provider
	// only. Its failure is the answer: a pin never falls back to another
	// provider in silence.
	if override != nil && override.Provider != "" {
		return m.resolvePinnedProvider(ctx, effectiveSlot, config)
	}

	// Search for a matching provider/model based on constraints
	return m.resolveByConstraints(ctx, effectiveSlot, config)
}

// resolvePinnedProvider resolves a slot on the one provider that a node pin
// names, with the pinned model or the provider's saved default model. A
// provider that the tenant does not have, a provider with no saved model, a
// model below the slot constraints and a model the gate denies each fail the
// resolution with their own reason.
func (m *DaemonSlotManager) resolvePinnedProvider(ctx context.Context, slot agent.SlotDefinition, config agent.SlotConfig) (llm.LLMProvider, llm.ModelInfo, error) {
	provider, model, err := m.tryProvider(ctx, config.Provider, slot, config.Model)
	if err != nil {
		return nil, llm.ModelInfo{}, types.WrapError(
			llm.ErrNoMatchingProvider,
			fmt.Sprintf("slot %q is pinned to provider %q, and the pin cannot be served", slot.Name, config.Provider),
			err,
		)
	}
	return provider, model, nil
}

// ValidateSlot validates that a slot configuration can be satisfied by available providers.
// It attempts to resolve the slot with its default configuration to ensure viability.
func (m *DaemonSlotManager) ValidateSlot(ctx context.Context, slot agent.SlotDefinition) error {
	_, _, err := m.ResolveSlot(ctx, slot, nil)
	return err
}

// applySlotNameDefaults applies intelligent defaults based on common slot name conventions.
// This allows agents to use semantic slot names without specifying full provider configs.
func (m *DaemonSlotManager) applySlotNameDefaults(slot agent.SlotDefinition) agent.SlotDefinition {
	// If slot already has explicit provider config, use it as-is
	if slot.Default.Provider != "" && slot.Default.Model != "" {
		return slot
	}

	// Apply defaults based on slot name
	switch slot.Name {
	case "primary":
		// High-capability model for main agent reasoning
		if slot.Constraints.MinContextWindow == 0 {
			slot.Constraints.MinContextWindow = 100000
		}

	case "fast":
		// Low-latency model for quick operations
		if slot.Constraints.MinContextWindow == 0 {
			slot.Constraints.MinContextWindow = 8192
		}

	case "vision":
		// Model with image understanding
		if slot.Constraints.MinContextWindow == 0 {
			slot.Constraints.MinContextWindow = 50000
		}

	case "reasoning":
		// High context window model for complex reasoning
		if slot.Constraints.MinContextWindow == 0 {
			slot.Constraints.MinContextWindow = 150000
		}

	default:
		// For unknown slot names, no defaults needed
		// Constraint-based search will handle provider/model selection
	}

	return slot
}

// resolveExplicitConfig resolves a slot when provider and model are explicitly specified
func (m *DaemonSlotManager) resolveExplicitConfig(ctx context.Context, slot agent.SlotDefinition, config agent.SlotConfig) (llm.LLMProvider, llm.ModelInfo, error) {
	// Get the specified provider
	provider, err := m.registry.GetProvider(config.Provider)
	if err != nil {
		return nil, llm.ModelInfo{}, types.WrapError(
			llm.ErrNoMatchingProvider,
			fmt.Sprintf("provider %q not found for slot %q. Configure it in the tenant's provider configuration or pick another provider",
				config.Provider, slot.Name),
			err,
		)
	}

	// The model is the saved choice of the tenant. A mission never asks the
	// provider for a model list: the list can be slow or down. The window comes
	// from the value stored with the saved provider. The provider rejects an
	// unknown model when it completes.
	model := savedModelInfo(provider, config.Model)
	if err := m.validateConstraints(slot, model); err != nil {
		return nil, llm.ModelInfo{}, types.WrapError(
			llm.ErrNoMatchingProvider,
			fmt.Sprintf("model %q from provider %q does not meet constraints for slot %q",
				config.Model, config.Provider, slot.Name),
			err,
		)
	}
	if err := m.applyModelGate(ctx, slot, provider, model); err != nil {
		return nil, llm.ModelInfo{}, err
	}
	return provider, model, nil
}

// savedModelInfo describes a model for a slot check. The saved default model of
// the provider carries the context window that was stored with it at save time,
// so its window is known. Any other model, and a provider saved before the
// window was stored, has an unknown window. A feature set is never known: no
// provider reports a complete one.
func savedModelInfo(provider llm.LLMProvider, name string) llm.ModelInfo {
	info := llm.ModelInfo{Name: name, ContextWindowUnreported: true}
	if name == llm.SavedModel(provider) {
		if w := llm.SavedModelWindow(provider); w > 0 {
			info.ContextWindow = w
			info.ContextWindowUnreported = false
		}
	}
	return info
}

// resolveByConstraints searches all available providers to find a model matching the slot constraints
func (m *DaemonSlotManager) resolveByConstraints(ctx context.Context, slot agent.SlotDefinition, config agent.SlotConfig) (llm.LLMProvider, llm.ModelInfo, error) {
	providerNames := m.registry.ListProviders()
	if len(providerNames) == 0 {
		return nil, llm.ModelInfo{}, types.NewError(
			llm.ErrNoMatchingProvider,
			fmt.Sprintf("no LLM providers registered for slot %q", slot.Name),
		)
	}

	// Provider preference order: an explicit slot provider first, then the
	// tenant's default provider (gibson#531) — never a hardcoded preference.
	preferredProviders := []string{}
	if config.Provider != "" {
		preferredProviders = append(preferredProviders, config.Provider)
	}
	if m.defaultProvider != "" && m.defaultProvider != config.Provider {
		preferredProviders = append(preferredProviders, m.defaultProvider)
	}

	// lastErr keeps the reason the last provider failed, so the final error
	// tells the person what to fix.
	var lastErr error

	// Try preferred providers first
	for _, providerName := range preferredProviders {
		provider, model, err := m.tryProvider(ctx, providerName, slot, m.modelFor(providerName, config, len(providerNames)))
		if err == nil {
			return provider, model, nil
		}
		lastErr = err
	}

	// Deterministic fallback: scan remaining providers in a stable (sorted)
	// order so selection never depends on map-iteration order (gibson#531).
	sortedNames := append([]string(nil), providerNames...)
	sort.Strings(sortedNames)

	// Try all other registered providers
	for _, providerName := range sortedNames {
		// Skip if already tried in preferred list
		alreadyTried := false
		for _, preferred := range preferredProviders {
			if providerName == preferred {
				alreadyTried = true
				break
			}
		}
		if alreadyTried {
			continue
		}

		provider, model, err := m.tryProvider(ctx, providerName, slot, m.modelFor(providerName, config, len(providerNames)))
		if err == nil {
			// Log when using fallback (no explicit provider configured)
			if config.Provider == "" && m.logger != nil {
				m.logger.Info("no explicit provider configured, using first available",
					"slot", slot.Name,
					"provider", provider.Name(),
					"model", model.Name,
				)
			}
			return provider, model, nil
		}
		lastErr = err
	}

	return nil, llm.ModelInfo{}, types.WrapError(
		llm.ErrNoMatchingProvider,
		fmt.Sprintf("no provider found with model meeting constraints for slot %q (min_context: %d)",
			slot.Name, slot.Constraints.MinContextWindow),
		lastErr,
	)
}

// tryProvider resolves a slot on one provider. The model is the preferred
// model when the slot names one for this provider, else the default model that
// the tenant saved for the provider. It never calls the network. A provider
// with neither fails with a clear error.
func (m *DaemonSlotManager) tryProvider(ctx context.Context, providerName string, slot agent.SlotDefinition, preferredModel string) (llm.LLMProvider, llm.ModelInfo, error) {
	provider, err := m.registry.GetProvider(providerName)
	if err != nil {
		return nil, llm.ModelInfo{}, err
	}

	name := preferredModel
	if name == "" {
		name = llm.SavedModel(provider)
	}
	if name == "" {
		return nil, llm.ModelInfo{}, types.NewError(
			llm.ErrNoMatchingProvider,
			fmt.Sprintf("provider %q has no saved default model. Set one in Settings → Providers", providerName),
		)
	}

	model := savedModelInfo(provider, name)
	if err := m.validateConstraints(slot, model); err != nil {
		return nil, llm.ModelInfo{}, err
	}
	if err := m.applyModelGate(ctx, slot, provider, model); err != nil {
		return nil, llm.ModelInfo{}, err
	}
	return provider, model, nil
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

// isProviderNotFoundError checks if an error or its cause chain contains a provider not found error
func isProviderNotFoundError(err error) bool {
	var gibsonErr *types.GibsonError
	if errors.As(err, &gibsonErr) {
		// Check the error code
		if gibsonErr.Code == llm.ErrLLMProviderNotFound || gibsonErr.Code == llm.ErrProviderNotFound {
			return true
		}
		// Check the cause chain
		if gibsonErr.Cause != nil {
			return isProviderNotFoundError(gibsonErr.Cause)
		}
	}
	return false
}

// validateConstraints checks if a model meets the slot's constraints
func (m *DaemonSlotManager) validateConstraints(slot agent.SlotDefinition, model llm.ModelInfo) error {
	constraints := slot.Constraints

	// An unreported context window or feature set passes: unknown is not too
	// small and not absent. A reported value that falls short still fails.
	if !model.ContextWindowAtLeast(constraints.MinContextWindow) {
		return types.NewError(
			llm.ErrInvalidSlotConfig,
			fmt.Sprintf("model %q context window %d is less than required %d for slot %q",
				model.Name, model.ContextWindow, constraints.MinContextWindow, slot.Name),
		)
	}

	return nil
}
