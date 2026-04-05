package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/zero-day-ai/gibson/internal/agent"
	"github.com/zero-day-ai/gibson/internal/llm"
	"github.com/zero-day-ai/gibson/internal/types"
)

// DaemonSlotManager implements llm.SlotManager with intelligent slot-to-provider
// resolution based on slot name conventions and provider capabilities.
//
// It extends the default slot manager behavior by providing constraint defaults for
// common slot names:
//   - "primary": MinContextWindow 100k (high-capability model for main agent reasoning)
//   - "fast": MinContextWindow 8k (low-latency model for quick operations)
//   - "vision": MinContextWindow 50k + vision feature required
//   - "reasoning": MinContextWindow 150k (large context window for complex reasoning)
//
// The manager queries the LLM registry to find available providers that match
// slot requirements, selecting models based on constraints rather than hardcoded defaults.
type DaemonSlotManager struct {
	registry        llm.LLMRegistry
	logger          *slog.Logger
	mu              sync.RWMutex          // Protects concurrent access to slot resolution
	providerEnvVars map[string]string      // Maps provider name to its API key env var name
}

// NewDaemonSlotManager creates a new DaemonSlotManager with the given LLM registry.
//
// The manager uses the registry to discover available providers and their capabilities,
// enabling dynamic slot resolution based on runtime provider availability.
func NewDaemonSlotManager(registry llm.LLMRegistry, logger *slog.Logger) *DaemonSlotManager {
	return &DaemonSlotManager{
		registry:        registry,
		logger:          logger,
		providerEnvVars: make(map[string]string),
	}
}

// SetProviderEnvVars configures the mapping from provider names to their API key
// environment variable names. This enables clear error messages when a slot resolves
// to a provider that has no API key configured.
func (m *DaemonSlotManager) SetProviderEnvVars(envVars map[string]string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.providerEnvVars = envVars
}

// envVarHint returns the environment variable hint for a provider, falling back
// to PROVIDER_NAME_API_KEY if not explicitly configured.
func (m *DaemonSlotManager) envVarHint(providerName string) string {
	if envVar, ok := m.providerEnvVars[providerName]; ok && envVar != "" {
		return envVar
	}
	return strings.ToUpper(providerName) + "_API_KEY"
}

// ResolveSlot resolves a slot definition to a specific provider and model that
// satisfies the slot's constraints and configuration.
//
// Resolution process:
// 1. Check if any providers are available
// 2. Apply slot name-based defaults if no explicit config is provided
// 3. Merge slot default config with any override
// 4. Query registry for available providers
// 5. Find a model that meets all constraints (context window, features)
// 6. Return the provider and model info
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
			fmt.Sprintf("no LLM providers configured for slot %q - set ANTHROPIC_API_KEY, OPENAI_API_KEY, or configure a provider in ~/.gibson/config.yaml", slot.Name),
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

	// Search for a matching provider/model based on constraints
	return m.resolveByConstraints(ctx, effectiveSlot, config)
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
		// Ensure vision feature is required
		hasVision := false
		for _, feature := range slot.Constraints.RequiredFeatures {
			if feature == agent.FeatureVision {
				hasVision = true
				break
			}
		}
		if !hasVision {
			slot.Constraints.RequiredFeatures = append(slot.Constraints.RequiredFeatures, agent.FeatureVision)
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
		envHint := m.envVarHint(config.Provider)
		return nil, llm.ModelInfo{}, types.WrapError(
			llm.ErrNoMatchingProvider,
			fmt.Sprintf("provider %q not found for slot %q. Set %q or configure an alternative provider",
				config.Provider, slot.Name, envHint),
			err,
		)
	}

	// Get models from provider
	models, err := provider.Models(ctx)
	if err != nil {
		return nil, llm.ModelInfo{}, types.WrapError(
			llm.ErrNoMatchingProvider,
			fmt.Sprintf("failed to get models from provider %q for slot %q", config.Provider, slot.Name),
			err,
		)
	}

	// Find the specified model
	for _, model := range models {
		if model.Name == config.Model {
			// Validate constraints
			if err := m.validateConstraints(slot, model); err != nil {
				return nil, llm.ModelInfo{}, types.WrapError(
					llm.ErrNoMatchingProvider,
					fmt.Sprintf("model %q from provider %q does not meet constraints for slot %q",
						config.Model, config.Provider, slot.Name),
					err,
				)
			}
			return provider, model, nil
		}
	}

	return nil, llm.ModelInfo{}, types.NewError(
		llm.ErrNoMatchingProvider,
		fmt.Sprintf("model %q not found in provider %q for slot %q", config.Model, config.Provider, slot.Name),
	)
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

	// Define provider preference order based on slot config
	preferredProviders := []string{}
	if config.Provider != "" {
		preferredProviders = append(preferredProviders, config.Provider)
	}
	// DO NOT add hardcoded providers here anymore

	// Try preferred providers first
	for _, providerName := range preferredProviders {
		provider, model, err := m.tryProvider(ctx, providerName, slot, config.Model)
		if err == nil {
			return provider, model, nil
		}
	}

	// Try all other registered providers
	for _, providerName := range providerNames {
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

		provider, model, err := m.tryProvider(ctx, providerName, slot, config.Model)
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
	}

	return nil, llm.ModelInfo{}, types.NewError(
		llm.ErrNoMatchingProvider,
		fmt.Sprintf("no provider found with model meeting constraints for slot %q (min_context: %d, features: %v)",
			slot.Name, slot.Constraints.MinContextWindow, slot.Constraints.RequiredFeatures),
	)
}

// tryProvider attempts to find a matching model from a specific provider
func (m *DaemonSlotManager) tryProvider(ctx context.Context, providerName string, slot agent.SlotDefinition, preferredModel string) (llm.LLMProvider, llm.ModelInfo, error) {
	provider, err := m.registry.GetProvider(providerName)
	if err != nil {
		return nil, llm.ModelInfo{}, err
	}

	models, err := provider.Models(ctx)
	if err != nil {
		return nil, llm.ModelInfo{}, err
	}

	// If a specific model is requested, try it first
	if preferredModel != "" {
		for _, model := range models {
			if model.Name == preferredModel {
				if err := m.validateConstraints(slot, model); err == nil {
					return provider, model, nil
				}
			}
		}
	}

	// Otherwise, find any model that meets constraints
	// Prefer models with higher capability (more features, larger context window)
	var bestModel *llm.ModelInfo
	for _, model := range models {
		if err := m.validateConstraints(slot, model); err == nil {
			if bestModel == nil || model.ContextWindow > bestModel.ContextWindow {
				modelCopy := model
				bestModel = &modelCopy
			}
		}
	}

	if bestModel != nil {
		return provider, *bestModel, nil
	}

	return nil, llm.ModelInfo{}, types.NewError(
		llm.ErrNoMatchingProvider,
		fmt.Sprintf("no matching model in provider %q", providerName),
	)
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

	// Check MinContextWindow constraint
	if constraints.MinContextWindow > 0 {
		if model.ContextWindow < constraints.MinContextWindow {
			return types.NewError(
				llm.ErrInvalidSlotConfig,
				fmt.Sprintf("model %q context window %d is less than required %d for slot %q",
					model.Name, model.ContextWindow, constraints.MinContextWindow, slot.Name),
			)
		}
	}

	// Check RequiredFeatures constraint
	if len(constraints.RequiredFeatures) > 0 {
		missingFeatures := []string{}
		for _, required := range constraints.RequiredFeatures {
			if !model.SupportsFeature(required) {
				missingFeatures = append(missingFeatures, required)
			}
		}

		if len(missingFeatures) > 0 {
			return types.NewError(
				llm.ErrInvalidSlotConfig,
				fmt.Sprintf("model %q missing required features for slot %q: %v",
					model.Name, slot.Name, missingFeatures),
			)
		}
	}

	return nil
}
