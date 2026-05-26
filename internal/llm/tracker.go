package llm

import (
	"fmt"
	"log/slog"
	"sync"

	"github.com/zeroroot-ai/gibson/internal/types"
)

// UsageScope defines the scope for tracking token usage.
// It provides hierarchical tracking at mission, agent, and slot levels.
type UsageScope struct {
	MissionID types.ID // Mission identifier
	AgentName string   // Agent name
	SlotName  string   // Slot name (optional, for slot-level tracking)
}

// String returns a string representation of the scope for debugging
func (s UsageScope) String() string {
	if s.SlotName != "" {
		return fmt.Sprintf("mission:%s/agent:%s/slot:%s", s.MissionID, s.AgentName, s.SlotName)
	}
	if s.AgentName != "" {
		return fmt.Sprintf("mission:%s/agent:%s", s.MissionID, s.AgentName)
	}
	return fmt.Sprintf("mission:%s", s.MissionID)
}

// Key returns a unique key for this scope for map lookups
func (s UsageScope) Key() string {
	return s.String()
}

// UsageRecord tracks token usage and associated costs for a specific scope
type UsageRecord struct {
	Scope        UsageScope // The scope of this usage record
	InputTokens  int        // Total input tokens used
	OutputTokens int        // Total output tokens used
	TotalCost    float64    // Total cost in USD
	CallCount    int        // Number of API calls made
}

// Budget defines spending limits for token usage
type Budget struct {
	MaxCost         float64 // Maximum cost in USD (0 = unlimited)
	MaxInputTokens  int     // Maximum input tokens (0 = unlimited)
	MaxOutputTokens int     // Maximum output tokens (0 = unlimited)
	MaxTotalTokens  int     // Maximum total tokens (0 = unlimited)
}

// TokenTracker tracks token usage and costs across missions, agents, and slots.
// It provides budget management and cost calculation based on provider pricing.
type TokenTracker interface {
	// RecordUsage records token usage for a specific scope
	RecordUsage(scope UsageScope, provider string, model string, usage TokenUsage) error

	// GetUsage retrieves usage statistics for a specific scope
	GetUsage(scope UsageScope) (UsageRecord, error)

	// GetCost retrieves the total cost for a specific scope
	GetCost(scope UsageScope) (float64, error)

	// SetBudget sets a budget limit for a specific scope
	SetBudget(scope UsageScope, budget Budget) error

	// CheckBudget checks if a proposed usage would exceed the budget
	// Returns ErrBudgetExceeded if the proposed usage would exceed limits
	CheckBudget(scope UsageScope, provider string, model string, usage TokenUsage) error

	// GetBudget retrieves the budget for a specific scope
	GetBudget(scope UsageScope) (Budget, error)

	// Reset clears usage data for a specific scope
	Reset(scope UsageScope) error
}

// DefaultTokenTracker implements TokenTracker with thread-safe operations.
type DefaultTokenTracker struct {
	mu      sync.RWMutex
	usage   map[string]*UsageRecord // Keyed by scope.Key()
	budgets map[string]Budget       // Keyed by scope.Key()
	pricing *PricingConfig          // Pricing configuration for cost calculation
}

// NewTokenTracker creates a new DefaultTokenTracker with the given pricing configuration.
// If pricing is nil, DefaultPricing() is used.
func NewTokenTracker(pricing *PricingConfig) *DefaultTokenTracker {
	if pricing == nil {
		pricing = DefaultPricing()
	}

	return &DefaultTokenTracker{
		usage:   make(map[string]*UsageRecord),
		budgets: make(map[string]Budget),
		pricing: pricing,
	}
}

// RecordUsage records token usage for a specific scope and calculates the cost.
// It automatically aggregates usage at all hierarchical levels (mission, agent, slot).
func (t *DefaultTokenTracker) RecordUsage(scope UsageScope, provider string, model string, usage TokenUsage) error {
	// Calculate cost for this usage.
	//
	// Three cases produce a zero-cost record:
	//   1. SelfHosted pricing (ollama/llamafile/local) — expected, silent.
	//   2. Unknown pricing flag (e.g. WatsonX custom deployments) — WARN so
	//      operators notice and patch the pricing table.
	//   3. No pricing entry at all — WARN so operators can add one.
	//
	// We check the pricing entry explicitly (not just the cost) so case 1 is
	// distinguishable from cases 2 and 3.
	pricing := t.pricing.GetModelPricing(provider, model)
	var cost float64
	switch {
	case pricing == nil:
		slog.Warn("no pricing entry for LLM usage; recording zero cost",
			"provider", provider, "model", model,
			"input_tokens", usage.InputTokens, "output_tokens", usage.OutputTokens)
		cost = 0
	case pricing.Unknown:
		slog.Warn("unknown model pricing, cost not tracked",
			"provider", provider, "model", model,
			"input_tokens", usage.InputTokens, "output_tokens", usage.OutputTokens)
		cost = 0
	case pricing.SelfHosted:
		cost = 0
	default:
		cost = pricing.CalculateCost(usage)
	}
	_ = pricing // keep for future diagnostics

	t.mu.Lock()
	defer t.mu.Unlock()

	// Record usage at the specific scope level
	key := scope.Key()
	record, exists := t.usage[key]
	if !exists {
		record = &UsageRecord{
			Scope: scope,
		}
		t.usage[key] = record
	}

	record.InputTokens += usage.InputTokens
	record.OutputTokens += usage.OutputTokens
	record.TotalCost += cost
	record.CallCount++

	// Also aggregate at parent scopes for hierarchical tracking
	t.aggregateToParentScopes(scope, usage, cost)

	return nil
}

// aggregateToParentScopes aggregates usage to parent scope levels
func (t *DefaultTokenTracker) aggregateToParentScopes(scope UsageScope, usage TokenUsage, cost float64) {
	// If this is a slot-level scope, aggregate to agent level
	if scope.SlotName != "" {
		agentScope := UsageScope{
			MissionID: scope.MissionID,
			AgentName: scope.AgentName,
		}
		t.aggregateToScope(agentScope, usage, cost)
	}

	// If this is an agent-level scope (or we just aggregated to it), aggregate to mission level
	if scope.AgentName != "" {
		missionScope := UsageScope{
			MissionID: scope.MissionID,
		}
		t.aggregateToScope(missionScope, usage, cost)
	}
}

// aggregateToScope adds usage to a specific scope's record
func (t *DefaultTokenTracker) aggregateToScope(scope UsageScope, usage TokenUsage, cost float64) {
	key := scope.Key()
	record, exists := t.usage[key]
	if !exists {
		record = &UsageRecord{
			Scope: scope,
		}
		t.usage[key] = record
	}

	record.InputTokens += usage.InputTokens
	record.OutputTokens += usage.OutputTokens
	record.TotalCost += cost
	record.CallCount++
}

// GetUsage retrieves usage statistics for a specific scope.
// Returns ErrUsageNotFound if no usage has been recorded for this scope.
func (t *DefaultTokenTracker) GetUsage(scope UsageScope) (UsageRecord, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	key := scope.Key()
	record, exists := t.usage[key]
	if !exists {
		return UsageRecord{}, types.NewError(
			ErrUsageNotFound,
			fmt.Sprintf("no usage found for scope %s", scope.String()),
		)
	}

	// Return a copy to prevent external modification
	return *record, nil
}

// GetCost retrieves the total cost for a specific scope.
// Returns ErrUsageNotFound if no usage has been recorded for this scope.
func (t *DefaultTokenTracker) GetCost(scope UsageScope) (float64, error) {
	record, err := t.GetUsage(scope)
	if err != nil {
		return 0, err
	}
	return record.TotalCost, nil
}

// SetBudget sets a budget limit for a specific scope.
func (t *DefaultTokenTracker) SetBudget(scope UsageScope, budget Budget) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	key := scope.Key()
	t.budgets[key] = budget

	return nil
}

// GetBudget retrieves the budget for a specific scope.
// Returns a zero budget if no budget has been set.
func (t *DefaultTokenTracker) GetBudget(scope UsageScope) (Budget, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	key := scope.Key()
	budget, exists := t.budgets[key]
	if !exists {
		// Return unlimited budget (all zeros)
		return Budget{}, nil
	}

	return budget, nil
}

// CheckBudget checks if a proposed usage would exceed the budget.
// Returns ErrBudgetExceeded if the proposed usage would exceed any limits.
// This should be called BEFORE making an API call to prevent overspending.
func (t *DefaultTokenTracker) CheckBudget(scope UsageScope, provider string, model string, usage TokenUsage) error {
	t.mu.RLock()
	defer t.mu.RUnlock()

	// Get the budget for this scope
	key := scope.Key()
	budget, exists := t.budgets[key]
	if !exists {
		// No budget set, unlimited
		return nil
	}

	// Get current usage
	currentRecord, exists := t.usage[key]
	var currentUsage UsageRecord
	if exists {
		currentUsage = *currentRecord
	}

	// Calculate cost for proposed usage
	proposedCost, err := t.pricing.CalculateCost(provider, model, usage)
	if err != nil {
		// If pricing not found, assume cost is 0 for budget checking
		proposedCost = 0
	}

	// Check cost limit
	if budget.MaxCost > 0 {
		newCost := currentUsage.TotalCost + proposedCost
		if newCost > budget.MaxCost {
			return types.NewError(
				ErrBudgetExceeded,
				fmt.Sprintf("cost budget exceeded: current=%.4f, proposed=%.4f, limit=%.4f, scope=%s",
					currentUsage.TotalCost, proposedCost, budget.MaxCost, scope.String()),
			)
		}
	}

	// Check input token limit
	if budget.MaxInputTokens > 0 {
		newInputTokens := currentUsage.InputTokens + usage.InputTokens
		if newInputTokens > budget.MaxInputTokens {
			return types.NewError(
				ErrBudgetExceeded,
				fmt.Sprintf("input token budget exceeded: current=%d, proposed=%d, limit=%d, scope=%s",
					currentUsage.InputTokens, usage.InputTokens, budget.MaxInputTokens, scope.String()),
			)
		}
	}

	// Check output token limit
	if budget.MaxOutputTokens > 0 {
		newOutputTokens := currentUsage.OutputTokens + usage.OutputTokens
		if newOutputTokens > budget.MaxOutputTokens {
			return types.NewError(
				ErrBudgetExceeded,
				fmt.Sprintf("output token budget exceeded: current=%d, proposed=%d, limit=%d, scope=%s",
					currentUsage.OutputTokens, usage.OutputTokens, budget.MaxOutputTokens, scope.String()),
			)
		}
	}

	// Check total token limit
	if budget.MaxTotalTokens > 0 {
		currentTotal := currentUsage.InputTokens + currentUsage.OutputTokens
		proposedTotal := usage.InputTokens + usage.OutputTokens
		newTotal := currentTotal + proposedTotal
		if newTotal > budget.MaxTotalTokens {
			return types.NewError(
				ErrBudgetExceeded,
				fmt.Sprintf("total token budget exceeded: current=%d, proposed=%d, limit=%d, scope=%s",
					currentTotal, proposedTotal, budget.MaxTotalTokens, scope.String()),
			)
		}
	}

	return nil
}

// Reset clears usage data for a specific scope.
// The budget for this scope is preserved.
func (t *DefaultTokenTracker) Reset(scope UsageScope) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	key := scope.Key()
	delete(t.usage, key)

	return nil
}
