package observability

import (
	"context"
	"fmt"
	"sync"

	"github.com/zero-day-ai/gibson/internal/llm"
	"github.com/zero-day-ai/gibson/internal/types"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// CostTracker tracks LLM costs across missions and agents.
// It provides cost calculation, aggregation, and threshold monitoring
// with integration to OpenTelemetry spans for cost tracking.
type CostTracker struct {
	tokenTracker llm.TokenTracker
	logger       *Logger
	thresholds   map[string]float64 // mission ID -> threshold in USD
	mu           sync.RWMutex
}

// NewCostTracker creates a new CostTracker with the given token tracker and logger.
// The token tracker is used to retrieve usage data for cost calculations.
//
// Parameters:
//   - tokenTracker: The token tracker to use for usage data
//   - logger: The logger for warning messages and events
//
// Returns:
//   - *CostTracker: A configured cost tracker ready for use
func NewCostTracker(tokenTracker llm.TokenTracker, logger *Logger) *CostTracker {
	return &CostTracker{
		tokenTracker: tokenTracker,
		logger:       logger,
		thresholds:   make(map[string]float64),
	}
}

// CalculateCost calculates the cost for a specific provider and model based on token usage.
// It uses the default pricing configuration from internal/llm/pricing.go.
//
// Parameters:
//   - provider: The LLM provider name (e.g., "anthropic", "openai", "google")
//   - model: The model name (e.g., "claude-3-opus", "gpt-4")
//   - inputTokens: Number of input tokens used
//   - outputTokens: Number of output tokens used
//
// Returns:
//   - float64: The total cost in USD
//
// Note: Returns 0.0 if pricing is not found for the provider/model combination.
// The pricing data is normalized before lookup for consistency.
func (c *CostTracker) CalculateCost(provider, model string, inputTokens, outputTokens int) float64 {
	// Get default pricing configuration
	pricing := llm.DefaultPricing()

	// Calculate cost using the pricing config
	usage := llm.TokenUsage{
		InputTokens:  inputTokens,
		OutputTokens: outputTokens,
	}

	cost, err := pricing.CalculateCost(provider, model, usage)
	if err != nil {
		// Pricing not found, return 0
		return 0.0
	}

	return cost
}

// RecordCostOnSpan adds the gibson.llm.cost attribute to an OpenTelemetry span.
// This enables cost tracking and analysis through distributed tracing.
//
// Parameters:
//   - span: The OpenTelemetry span to annotate with cost
//   - cost: The cost in USD to record
func (c *CostTracker) RecordCostOnSpan(span trace.Span, cost float64) {
	span.SetAttributes(attribute.Float64(GibsonLLMCost, cost))
}

// GetMissionCost retrieves the total cost for all operations in a mission.
// It aggregates costs from all agents and slots within the mission.
//
// Parameters:
//   - missionID: The unique identifier for the mission
//
// Returns:
//   - float64: The total cost in USD for the mission
//   - error: An error if the mission has no usage data
func (c *CostTracker) GetMissionCost(missionID string) (float64, error) {
	// Parse mission ID
	id, err := types.ParseID(missionID)
	if err != nil {
		return 0, types.NewError(
			types.CONFIG_VALIDATION_FAILED,
			fmt.Sprintf("invalid mission ID: %v", err),
		)
	}

	// Create mission-level scope
	scope := llm.UsageScope{
		MissionID: id,
	}

	// Get cost from token tracker
	cost, err := c.tokenTracker.GetCost(scope)
	if err != nil {
		return 0, err
	}

	return cost, nil
}

// GetAgentCost retrieves the total cost for a specific agent within a mission.
// It aggregates costs from all slots used by the agent.
//
// Parameters:
//   - missionID: The unique identifier for the mission
//   - agentName: The name of the agent
//
// Returns:
//   - float64: The total cost in USD for the agent
//   - error: An error if the agent has no usage data
func (c *CostTracker) GetAgentCost(missionID, agentName string) (float64, error) {
	// Parse mission ID
	id, err := types.ParseID(missionID)
	if err != nil {
		return 0, types.NewError(
			types.CONFIG_VALIDATION_FAILED,
			fmt.Sprintf("invalid mission ID: %v", err),
		)
	}

	// Create agent-level scope
	scope := llm.UsageScope{
		MissionID: id,
		AgentName: agentName,
	}

	// Get cost from token tracker
	cost, err := c.tokenTracker.GetCost(scope)
	if err != nil {
		return 0, err
	}

	return cost, nil
}

// SetThreshold sets a cost warning threshold for a mission.
// When the mission cost exceeds this threshold, warnings are logged
// and events are emitted.
//
// Parameters:
//   - missionID: The unique identifier for the mission
//   - thresholdUSD: The threshold cost in USD (must be > 0)
//
// Returns:
//   - error: An error if the mission ID is invalid or threshold is invalid
func (c *CostTracker) SetThreshold(missionID string, thresholdUSD float64) error {
	// Validate mission ID
	id, err := types.ParseID(missionID)
	if err != nil {
		return types.NewError(
			types.CONFIG_VALIDATION_FAILED,
			fmt.Sprintf("invalid mission ID: %v", err),
		)
	}

	// Validate threshold
	if thresholdUSD <= 0 {
		return types.NewError(
			types.CONFIG_VALIDATION_FAILED,
			fmt.Sprintf("threshold must be greater than 0, got: %.2f", thresholdUSD),
		)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.thresholds[id.String()] = thresholdUSD
	return nil
}

// CheckThreshold checks if the current mission cost exceeds the configured threshold.
// If the threshold is exceeded, it logs a warning and emits a metric event.
//
// Parameters:
//   - missionID: The unique identifier for the mission
//   - currentCost: The current cost in USD to check against threshold
//
// Returns:
//   - bool: true if the threshold is exceeded, false otherwise
//
// Note: Returns false if no threshold is set for the mission.
func (c *CostTracker) CheckThreshold(missionID string, currentCost float64) bool {
	c.mu.RLock()
	threshold, exists := c.thresholds[missionID]
	c.mu.RUnlock()

	// No threshold set, return false
	if !exists {
		return false
	}

	// Check if threshold exceeded
	if currentCost > threshold {
		// Log warning with context
		if c.logger != nil {
			ctx := context.Background()
			c.logger.Warn(ctx, "cost threshold exceeded",
				"mission_id", missionID,
				"current_cost", fmt.Sprintf("%.4f", currentCost),
				"threshold", fmt.Sprintf("%.4f", threshold),
				"overage", fmt.Sprintf("%.4f", currentCost-threshold),
				"overage_percent", fmt.Sprintf("%.1f%%", ((currentCost-threshold)/threshold)*100),
			)
		}
		return true
	}

	return false
}

// GetThreshold retrieves the cost threshold for a mission.
//
// Parameters:
//   - missionID: The unique identifier for the mission
//
// Returns:
//   - float64: The threshold in USD, or 0 if no threshold is set
//   - bool: true if a threshold exists, false otherwise
func (c *CostTracker) GetThreshold(missionID string) (float64, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	threshold, exists := c.thresholds[missionID]
	return threshold, exists
}

// RemoveThreshold removes the cost threshold for a mission.
//
// Parameters:
//   - missionID: The unique identifier for the mission
func (c *CostTracker) RemoveThreshold(missionID string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.thresholds, missionID)
}
