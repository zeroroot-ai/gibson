package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/zero-day-ai/gibson/internal/events"
	"github.com/zero-day-ai/gibson/internal/graphrag/graph"
	"github.com/zero-day-ai/gibson/internal/llm"
	"github.com/zero-day-ai/gibson/internal/types"
)

// ReflectionScope defines the scope of a reflection evaluation.
type ReflectionScope string

const (
	// ReflectionScopeMission evaluates the overall mission strategy
	ReflectionScopeMission ReflectionScope = "mission"

	// ReflectionScopeRecentDecisions evaluates recent orchestrator decisions
	ReflectionScopeRecentDecisions ReflectionScope = "recent_decisions"

	// ReflectionScopeSpecificNode evaluates a specific workflow node
	ReflectionScopeSpecificNode ReflectionScope = "specific_node"
)

// String returns the string representation of ReflectionScope.
func (s ReflectionScope) String() string {
	return string(s)
}

// IsValid checks if the reflection scope is valid.
func (s ReflectionScope) IsValid() bool {
	switch s {
	case ReflectionScopeMission, ReflectionScopeRecentDecisions, ReflectionScopeSpecificNode:
		return true
	default:
		return false
	}
}

// ReflectionResult contains the output of a reflection evaluation.
type ReflectionResult struct {
	// Assessment is the overall strategy evaluation
	Assessment string `json:"assessment"`

	// IssuesIdentified contains problems found in the current approach
	IssuesIdentified []string `json:"issues_identified"`

	// SuggestedChanges contains recommendations for improvement
	SuggestedChanges []string `json:"suggested_changes"`

	// ConfidenceInApproach indicates confidence in the current strategy (0.0-1.0)
	ConfidenceInApproach float64 `json:"confidence_in_approach"`

	// TokensUsed tracks the number of tokens consumed by this reflection
	TokensUsed int `json:"tokens_used"`
}

// Validate checks if the reflection result is valid.
func (r *ReflectionResult) Validate() error {
	if r.Assessment == "" {
		return fmt.Errorf("assessment is required")
	}

	if r.ConfidenceInApproach < 0.0 || r.ConfidenceInApproach > 1.0 {
		return fmt.Errorf("confidence must be between 0.0 and 1.0, got %f", r.ConfidenceInApproach)
	}

	if r.IssuesIdentified == nil {
		r.IssuesIdentified = []string{}
	}

	if r.SuggestedChanges == nil {
		r.SuggestedChanges = []string{}
	}

	return nil
}

// ReflectionInsight represents a stored reflection result in Neo4j.
type ReflectionInsight struct {
	// ID is the unique identifier for this insight
	ID string `json:"id"`

	// MissionID associates this insight with a mission
	MissionID string `json:"mission_id"`

	// CreatedAt is when this reflection was performed
	CreatedAt time.Time `json:"created_at"`

	// Scope is the reflection scope that was used
	Scope ReflectionScope `json:"scope"`

	// Assessment is the overall strategy evaluation
	Assessment string `json:"assessment"`

	// Issues contains identified problems
	Issues []string `json:"issues"`

	// Suggestions contains recommendations
	Suggestions []string `json:"suggestions"`

	// Confidence is the confidence in the current approach
	Confidence float64 `json:"confidence"`

	// TokensUsed tracks token consumption
	TokensUsed int `json:"tokens_used"`
}

// ReflectionEngine defines the interface for self-evaluation operations.
type ReflectionEngine interface {
	// Reflect performs a reflection evaluation and returns structured insights.
	// The scope determines what is being evaluated (mission, recent decisions, specific node).
	// The prompt provides guidance for the evaluation.
	// The state contains the current observation state for context.
	Reflect(ctx context.Context, scope ReflectionScope, prompt string, state *ObservationState) (*ReflectionResult, error)

	// GetRecentInsights retrieves stored insights for inclusion in observations.
	// This enables the orchestrator to learn from past reflections.
	GetRecentInsights(ctx context.Context, missionID string, limit int) ([]ReflectionInsight, error)
}

// LLMReflectionEngine implements ReflectionEngine using LLM completions.
type LLMReflectionEngine struct {
	llmClient   LLMClient
	graphClient graph.GraphClient
	eventBus    EventBus
	slotName    string
	temperature float64
}

// ReflectionEngineOption is a functional option for configuring LLMReflectionEngine.
type ReflectionEngineOption func(*LLMReflectionEngine)

// WithReflectionSlot sets the LLM slot to use for reflection calls.
func WithReflectionSlot(slotName string) ReflectionEngineOption {
	return func(e *LLMReflectionEngine) {
		e.slotName = slotName
	}
}

// WithReflectionTemperature sets the temperature for reflection LLM calls.
func WithReflectionTemperature(temp float64) ReflectionEngineOption {
	return func(e *LLMReflectionEngine) {
		if temp >= 0.0 && temp <= 1.0 {
			e.temperature = temp
		}
	}
}

// NewLLMReflectionEngine creates a new LLMReflectionEngine.
//
// Parameters:
//   - llmClient: Client for making LLM completion requests
//   - graphClient: Client for storing reflection insights in Neo4j
//   - eventBus: Event bus for emitting reflection events
//   - options: Optional configuration
//
// Returns a configured LLMReflectionEngine ready to perform reflections.
func NewLLMReflectionEngine(
	llmClient LLMClient,
	graphClient graph.GraphClient,
	eventBus EventBus,
	options ...ReflectionEngineOption,
) *LLMReflectionEngine {
	engine := &LLMReflectionEngine{
		llmClient:   llmClient,
		graphClient: graphClient,
		eventBus:    eventBus,
		slotName:    "primary", // Default to primary slot
		temperature: 0.3,       // Slightly higher than orchestrator for creative evaluation
	}

	for _, opt := range options {
		opt(engine)
	}

	return engine
}

// Reflect performs a reflection evaluation using an LLM call.
func (e *LLMReflectionEngine) Reflect(ctx context.Context, scope ReflectionScope, prompt string, state *ObservationState) (*ReflectionResult, error) {
	if state == nil {
		return nil, fmt.Errorf("observation state is nil")
	}

	if !scope.IsValid() {
		return nil, fmt.Errorf("invalid reflection scope: %s", scope)
	}

	// Emit reflection started event
	if e.eventBus != nil {
		e.eventBus.Publish(events.Event{
			Type:      events.EventReflectionStarted,
			Timestamp: time.Now(),
			MissionID: types.ID(state.MissionInfo.ID),
			Payload: map[string]any{
				"scope":       scope.String(),
				"has_prompt":  prompt != "",
				"total_nodes": state.GraphSummary.TotalNodes,
			},
		})
	}

	startTime := time.Now()

	// Build reflection messages
	systemPrompt := buildReflectionSystemPrompt()
	userPrompt := buildReflectionUserPrompt(scope, prompt, state)

	messages := []llm.Message{
		llm.NewSystemMessage(systemPrompt),
		llm.NewUserMessage(userPrompt),
	}

	// Prepare options for LLM call
	opts := []CompletionOption{
		WithTemperature(e.temperature),
		WithMaxTokens(2000), // Sufficient for reflection analysis
	}

	// Try structured output first
	result, err := e.tryStructuredReflection(ctx, messages, opts)
	if err != nil {
		// Fall back to text parsing
		result, err = e.tryTextReflection(ctx, messages, opts)
		if err != nil {
			// Emit failure event
			if e.eventBus != nil {
				e.eventBus.Publish(events.Event{
					Type:      events.EventReflectionCompleted,
					Timestamp: time.Now(),
					MissionID: types.ID(state.MissionInfo.ID),
					Payload: map[string]any{
						"scope":    scope.String(),
						"success":  false,
						"error":    err.Error(),
						"duration": time.Since(startTime).String(),
					},
				})
			}
			return nil, fmt.Errorf("reflection failed: %w", err)
		}
	}

	// Validate the result
	if err := result.Validate(); err != nil {
		return nil, fmt.Errorf("invalid reflection result: %w", err)
	}

	// Store the insight in Neo4j
	insight := &ReflectionInsight{
		ID:          uuid.New().String(),
		MissionID:   state.MissionInfo.ID,
		CreatedAt:   time.Now(),
		Scope:       scope,
		Assessment:  result.Assessment,
		Issues:      result.IssuesIdentified,
		Suggestions: result.SuggestedChanges,
		Confidence:  result.ConfidenceInApproach,
		TokensUsed:  result.TokensUsed,
	}

	if err := e.storeInsight(ctx, insight); err != nil {
		// Log warning but don't fail - the reflection result is still valid
		// We just won't have it stored for future reference
		fmt.Printf("Warning: failed to store reflection insight: %v\n", err)
	}

	// Emit completion event
	if e.eventBus != nil {
		e.eventBus.Publish(events.Event{
			Type:      events.EventReflectionCompleted,
			Timestamp: time.Now(),
			MissionID: types.ID(state.MissionInfo.ID),
			Payload: map[string]any{
				"scope":           scope.String(),
				"success":         true,
				"issues_count":    len(result.IssuesIdentified),
				"suggestions_count": len(result.SuggestedChanges),
				"confidence":      result.ConfidenceInApproach,
				"tokens_used":     result.TokensUsed,
				"duration":        time.Since(startTime).String(),
			},
		})
	}

	return result, nil
}

// tryStructuredReflection attempts to use provider-native structured output.
func (e *LLMReflectionEngine) tryStructuredReflection(ctx context.Context, messages []llm.Message, opts []CompletionOption) (*ReflectionResult, error) {
	// Use CompleteStructuredAnyWithUsage to get guaranteed structured output AND token usage
	response, err := e.llmClient.CompleteStructuredAnyWithUsage(ctx, e.slotName, messages, ReflectionResult{}, opts...)
	if err != nil {
		return nil, fmt.Errorf("structured reflection failed: %w", err)
	}

	// Extract the result
	var result *ReflectionResult
	switch v := response.Result.(type) {
	case *ReflectionResult:
		result = v
	case ReflectionResult:
		result = &v
	default:
		return nil, fmt.Errorf("unexpected structured output type: %T", response.Result)
	}

	// Set token usage
	result.TokensUsed = response.TotalTokens

	return result, nil
}

// tryTextReflection attempts traditional text completion with JSON parsing.
func (e *LLMReflectionEngine) tryTextReflection(ctx context.Context, messages []llm.Message, opts []CompletionOption) (*ReflectionResult, error) {
	// Call LLM
	response, err := e.llmClient.Complete(ctx, e.slotName, messages, opts...)
	if err != nil {
		return nil, fmt.Errorf("LLM completion failed: %w", err)
	}

	// Parse response as JSON
	var result ReflectionResult
	if err := json.Unmarshal([]byte(response.Message.Content), &result); err != nil {
		return nil, fmt.Errorf("failed to parse reflection response: %w", err)
	}

	// Set token usage
	result.TokensUsed = response.Usage.TotalTokens

	return &result, nil
}

// storeInsight stores a reflection insight in Neo4j.
func (e *LLMReflectionEngine) storeInsight(ctx context.Context, insight *ReflectionInsight) error {
	if e.graphClient == nil {
		return fmt.Errorf("graph client is nil")
	}

	// Serialize arrays to JSON
	issuesJSON, err := json.Marshal(insight.Issues)
	if err != nil {
		return fmt.Errorf("failed to marshal issues: %w", err)
	}

	suggestionsJSON, err := json.Marshal(insight.Suggestions)
	if err != nil {
		return fmt.Errorf("failed to marshal suggestions: %w", err)
	}

	// Create the ReflectionInsight node
	cypher := `
		MATCH (m:Mission {id: $mission_id})
		CREATE (r:ReflectionInsight {
			id: $id,
			mission_id: $mission_id,
			created_at: datetime($created_at),
			scope: $scope,
			assessment: $assessment,
			issues_json: $issues_json,
			suggestions_json: $suggestions_json,
			confidence: $confidence,
			tokens_used: $tokens_used
		})
		CREATE (r)-[:PART_OF]->(m)
		RETURN r.id
	`

	params := map[string]any{
		"id":               insight.ID,
		"mission_id":       insight.MissionID,
		"created_at":       insight.CreatedAt.Format(time.RFC3339),
		"scope":            insight.Scope.String(),
		"assessment":       insight.Assessment,
		"issues_json":      string(issuesJSON),
		"suggestions_json": string(suggestionsJSON),
		"confidence":       insight.Confidence,
		"tokens_used":      insight.TokensUsed,
	}

	_, err = e.graphClient.Query(ctx, cypher, params)
	if err != nil {
		return fmt.Errorf("failed to create reflection insight node: %w", err)
	}

	return nil
}

// GetRecentInsights retrieves stored reflection insights from Neo4j.
func (e *LLMReflectionEngine) GetRecentInsights(ctx context.Context, missionID string, limit int) ([]ReflectionInsight, error) {
	if e.graphClient == nil {
		return nil, fmt.Errorf("graph client is nil")
	}

	if limit <= 0 {
		limit = 5 // Default limit
	}

	cypher := `
		MATCH (r:ReflectionInsight)-[:PART_OF]->(m:Mission {id: $mission_id})
		RETURN r.id AS id,
		       r.mission_id AS mission_id,
		       r.created_at AS created_at,
		       r.scope AS scope,
		       r.assessment AS assessment,
		       r.issues_json AS issues_json,
		       r.suggestions_json AS suggestions_json,
		       r.confidence AS confidence,
		       r.tokens_used AS tokens_used
		ORDER BY r.created_at DESC
		LIMIT $limit
	`

	params := map[string]any{
		"mission_id": missionID,
		"limit":      limit,
	}

	result, err := e.graphClient.Query(ctx, cypher, params)
	if err != nil {
		return nil, fmt.Errorf("failed to query reflection insights: %w", err)
	}

	insights := make([]ReflectionInsight, 0, len(result.Records))
	for _, record := range result.Records {
		insight := ReflectionInsight{
			ID:        record["id"].(string),
			MissionID: record["mission_id"].(string),
			Scope:     ReflectionScope(record["scope"].(string)),
		}

		// Parse created_at
		if createdAtStr, ok := record["created_at"].(string); ok {
			createdAt, err := time.Parse(time.RFC3339, createdAtStr)
			if err == nil {
				insight.CreatedAt = createdAt
			}
		}

		// Parse assessment
		if assessment, ok := record["assessment"].(string); ok {
			insight.Assessment = assessment
		}

		// Parse confidence
		if confidence, ok := record["confidence"].(float64); ok {
			insight.Confidence = confidence
		}

		// Parse tokens_used
		if tokensUsed, ok := record["tokens_used"].(int64); ok {
			insight.TokensUsed = int(tokensUsed)
		} else if tokensUsed, ok := record["tokens_used"].(int); ok {
			insight.TokensUsed = tokensUsed
		}

		// Parse issues JSON
		if issuesJSON, ok := record["issues_json"].(string); ok && issuesJSON != "" {
			var issues []string
			if err := json.Unmarshal([]byte(issuesJSON), &issues); err == nil {
				insight.Issues = issues
			}
		}
		if insight.Issues == nil {
			insight.Issues = []string{}
		}

		// Parse suggestions JSON
		if suggestionsJSON, ok := record["suggestions_json"].(string); ok && suggestionsJSON != "" {
			var suggestions []string
			if err := json.Unmarshal([]byte(suggestionsJSON), &suggestions); err == nil {
				insight.Suggestions = suggestions
			}
		}
		if insight.Suggestions == nil {
			insight.Suggestions = []string{}
		}

		insights = append(insights, insight)
	}

	return insights, nil
}

// buildReflectionSystemPrompt creates the system prompt for reflection calls.
func buildReflectionSystemPrompt() string {
	return `You are Gibson's Strategic Evaluator, responsible for self-reflection on mission orchestration decisions.

Your role is to critically assess the current approach, identify potential problems, and suggest improvements. You have complete visibility into the mission state, workflow progress, and recent decisions.

## Evaluation Criteria

When reflecting, consider:
1. **Strategy Effectiveness**: Is the current approach likely to achieve mission objectives?
2. **Resource Efficiency**: Are we using agents and tools efficiently?
3. **Error Patterns**: Are there repeating failures that suggest a systemic issue?
4. **Dependency Bottlenecks**: Are nodes blocked unnecessarily?
5. **Risk Management**: Are we taking appropriate safety precautions?

## Response Format

You must respond with a JSON object matching this exact structure:

{
  "assessment": "Overall evaluation of the current strategy (2-3 sentences)",
  "issues_identified": [
    "Specific problem 1",
    "Specific problem 2"
  ],
  "suggested_changes": [
    "Concrete recommendation 1",
    "Concrete recommendation 2"
  ],
  "confidence_in_approach": 0.75  // Float between 0.0 and 1.0
}

## Guidelines

- **Be specific**: Identify concrete issues, not vague concerns
- **Be actionable**: Suggest changes that can be implemented
- **Be honest**: Low confidence scores are valuable feedback
- **Consider context**: Failed nodes may be expected (e.g., testing defenses)
- **Focus on patterns**: Single failures are less concerning than repeated issues

## Example

If you see multiple failed reconnaissance nodes with timeout errors:

{
  "assessment": "The current reconnaissance strategy appears to be timing out consistently, suggesting targets may have rate limiting or the scan is too aggressive. This is blocking progress on dependent exploitation nodes.",
  "issues_identified": [
    "3 consecutive nmap scans timed out after 5 minutes each",
    "No alternative reconnaissance methods attempted",
    "Dependent nodes are blocked waiting for scan results"
  ],
  "suggested_changes": [
    "Retry failed scans with more conservative timing (-T2 instead of -T4)",
    "Consider using alternative tools like masscan for faster initial discovery",
    "Execute non-dependent nodes in parallel to maintain progress"
  ],
  "confidence_in_approach": 0.4
}
`
}

// buildReflectionUserPrompt constructs the user prompt for reflection.
func buildReflectionUserPrompt(scope ReflectionScope, prompt string, state *ObservationState) string {
	var sb strings.Builder

	// Add scope-specific context
	sb.WriteString("## Reflection Scope\n\n")
	switch scope {
	case ReflectionScopeMission:
		sb.WriteString("Evaluate the **overall mission strategy** and progress.\n\n")
	case ReflectionScopeRecentDecisions:
		sb.WriteString("Evaluate the **recent orchestrator decisions** and their effectiveness.\n\n")
	case ReflectionScopeSpecificNode:
		sb.WriteString("Evaluate a **specific workflow node** and related decisions.\n\n")
	default:
		sb.WriteString("Evaluate the current approach.\n\n")
	}

	// Add custom reflection prompt if provided
	if prompt != "" {
		sb.WriteString("## Guidance\n\n")
		sb.WriteString(prompt)
		sb.WriteString("\n\n")
	}

	// Add formatted observation state
	sb.WriteString(state.FormatForPrompt())

	// Add reflection instruction
	sb.WriteString("\n## Your Task\n\n")
	sb.WriteString("Analyze the current state and provide a structured reflection in JSON format.\n")
	sb.WriteString("Be critical but constructive. Focus on actionable improvements.\n")

	return sb.String()
}
