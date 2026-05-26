package orchestrator

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/zeroroot-ai/gibson/internal/llm"
)

// LLMClient defines the interface for LLM operations required by the Thinker.
// This matches the SDK harness interface for LLM completions.
type LLMClient interface {
	// Complete performs a synchronous LLM completion using the specified slot.
	Complete(ctx context.Context, slot string, messages []llm.Message, opts ...CompletionOption) (*llm.CompletionResponse, error)

	// CompleteStructuredAny performs a completion with provider-native structured output.
	// The response is guaranteed to match the provided schema.
	CompleteStructuredAny(ctx context.Context, slot string, messages []llm.Message, schemaType any, opts ...CompletionOption) (any, error)

	// CompleteStructuredAnyWithUsage performs structured completion and returns token usage.
	// This is needed for orchestrator observability (Langfuse, token tracking, etc.)
	CompleteStructuredAnyWithUsage(ctx context.Context, slot string, messages []llm.Message, schemaType any, opts ...CompletionOption) (*StructuredCompletionResult, error)
}

// StructuredCompletionResult contains the result of a structured completion
// along with token usage information for observability and cost tracking.
type StructuredCompletionResult struct {
	// Result is the parsed structured output (pointer to the schema type)
	Result any

	// Model is the name of the model that was used
	Model string

	// RawJSON is the raw JSON response from the LLM
	RawJSON string

	// PromptTokens is the number of tokens in the prompt
	PromptTokens int

	// CompletionTokens is the number of tokens in the completion
	CompletionTokens int

	// TotalTokens is the total token usage (prompt + completion)
	TotalTokens int
}

// CompletionOption defines functional options for LLM completion requests.
// These match the harness.CompletionOption interface.
type CompletionOption func(*CompletionOptions)

// CompletionOptions contains all options that can be configured for an LLM completion.
type CompletionOptions struct {
	Temperature float64
	MaxTokens   int
	TopP        float64
}

// WithTemperature sets the temperature for completion (0.0-1.0).
func WithTemperature(temp float64) CompletionOption {
	return func(o *CompletionOptions) {
		o.Temperature = temp
	}
}

// WithMaxTokens sets the maximum tokens to generate.
func WithMaxTokens(tokens int) CompletionOption {
	return func(o *CompletionOptions) {
		o.MaxTokens = tokens
	}
}

// WithTopP sets the nucleus sampling parameter (0.0-1.0).
func WithTopP(topP float64) CompletionOption {
	return func(o *CompletionOptions) {
		o.TopP = topP
	}
}

// Note: ObservationState is defined in observe.go
// This file uses the existing ObservationState from the observe phase.

// RequestConfig contains LLM request configuration parameters for observability.
// This enables Langfuse to display the exact parameters used for each decision.
type RequestConfig struct {
	// Temperature controls randomness in the LLM output (0.0-1.0)
	Temperature float64 `json:"temperature"`

	// MaxTokens is the maximum number of tokens to generate
	MaxTokens int `json:"max_tokens"`

	// TopP controls nucleus sampling (0.0-1.0)
	TopP float64 `json:"top_p,omitempty"`

	// SlotName is the LLM slot used for this request
	SlotName string `json:"slot_name"`
}

// ThinkResult contains the complete result of a think operation.
type ThinkResult struct {
	// Decision is the orchestrator's decision about what to do next
	Decision *Decision

	// PromptTokens is the number of tokens used in the prompt
	PromptTokens int

	// CompletionTokens is the number of tokens used in the completion
	CompletionTokens int

	// TotalTokens is the total token usage
	TotalTokens int

	// Latency is how long the LLM call took
	Latency time.Duration

	// RawResponse contains the raw LLM response for logging/debugging
	RawResponse string

	// Model is the model used for this completion
	Model string

	// RetryCount is how many retries were needed
	RetryCount int

	// SystemPrompt is the full system prompt sent to the LLM
	// This is captured for observability and debugging purposes
	SystemPrompt string

	// UserPrompt is the full user message sent to the LLM
	// This includes the observation state and decision schema
	UserPrompt string

	// Messages is the complete message array sent to the LLM
	// This preserves the exact structure of the conversation
	Messages []llm.Message

	// RequestConfig contains the LLM parameters used for this request
	// This enables full observability of the decision-making process
	RequestConfig RequestConfig
}

// Thinker implements the orchestrator's think phase using an LLM.
// It takes the current observation state and produces a decision about what to do next.
type Thinker struct {
	llmClient   LLMClient
	slotName    string
	maxRetries  int
	model       string
	temperature float64
}

// ThinkerOption is a functional option for configuring the Thinker.
type ThinkerOption func(*Thinker)

// WithMaxRetries sets the maximum number of retry attempts for parse failures.
func WithMaxRetries(n int) ThinkerOption {
	return func(t *Thinker) {
		if n >= 0 {
			t.maxRetries = n
		}
	}
}

// WithModel sets the LLM model to use (if supported by slot config).
func WithModel(model string) ThinkerOption {
	return func(t *Thinker) {
		t.model = model
	}
}

// WithThinkerTemperature sets the temperature for LLM calls.
func WithThinkerTemperature(temp float64) ThinkerOption {
	return func(t *Thinker) {
		if temp >= 0.0 && temp <= 1.0 {
			t.temperature = temp
		}
	}
}

// NewThinker creates a new Thinker with the specified LLM client and options.
//
// Parameters:
//   - llmClient: Client for making LLM completion requests
//   - options: Optional configuration (max retries, model, temperature)
//
// Returns a configured Thinker ready to make orchestration decisions.
func NewThinker(llmClient LLMClient, options ...ThinkerOption) *Thinker {
	t := &Thinker{
		llmClient:   llmClient,
		slotName:    "primary", // Default slot
		maxRetries:  3,         // Default retry count
		temperature: 0.2,       // Low temperature for consistent reasoning
	}

	for _, opt := range options {
		opt(t)
	}

	return t
}

// Think analyzes the current observation state and produces a decision.
//
// The thinking process:
//  1. Build a comprehensive prompt with mission state, context, and constraints
//  2. Call the LLM with structured output schema for Decision
//  3. Parse the response into a Decision struct
//  4. Validate the decision is properly formed
//  5. Retry on parse failures (up to maxRetries)
//  6. Return the decision with full metadata
//
// Returns an error if:
//   - Context is cancelled
//   - LLM call fails after all retries
//   - Response cannot be parsed as valid Decision
//   - Decision validation fails
func (t *Thinker) Think(ctx context.Context, state *ObservationState) (*ThinkResult, error) {
	if state == nil {
		return nil, fmt.Errorf("observation state is nil")
	}

	startTime := time.Now()
	var lastErr error

	// Retry loop for handling parse failures
	for attempt := 0; attempt <= t.maxRetries; attempt++ {
		result, err := t.thinkAttempt(ctx, state, attempt)
		if err == nil {
			// Success - populate retry count and return
			result.RetryCount = attempt
			return result, nil
		}

		lastErr = err

		// Check if error is retryable (parse failures are, LLM errors might not be)
		if !isRetryableError(err) {
			return nil, fmt.Errorf("non-retryable error on attempt %d: %w", attempt+1, err)
		}

		// Check if we should retry
		if attempt < t.maxRetries {
			// Brief exponential backoff
			backoff := time.Duration(100*(1<<attempt)) * time.Millisecond
			select {
			case <-ctx.Done():
				return nil, fmt.Errorf("context cancelled during retry backoff: %w", ctx.Err())
			case <-time.After(backoff):
				// Continue to next attempt
			}
		}
	}

	// All retries exhausted
	elapsed := time.Since(startTime)
	return nil, fmt.Errorf("failed after %d attempts (took %s): %w", t.maxRetries+1, elapsed, lastErr)
}

// thinkAttempt performs a single think attempt.
func (t *Thinker) thinkAttempt(ctx context.Context, state *ObservationState, attemptNum int) (*ThinkResult, error) {
	startTime := time.Now()

	// Build prompts and store for observability
	systemPrompt := t.buildSystemPrompt()
	userPrompt, err := t.buildPrompt(state, attemptNum)
	if err != nil {
		return nil, fmt.Errorf("failed to build prompt: %w", err)
	}

	// Prepare messages
	messages := []llm.Message{
		llm.NewSystemMessage(systemPrompt),
		llm.NewUserMessage(userPrompt),
	}

	// Prepare options
	opts := []CompletionOption{
		WithTemperature(t.temperature),
		WithMaxTokens(2000), // Sufficient for decision + reasoning
	}

	// Try structured output first (preferred for reliability)
	decision, response, err := t.tryStructuredOutput(ctx, messages, opts)
	if err != nil {
		// Fall back to text parsing
		decision, response, err = t.tryTextOutput(ctx, messages, opts)
		if err != nil {
			return nil, fmt.Errorf("both structured and text output failed: %w", err)
		}
	}

	// Validate the decision
	if err := decision.Validate(); err != nil {
		return nil, &parseError{msg: fmt.Sprintf("invalid decision: %v", err)}
	}

	// Build result with full prompt capture for observability
	latency := time.Since(startTime)
	result := &ThinkResult{
		Decision:         decision,
		PromptTokens:     response.Usage.PromptTokens,
		CompletionTokens: response.Usage.CompletionTokens,
		TotalTokens:      response.Usage.TotalTokens,
		Latency:          latency,
		RawResponse:      response.Message.Content,
		Model:            response.Model,

		// Capture full prompts for observability
		SystemPrompt: systemPrompt,
		UserPrompt:   userPrompt,
		Messages:     append([]llm.Message{}, messages...), // Copy to prevent external mutations

		// Capture request configuration
		RequestConfig: RequestConfig{
			Temperature: t.temperature,
			MaxTokens:   2000,
			TopP:        0.0, // Not currently configurable, use zero value
			SlotName:    t.slotName,
		},
	}

	return result, nil
}

// tryStructuredOutput attempts to use provider-native structured output.
func (t *Thinker) tryStructuredOutput(ctx context.Context, messages []llm.Message, opts []CompletionOption) (*Decision, *llm.CompletionResponse, error) {
	// Use CompleteStructuredAnyWithUsage to get guaranteed structured output AND token usage
	result, err := t.llmClient.CompleteStructuredAnyWithUsage(ctx, t.slotName, messages, Decision{}, opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("structured completion failed: %w", err)
	}

	// Extract the decision from the result
	// The structured output should be a *Decision or Decision
	var decision *Decision
	switch v := result.Result.(type) {
	case *Decision:
		decision = v
	case Decision:
		decision = &v
	default:
		return nil, nil, fmt.Errorf("unexpected structured output type: %T", result.Result)
	}

	// Build response with actual token usage from the structured completion
	response := &llm.CompletionResponse{
		Model: result.Model,
		Message: llm.Message{
			Role:    llm.RoleAssistant,
			Content: result.RawJSON, // Use raw JSON as content for logging
		},
		Usage: llm.CompletionTokenUsage{
			PromptTokens:     result.PromptTokens,
			CompletionTokens: result.CompletionTokens,
			TotalTokens:      result.TotalTokens,
		},
	}

	return decision, response, nil
}

// tryTextOutput attempts traditional text completion with JSON parsing.
func (t *Thinker) tryTextOutput(ctx context.Context, messages []llm.Message, opts []CompletionOption) (*Decision, *llm.CompletionResponse, error) {
	// Call LLM
	response, err := t.llmClient.Complete(ctx, t.slotName, messages, opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("LLM completion failed: %w", err)
	}

	// Parse response as JSON
	decision, err := ParseDecision(response.Message.Content)
	if err != nil {
		return nil, response, &parseError{msg: fmt.Sprintf("failed to parse decision: %v", err)}
	}

	return decision, response, nil
}

// buildSystemPrompt creates the system message defining the orchestrator's role.
func (t *Thinker) buildSystemPrompt() string {
	// Use the centralized system prompt from prompts.go
	return SystemPrompt
}

// buildPrompt constructs the detailed prompt with mission state and context.
func (t *Thinker) buildPrompt(state *ObservationState, attemptNum int) (string, error) {
	var b strings.Builder

	// Use the centralized prompt builder from prompts.go
	// This provides formatted observation state
	b.WriteString(state.FormatForPrompt())

	// Add decision schema for clarity
	b.WriteString("\n## Required Response Format\n\n")
	b.WriteString("Respond with a JSON Decision object matching this structure:\n")
	b.WriteString(BuildDecisionSchema())
	b.WriteString("\n\n")

	// Add examples for guidance
	b.WriteString("## Example Decisions\n\n")
	b.WriteString("Execute agent example:\n```json\n")
	b.WriteString(FormatDecisionExample())
	b.WriteString("\n```\n\n")
	b.WriteString("Complete mission example:\n```json\n")
	b.WriteString(FormatCompleteExample())
	b.WriteString("\n```\n\n")

	// Add retry context if this is a retry
	if attemptNum > 0 {
		b.WriteString(fmt.Sprintf("\n**IMPORTANT**: This is retry attempt %d. ", attemptNum+1))
		b.WriteString("The previous response was invalid or could not be parsed. ")
		b.WriteString("Please ensure your response is valid JSON matching the schema exactly.\n")
	}

	return b.String(), nil
}

// parseError is a retryable error for parse failures.
type parseError struct {
	msg string
}

func (e *parseError) Error() string {
	return e.msg
}

// isRetryableError determines if an error should trigger a retry.
func isRetryableError(err error) bool {
	if err == nil {
		return false
	}

	// Parse errors are retryable (LLM might fix format on retry)
	var pErr *parseError
	if errors, ok := err.(*parseError); ok || (pErr != nil) {
		_ = errors
		return true
	}

	// Check for JSON parse errors (also retryable)
	if strings.Contains(err.Error(), "parse") ||
		strings.Contains(err.Error(), "unmarshal") ||
		strings.Contains(err.Error(), "invalid") {
		return true
	}

	// Other errors (LLM failures, context cancelled) are not retryable
	return false
}

// DecisionJSONSchema returns the JSON schema for Decision struct.
// This can be used for provider-native structured output.
func DecisionJSONSchema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"reasoning": map[string]interface{}{
				"type":        "string",
				"description": "Chain-of-thought explanation of why this decision was made",
			},
			"action": map[string]interface{}{
				"type":        "string",
				"enum":        []string{"execute_agent", "skip_agent", "modify_params", "retry", "spawn_agent", "complete"},
				"description": "The action the orchestrator should take",
			},
			"target_node_id": map[string]interface{}{
				"type":        "string",
				"description": "Which mission node to act on (required for most actions)",
			},
			"modifications": map[string]interface{}{
				"type":        "object",
				"description": "Parameter overrides for modify_params action",
			},
			"spawn_config": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"agent_name": map[string]interface{}{
						"type": "string",
					},
					"description": map[string]interface{}{
						"type": "string",
					},
					"task_config": map[string]interface{}{
						"type": "object",
					},
					"depends_on": map[string]interface{}{
						"type": "array",
						"items": map[string]interface{}{
							"type": "string",
						},
					},
				},
				"required": []string{"agent_name", "description", "task_config", "depends_on"},
			},
			"confidence": map[string]interface{}{
				"type":        "number",
				"minimum":     0.0,
				"maximum":     1.0,
				"description": "Confidence level between 0.0 and 1.0",
			},
			"stop_reason": map[string]interface{}{
				"type":        "string",
				"description": "Explanation for why mission is complete (required for complete action)",
			},
		},
		"required": []string{"reasoning", "action", "confidence"},
	}
}
