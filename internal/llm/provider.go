package llm

import (
	"context"

	"github.com/zeroroot-ai/gibson/internal/types"
)

// LLMProvider defines the interface that all LLM providers must implement.
// It provides a unified abstraction for interacting with different LLM services
// (Anthropic Claude, OpenAI GPT, local models, etc.).
type LLMProvider interface {
	// Name returns the provider name (e.g., "anthropic", "openai", "local")
	Name() string

	// Models returns information about all available models for this provider
	Models(ctx context.Context) ([]ModelInfo, error)

	// Complete sends a completion request and returns the full response.
	// This is a blocking call that waits for the entire response.
	Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error)

	// CompleteWithTools sends a completion request with tool definitions.
	// The LLM may choose to call one or more tools in its response.
	CompleteWithTools(ctx context.Context, req CompletionRequest, tools []ToolDef) (*CompletionResponse, error)

	// Stream sends a completion request and streams the response as it's generated.
	// The returned channel will emit StreamChunk items until completion or error.
	// The channel will be closed when streaming is complete.
	Stream(ctx context.Context, req CompletionRequest) (<-chan StreamChunk, error)

	// Health checks the health status of the provider and its connectivity
	Health(ctx context.Context) types.HealthStatus
}

// ModelInfo contains metadata about an LLM model.
type ModelInfo struct {
	// Name is the model identifier (e.g., "claude-3-opus-20240229", "gpt-4")
	Name string `json:"name"`

	// ContextWindow is the maximum number of tokens the model can process
	ContextWindow int `json:"context_window"`

	// Features lists the capabilities this model supports
	Features []string `json:"features"`

	// MaxOutput is the maximum number of tokens the model can generate
	MaxOutput int `json:"max_output"`
}

// SupportsFeature checks if the model supports a given feature
func (m ModelInfo) SupportsFeature(feature string) bool {
	for _, f := range m.Features {
		if f == feature {
			return true
		}
	}
	return false
}

// SupportsToolUse checks if the model supports tool/function calling
func (m ModelInfo) SupportsToolUse() bool {
	return m.SupportsFeature("tool_use")
}

// SupportsVision checks if the model supports image understanding
func (m ModelInfo) SupportsVision() bool {
	return m.SupportsFeature("vision")
}

// SupportsStreaming checks if the model supports streaming responses
func (m ModelInfo) SupportsStreaming() bool {
	return m.SupportsFeature("streaming")
}

// SupportsJSONMode checks if the model supports structured JSON output
func (m ModelInfo) SupportsJSONMode() bool {
	return m.SupportsFeature("json_mode")
}

// StructuredOutputProvider is implemented by providers with native JSON mode support.
// Providers that support structured output should implement this interface in addition
// to the base LLMProvider interface. If a provider doesn't implement this interface,
// structured output requests will fail with ErrStructuredOutputNotSupported.
//
// Provider Implementation Notes:
//   - Anthropic: Uses tool_use pattern to enforce structured output (Requirement 2.1)
//   - OpenAI: Sets response_format parameter for native JSON mode (Requirement 2.2)
//   - Providers without support: Should NOT implement this interface (Requirement 2.3)
//
// The interface is optional - only providers with native structured output support
// should implement it. Attempting structured output on providers that don't implement
// this interface will result in an error at the SDK/manager level.
type StructuredOutputProvider interface {
	LLMProvider

	// SupportsStructuredOutput returns true if the provider supports the given format type.
	// Providers may support json_object but not json_schema, for example.
	//
	// Example:
	//   - A provider might return true for ResponseFormatJSONObject
	//   - But return false for ResponseFormatJSONSchema if strict schema validation isn't supported
	//
	// Parameters:
	//   - format: The response format type to check (json_object, json_schema, etc.)
	//
	// Returns:
	//   - true if the provider can handle completions with this format type
	//   - false otherwise
	SupportsStructuredOutput(format types.ResponseFormatType) bool

	// CompleteStructured performs a completion with structured output enforcement.
	// This method guarantees that the response will contain valid JSON conforming to
	// the requested format.
	//
	// The implementation varies by provider:
	//   - Anthropic: Converts schema to tool definition and uses tool_use
	//   - OpenAI: Sets response_format parameter in the API request
	//
	// Response Fields:
	//   - Message.Content: Contains the raw JSON string
	//   - For tool-based implementations: Uses ToolUse content blocks
	//
	// Error Conditions:
	//   - Returns error if the requested format is not supported (check SupportsStructuredOutput first)
	//   - Returns error if schema validation fails (when enabled in options)
	//   - Returns error on API failures or malformed responses
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeouts
	//   - req: Completion request with all standard parameters
	//
	// Returns:
	//   - CompletionResponse with structured JSON data
	//   - Error if structured output is not supported or request fails
	CompleteStructured(ctx context.Context, req CompletionRequest) (*CompletionResponse, error)
}
