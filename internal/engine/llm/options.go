package llm

// CompletionOption is a functional option for configuring completion requests.
// This pattern allows for flexible, readable configuration of LLM requests.
type CompletionOption func(*CompletionRequest)

// WithTemperature sets the temperature for the completion request.
// Temperature controls randomness in the output (0.0 - 1.0).
// Lower values (e.g., 0.2) make output more focused and deterministic.
// Higher values (e.g., 0.8) make output more creative and varied.
func WithTemperature(temperature float64) CompletionOption {
	return func(req *CompletionRequest) {
		req.Temperature = temperature
	}
}

// WithMaxTokens sets the maximum number of tokens to generate.
// This limits the length of the LLM's response.
func WithMaxTokens(maxTokens int) CompletionOption {
	return func(req *CompletionRequest) {
		req.MaxTokens = maxTokens
	}
}

// WithTopP sets the nucleus sampling parameter (0.0 - 1.0).
// TopP controls the cumulative probability of token selection.
// For example, 0.9 means only tokens comprising the top 90% probability mass are considered.
func WithTopP(topP float64) CompletionOption {
	return func(req *CompletionRequest) {
		req.TopP = topP
	}
}

// WithStopSequences sets sequences that will stop generation when encountered.
// When the LLM generates any of these sequences, generation stops immediately.
func WithStopSequences(sequences ...string) CompletionOption {
	return func(req *CompletionRequest) {
		req.StopSequences = sequences
	}
}

// WithSystemPrompt sets a system prompt for the completion request.
// System prompts provide high-level instructions and context to the LLM.
// Some providers handle system prompts differently than system messages in the conversation.
func WithSystemPrompt(prompt string) CompletionOption {
	return func(req *CompletionRequest) {
		req.SystemPrompt = prompt
	}
}

// WithStream enables or disables streaming mode.
// When enabled, the LLM will stream responses as they're generated.
func WithStream(stream bool) CompletionOption {
	return func(req *CompletionRequest) {
		req.Stream = stream
	}
}

// WithMetadataOption adds metadata to the completion request.
// This is useful for tracking requests or passing provider-specific options.
func WithMetadataOption(key string, value any) CompletionOption {
	return func(req *CompletionRequest) {
		if req.Metadata == nil {
			req.Metadata = make(map[string]any)
		}
		req.Metadata[key] = value
	}
}

// ApplyOptions applies a list of options to a completion request.
// This is a helper function for implementing providers.
func ApplyOptions(req *CompletionRequest, opts ...CompletionOption) {
	for _, opt := range opts {
		opt(req)
	}
}

// NewCompletionRequest creates a new completion request with the given model and messages.
// Additional options can be applied using the functional options pattern.
//
// Example:
//
//	req := NewCompletionRequest("claude-3-opus-20240229",
//	    []Message{NewUserMessage("Hello, world!")},
//	    WithTemperature(0.7),
//	    WithMaxTokens(1000),
//	)
func NewCompletionRequest(model string, messages []Message, opts ...CompletionOption) CompletionRequest {
	req := CompletionRequest{
		Model:    model,
		Messages: messages,
	}

	ApplyOptions(&req, opts...)
	return req
}
