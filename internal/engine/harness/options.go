package harness

// CompletionOption is a functional option for configuring LLM completions.
// This pattern allows for flexible, readable configuration of agent completions.
type CompletionOption func(*completionOptions)

// completionOptions holds the configurable options for completions.
// All fields use pointers to distinguish between "not set" and "set to zero value".
type completionOptions struct {
	Temperature   *float64
	MaxTokens     *int
	StopSequences []string
	TopP          *float64
	SystemPrompt  *string
}

// WithTemperature sets the temperature for the completion.
// Temperature controls randomness in the output (0.0 - 1.0).
// Lower values (e.g., 0.2) make output more focused and deterministic.
// Higher values (e.g., 0.8) make output more creative and varied.
func WithTemperature(t float64) CompletionOption {
	return func(opts *completionOptions) {
		opts.Temperature = &t
	}
}

// WithMaxTokens sets the maximum tokens for the completion.
// This limits the length of the LLM's response.
func WithMaxTokens(n int) CompletionOption {
	return func(opts *completionOptions) {
		opts.MaxTokens = &n
	}
}

// WithStopSequences sets stop sequences for the completion.
// When the LLM generates any of these sequences, generation stops immediately.
func WithStopSequences(s ...string) CompletionOption {
	return func(opts *completionOptions) {
		opts.StopSequences = s
	}
}

// WithTopP sets the top_p (nucleus sampling) for the completion.
// TopP controls the cumulative probability of token selection (0.0 - 1.0).
// For example, 0.9 means only tokens comprising the top 90% probability mass are considered.
func WithTopP(p float64) CompletionOption {
	return func(opts *completionOptions) {
		opts.TopP = &p
	}
}

// WithSystemPrompt sets or overrides the system prompt.
// System prompts provide high-level instructions and context to the LLM.
func WithSystemPrompt(s string) CompletionOption {
	return func(opts *completionOptions) {
		opts.SystemPrompt = &s
	}
}

// newCompletionOptions creates default completion options.
// All fields are nil by default, indicating they haven't been set.
func newCompletionOptions() *completionOptions {
	return &completionOptions{}
}

// applyOptions applies all options and returns the resulting config.
// This is a helper function for implementing agent harness methods.
func applyOptions(opts ...CompletionOption) *completionOptions {
	config := newCompletionOptions()
	for _, opt := range opts {
		opt(config)
	}
	return config
}
