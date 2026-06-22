package harness

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestWithTemperature tests the WithTemperature option
func TestWithTemperature(t *testing.T) {
	tests := []struct {
		name     string
		value    float64
		expected float64
	}{
		{
			name:     "low temperature",
			value:    0.2,
			expected: 0.2,
		},
		{
			name:     "medium temperature",
			value:    0.7,
			expected: 0.7,
		},
		{
			name:     "high temperature",
			value:    0.9,
			expected: 0.9,
		},
		{
			name:     "zero temperature",
			value:    0.0,
			expected: 0.0,
		},
		{
			name:     "max temperature",
			value:    1.0,
			expected: 1.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := newCompletionOptions()
			opt := WithTemperature(tt.value)
			opt(opts)

			assert.NotNil(t, opts.Temperature)
			assert.Equal(t, tt.expected, *opts.Temperature)
		})
	}
}

// TestWithMaxTokens tests the WithMaxTokens option
func TestWithMaxTokens(t *testing.T) {
	tests := []struct {
		name     string
		value    int
		expected int
	}{
		{
			name:     "small limit",
			value:    100,
			expected: 100,
		},
		{
			name:     "medium limit",
			value:    1000,
			expected: 1000,
		},
		{
			name:     "large limit",
			value:    4000,
			expected: 4000,
		},
		{
			name:     "zero tokens",
			value:    0,
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := newCompletionOptions()
			opt := WithMaxTokens(tt.value)
			opt(opts)

			assert.NotNil(t, opts.MaxTokens)
			assert.Equal(t, tt.expected, *opts.MaxTokens)
		})
	}
}

// TestWithStopSequences tests the WithStopSequences option
func TestWithStopSequences(t *testing.T) {
	tests := []struct {
		name      string
		sequences []string
		expected  []string
	}{
		{
			name:      "single sequence",
			sequences: []string{"STOP"},
			expected:  []string{"STOP"},
		},
		{
			name:      "multiple sequences",
			sequences: []string{"STOP", "END", "DONE"},
			expected:  []string{"STOP", "END", "DONE"},
		},
		{
			name:      "empty sequences",
			sequences: []string{},
			expected:  []string{},
		},
		{
			name:      "sequences with special chars",
			sequences: []string{"\n\n", "###", "---"},
			expected:  []string{"\n\n", "###", "---"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := newCompletionOptions()
			opt := WithStopSequences(tt.sequences...)
			opt(opts)

			assert.Equal(t, tt.expected, opts.StopSequences)
		})
	}
}

// TestWithTopP tests the WithTopP option
func TestWithTopP(t *testing.T) {
	tests := []struct {
		name     string
		value    float64
		expected float64
	}{
		{
			name:     "low top_p",
			value:    0.1,
			expected: 0.1,
		},
		{
			name:     "medium top_p",
			value:    0.5,
			expected: 0.5,
		},
		{
			name:     "high top_p",
			value:    0.9,
			expected: 0.9,
		},
		{
			name:     "zero top_p",
			value:    0.0,
			expected: 0.0,
		},
		{
			name:     "max top_p",
			value:    1.0,
			expected: 1.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := newCompletionOptions()
			opt := WithTopP(tt.value)
			opt(opts)

			assert.NotNil(t, opts.TopP)
			assert.Equal(t, tt.expected, *opts.TopP)
		})
	}
}

// TestWithSystemPrompt tests the WithSystemPrompt option
func TestWithSystemPrompt(t *testing.T) {
	tests := []struct {
		name     string
		prompt   string
		expected string
	}{
		{
			name:     "simple prompt",
			prompt:   "You are a helpful assistant",
			expected: "You are a helpful assistant",
		},
		{
			name:     "complex prompt",
			prompt:   "You are a specialized agent that helps with code analysis. Be precise and thorough.",
			expected: "You are a specialized agent that helps with code analysis. Be precise and thorough.",
		},
		{
			name:     "empty prompt",
			prompt:   "",
			expected: "",
		},
		{
			name:     "multiline prompt",
			prompt:   "You are an agent.\nBe helpful.\nBe concise.",
			expected: "You are an agent.\nBe helpful.\nBe concise.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := newCompletionOptions()
			opt := WithSystemPrompt(tt.prompt)
			opt(opts)

			assert.NotNil(t, opts.SystemPrompt)
			assert.Equal(t, tt.expected, *opts.SystemPrompt)
		})
	}
}

// TestNewCompletionOptions tests the default options constructor
func TestNewCompletionOptions(t *testing.T) {
	opts := newCompletionOptions()

	assert.NotNil(t, opts)
	assert.Nil(t, opts.Temperature)
	assert.Nil(t, opts.MaxTokens)
	assert.Nil(t, opts.TopP)
	assert.Nil(t, opts.SystemPrompt)
	assert.Nil(t, opts.StopSequences)
}

// TestApplyOptions tests applying multiple options
func TestApplyOptions(t *testing.T) {
	tests := []struct {
		name     string
		opts     []CompletionOption
		validate func(t *testing.T, opts *completionOptions)
	}{
		{
			name: "single option",
			opts: []CompletionOption{
				WithTemperature(0.7),
			},
			validate: func(t *testing.T, opts *completionOptions) {
				assert.NotNil(t, opts.Temperature)
				assert.Equal(t, 0.7, *opts.Temperature)
				assert.Nil(t, opts.MaxTokens)
				assert.Nil(t, opts.TopP)
				assert.Nil(t, opts.SystemPrompt)
			},
		},
		{
			name: "multiple options",
			opts: []CompletionOption{
				WithTemperature(0.8),
				WithMaxTokens(1000),
				WithTopP(0.9),
			},
			validate: func(t *testing.T, opts *completionOptions) {
				assert.NotNil(t, opts.Temperature)
				assert.Equal(t, 0.8, *opts.Temperature)
				assert.NotNil(t, opts.MaxTokens)
				assert.Equal(t, 1000, *opts.MaxTokens)
				assert.NotNil(t, opts.TopP)
				assert.Equal(t, 0.9, *opts.TopP)
			},
		},
		{
			name: "all options",
			opts: []CompletionOption{
				WithTemperature(0.5),
				WithMaxTokens(500),
				WithTopP(0.85),
				WithSystemPrompt("Test prompt"),
				WithStopSequences("STOP", "END"),
			},
			validate: func(t *testing.T, opts *completionOptions) {
				assert.NotNil(t, opts.Temperature)
				assert.Equal(t, 0.5, *opts.Temperature)
				assert.NotNil(t, opts.MaxTokens)
				assert.Equal(t, 500, *opts.MaxTokens)
				assert.NotNil(t, opts.TopP)
				assert.Equal(t, 0.85, *opts.TopP)
				assert.NotNil(t, opts.SystemPrompt)
				assert.Equal(t, "Test prompt", *opts.SystemPrompt)
				assert.Equal(t, []string{"STOP", "END"}, opts.StopSequences)
			},
		},
		{
			name: "no options",
			opts: []CompletionOption{},
			validate: func(t *testing.T, opts *completionOptions) {
				assert.Nil(t, opts.Temperature)
				assert.Nil(t, opts.MaxTokens)
				assert.Nil(t, opts.TopP)
				assert.Nil(t, opts.SystemPrompt)
				assert.Nil(t, opts.StopSequences)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := applyOptions(tt.opts...)
			assert.NotNil(t, opts)
			tt.validate(t, opts)
		})
	}
}

// TestOptionComposition tests that options can be composed and applied in order
func TestOptionComposition(t *testing.T) {
	opts := newCompletionOptions()

	// Apply options in sequence
	WithTemperature(0.7)(opts)
	WithMaxTokens(1000)(opts)
	WithTopP(0.9)(opts)
	WithSystemPrompt("You are helpful")(opts)
	WithStopSequences("STOP", "END")(opts)

	// Verify all options were applied
	assert.NotNil(t, opts.Temperature)
	assert.Equal(t, 0.7, *opts.Temperature)
	assert.NotNil(t, opts.MaxTokens)
	assert.Equal(t, 1000, *opts.MaxTokens)
	assert.NotNil(t, opts.TopP)
	assert.Equal(t, 0.9, *opts.TopP)
	assert.NotNil(t, opts.SystemPrompt)
	assert.Equal(t, "You are helpful", *opts.SystemPrompt)
	assert.Equal(t, []string{"STOP", "END"}, opts.StopSequences)
}

// TestOptionsOverwrite tests that later options overwrite earlier ones
func TestOptionsOverwrite(t *testing.T) {
	tests := []struct {
		name     string
		opts     []CompletionOption
		validate func(t *testing.T, opts *completionOptions)
	}{
		{
			name: "temperature overwrite",
			opts: []CompletionOption{
				WithTemperature(0.5),
				WithTemperature(0.9),
			},
			validate: func(t *testing.T, opts *completionOptions) {
				assert.NotNil(t, opts.Temperature)
				assert.Equal(t, 0.9, *opts.Temperature)
			},
		},
		{
			name: "max tokens overwrite",
			opts: []CompletionOption{
				WithMaxTokens(100),
				WithMaxTokens(500),
			},
			validate: func(t *testing.T, opts *completionOptions) {
				assert.NotNil(t, opts.MaxTokens)
				assert.Equal(t, 500, *opts.MaxTokens)
			},
		},
		{
			name: "top_p overwrite",
			opts: []CompletionOption{
				WithTopP(0.5),
				WithTopP(0.95),
			},
			validate: func(t *testing.T, opts *completionOptions) {
				assert.NotNil(t, opts.TopP)
				assert.Equal(t, 0.95, *opts.TopP)
			},
		},
		{
			name: "system prompt overwrite",
			opts: []CompletionOption{
				WithSystemPrompt("First prompt"),
				WithSystemPrompt("Second prompt"),
			},
			validate: func(t *testing.T, opts *completionOptions) {
				assert.NotNil(t, opts.SystemPrompt)
				assert.Equal(t, "Second prompt", *opts.SystemPrompt)
			},
		},
		{
			name: "stop sequences overwrite",
			opts: []CompletionOption{
				WithStopSequences("STOP"),
				WithStopSequences("END", "DONE"),
			},
			validate: func(t *testing.T, opts *completionOptions) {
				assert.Equal(t, []string{"END", "DONE"}, opts.StopSequences)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := applyOptions(tt.opts...)
			tt.validate(t, opts)
		})
	}
}

// TestPointerSemantics verifies that pointer fields allow distinguishing
// between "not set" and "set to zero value"
func TestPointerSemantics(t *testing.T) {
	t.Run("unset values are nil", func(t *testing.T) {
		opts := newCompletionOptions()
		assert.Nil(t, opts.Temperature)
		assert.Nil(t, opts.MaxTokens)
		assert.Nil(t, opts.TopP)
		assert.Nil(t, opts.SystemPrompt)
	})

	t.Run("zero values are not nil", func(t *testing.T) {
		opts := applyOptions(
			WithTemperature(0.0),
			WithMaxTokens(0),
			WithTopP(0.0),
			WithSystemPrompt(""),
		)

		// All should be non-nil even though they're zero values
		assert.NotNil(t, opts.Temperature)
		assert.Equal(t, 0.0, *opts.Temperature)
		assert.NotNil(t, opts.MaxTokens)
		assert.Equal(t, 0, *opts.MaxTokens)
		assert.NotNil(t, opts.TopP)
		assert.Equal(t, 0.0, *opts.TopP)
		assert.NotNil(t, opts.SystemPrompt)
		assert.Equal(t, "", *opts.SystemPrompt)
	})
}

// TestComplexScenarios tests realistic usage patterns
func TestComplexScenarios(t *testing.T) {
	t.Run("agent with custom temperature and tokens", func(t *testing.T) {
		opts := applyOptions(
			WithTemperature(0.3),
			WithMaxTokens(2000),
		)

		assert.NotNil(t, opts.Temperature)
		assert.Equal(t, 0.3, *opts.Temperature)
		assert.NotNil(t, opts.MaxTokens)
		assert.Equal(t, 2000, *opts.MaxTokens)
		assert.Nil(t, opts.TopP)
		assert.Nil(t, opts.SystemPrompt)
	})

	t.Run("agent with all sampling parameters", func(t *testing.T) {
		opts := applyOptions(
			WithTemperature(0.7),
			WithTopP(0.9),
			WithMaxTokens(1500),
			WithStopSequences("\n\nHuman:", "\n\nAssistant:"),
		)

		assert.NotNil(t, opts.Temperature)
		assert.Equal(t, 0.7, *opts.Temperature)
		assert.NotNil(t, opts.TopP)
		assert.Equal(t, 0.9, *opts.TopP)
		assert.NotNil(t, opts.MaxTokens)
		assert.Equal(t, 1500, *opts.MaxTokens)
		assert.Equal(t, []string{"\n\nHuman:", "\n\nAssistant:"}, opts.StopSequences)
	})

	t.Run("overriding system prompt", func(t *testing.T) {
		opts := applyOptions(
			WithSystemPrompt("Original prompt"),
			WithTemperature(0.5),
			WithSystemPrompt("Overridden prompt"),
		)

		assert.NotNil(t, opts.SystemPrompt)
		assert.Equal(t, "Overridden prompt", *opts.SystemPrompt)
		assert.NotNil(t, opts.Temperature)
		assert.Equal(t, 0.5, *opts.Temperature)
	})
}

// TestEdgeCases tests edge cases and boundary conditions
func TestEdgeCases(t *testing.T) {
	t.Run("empty stop sequences", func(t *testing.T) {
		opts := applyOptions(WithStopSequences())
		// Empty variadic creates a non-nil empty slice
		assert.Empty(t, opts.StopSequences)
		assert.Equal(t, 0, len(opts.StopSequences))
	})

	t.Run("nil option list", func(t *testing.T) {
		opts := applyOptions()
		assert.NotNil(t, opts)
		assert.Nil(t, opts.Temperature)
		assert.Nil(t, opts.MaxTokens)
	})

	t.Run("very large max tokens", func(t *testing.T) {
		opts := applyOptions(WithMaxTokens(100000))
		assert.NotNil(t, opts.MaxTokens)
		assert.Equal(t, 100000, *opts.MaxTokens)
	})

	t.Run("very small temperature", func(t *testing.T) {
		opts := applyOptions(WithTemperature(0.01))
		assert.NotNil(t, opts.Temperature)
		assert.Equal(t, 0.01, *opts.Temperature)
	})

	t.Run("multiline system prompt", func(t *testing.T) {
		prompt := `You are a specialized agent.

Guidelines:
1. Be precise
2. Be thorough
3. Be helpful`

		opts := applyOptions(WithSystemPrompt(prompt))
		assert.NotNil(t, opts.SystemPrompt)
		assert.Equal(t, prompt, *opts.SystemPrompt)
	})
}
