package llm

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWithTemperature(t *testing.T) {
	req := CompletionRequest{}
	opt := WithTemperature(0.7)
	opt(&req)

	assert.Equal(t, 0.7, req.Temperature)
}

func TestWithMaxTokens(t *testing.T) {
	req := CompletionRequest{}
	opt := WithMaxTokens(1000)
	opt(&req)

	assert.Equal(t, 1000, req.MaxTokens)
}

func TestWithTopP(t *testing.T) {
	req := CompletionRequest{}
	opt := WithTopP(0.9)
	opt(&req)

	assert.Equal(t, 0.9, req.TopP)
}

func TestWithStopSequences(t *testing.T) {
	req := CompletionRequest{}
	opt := WithStopSequences("STOP", "END")
	opt(&req)

	assert.Equal(t, []string{"STOP", "END"}, req.StopSequences)
}

func TestWithSystemPrompt(t *testing.T) {
	req := CompletionRequest{}
	opt := WithSystemPrompt("You are a helpful assistant")
	opt(&req)

	assert.Equal(t, "You are a helpful assistant", req.SystemPrompt)
}

func TestWithStream(t *testing.T) {
	tests := []struct {
		name     string
		value    bool
		expected bool
	}{
		{"enable stream", true, true},
		{"disable stream", false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := CompletionRequest{}
			opt := WithStream(tt.value)
			opt(&req)

			assert.Equal(t, tt.expected, req.Stream)
		})
	}
}

func TestWithMetadataOption(t *testing.T) {
	req := CompletionRequest{}
	opt1 := WithMetadataOption("key1", "value1")
	opt2 := WithMetadataOption("key2", 123)

	opt1(&req)
	opt2(&req)

	assert.Equal(t, "value1", req.Metadata["key1"])
	assert.Equal(t, 123, req.Metadata["key2"])
}

func TestApplyOptions(t *testing.T) {
	req := CompletionRequest{
		Model:    "gpt-4",
		Messages: []Message{NewUserMessage("test")},
	}

	ApplyOptions(&req,
		WithTemperature(0.8),
		WithMaxTokens(500),
		WithTopP(0.95),
		WithStopSequences("STOP"),
		WithSystemPrompt("You are helpful"),
		WithStream(true),
		WithMetadataOption("source", "api"),
	)

	assert.Equal(t, 0.8, req.Temperature)
	assert.Equal(t, 500, req.MaxTokens)
	assert.Equal(t, 0.95, req.TopP)
	assert.Equal(t, []string{"STOP"}, req.StopSequences)
	assert.Equal(t, "You are helpful", req.SystemPrompt)
	assert.True(t, req.Stream)
	assert.Equal(t, "api", req.Metadata["source"])
}

func TestNewCompletionRequest(t *testing.T) {
	messages := []Message{NewUserMessage("Hello")}

	req := NewCompletionRequest("gpt-4", messages,
		WithTemperature(0.7),
		WithMaxTokens(1000),
	)

	assert.Equal(t, "gpt-4", req.Model)
	assert.Equal(t, messages, req.Messages)
	assert.Equal(t, 0.7, req.Temperature)
	assert.Equal(t, 1000, req.MaxTokens)
}

func TestNewCompletionRequest_NoOptions(t *testing.T) {
	messages := []Message{NewUserMessage("Hello")}

	req := NewCompletionRequest("gpt-4", messages)

	assert.Equal(t, "gpt-4", req.Model)
	assert.Equal(t, messages, req.Messages)
	assert.Equal(t, 0.0, req.Temperature) // default value
	assert.Equal(t, 0, req.MaxTokens)     // default value
}

func TestMultipleOptions(t *testing.T) {
	req := CompletionRequest{}

	opts := []CompletionOption{
		WithTemperature(0.5),
		WithMaxTokens(200),
		WithTopP(0.8),
		WithStopSequences("END", "FINISH"),
		WithSystemPrompt("Test prompt"),
		WithStream(true),
		WithMetadataOption("test", true),
	}

	for _, opt := range opts {
		opt(&req)
	}

	assert.Equal(t, 0.5, req.Temperature)
	assert.Equal(t, 200, req.MaxTokens)
	assert.Equal(t, 0.8, req.TopP)
	assert.Equal(t, []string{"END", "FINISH"}, req.StopSequences)
	assert.Equal(t, "Test prompt", req.SystemPrompt)
	assert.True(t, req.Stream)
	assert.Equal(t, true, req.Metadata["test"])
}

func TestOptionsOverwrite(t *testing.T) {
	req := CompletionRequest{
		Temperature: 0.3,
		MaxTokens:   100,
	}

	// Options should overwrite existing values
	opt1 := WithTemperature(0.9)
	opt2 := WithMaxTokens(500)

	opt1(&req)
	opt2(&req)

	assert.Equal(t, 0.9, req.Temperature)
	assert.Equal(t, 500, req.MaxTokens)
}
