package llm

import (
	"encoding/json"
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/types"
)

// Role represents the role of a message in a conversation
type Role string

const (
	RoleSystem    Role = "system"
	RoleUser      Role = "user"
	RoleAssistant Role = "assistant"
	RoleTool      Role = "tool"
)

// String returns the string representation of the Role
func (r Role) String() string {
	return string(r)
}

// IsValid checks if the role is a valid value
func (r Role) IsValid() bool {
	switch r {
	case RoleSystem, RoleUser, RoleAssistant, RoleTool:
		return true
	default:
		return false
	}
}

// MarshalJSON implements json.Marshaler
func (r Role) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(r))
}

// UnmarshalJSON implements json.Unmarshaler
func (r *Role) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}

	role := Role(str)
	if !role.IsValid() {
		return fmt.Errorf("invalid role: %s", str)
	}

	*r = role
	return nil
}

// Message represents a single message in a conversation with an LLM.
type Message struct {
	Role       Role           `json:"role"`
	Content    string         `json:"content,omitempty"`
	Name       string         `json:"name,omitempty"`
	ToolCalls  []ToolCall     `json:"tool_calls,omitempty"`
	ToolCallID string         `json:"tool_call_id,omitempty"`
	Metadata   map[string]any `json:"metadata,omitempty"`
}

// NewSystemMessage creates a new system message
func NewSystemMessage(content string) Message {
	return Message{
		Role:    RoleSystem,
		Content: content,
	}
}

// NewUserMessage creates a new user message
func NewUserMessage(content string) Message {
	return Message{
		Role:    RoleUser,
		Content: content,
	}
}

// NewAssistantMessage creates a new assistant message
func NewAssistantMessage(content string) Message {
	return Message{
		Role:    RoleAssistant,
		Content: content,
	}
}

// NewToolResultMessage creates a new tool result message
func NewToolResultMessage(toolCallID string, content string) Message {
	return Message{
		Role:       RoleTool,
		Content:    content,
		ToolCallID: toolCallID,
	}
}

// WithName sets the name field on the message
func (m Message) WithName(name string) Message {
	m.Name = name
	return m
}

// WithMetadata sets metadata on the message
func (m Message) WithMetadata(key string, value any) Message {
	if m.Metadata == nil {
		m.Metadata = make(map[string]any)
	}
	m.Metadata[key] = value
	return m
}

// Validate checks if the message is valid
func (m Message) Validate() error {
	if !m.Role.IsValid() {
		return fmt.Errorf("invalid role: %s", m.Role)
	}

	switch m.Role {
	case RoleSystem, RoleUser:
		if m.Content == "" {
			return fmt.Errorf("%s message must have content", m.Role)
		}
		if len(m.ToolCalls) > 0 {
			return fmt.Errorf("%s message cannot have tool calls", m.Role)
		}
		if m.ToolCallID != "" {
			return fmt.Errorf("%s message cannot have tool_call_id", m.Role)
		}

	case RoleAssistant:
		if m.Content == "" && len(m.ToolCalls) == 0 {
			return fmt.Errorf("assistant message must have content or tool calls")
		}
		if m.ToolCallID != "" {
			return fmt.Errorf("assistant message cannot have tool_call_id")
		}

	case RoleTool:
		if m.Content == "" {
			return fmt.Errorf("tool message must have content")
		}
		if m.ToolCallID == "" {
			return fmt.Errorf("tool message must have tool_call_id")
		}
		if len(m.ToolCalls) > 0 {
			return fmt.Errorf("tool message cannot have tool calls")
		}
	}

	return nil
}

// CompletionRequest represents a request to generate a completion
type CompletionRequest struct {
	Model         string         `json:"model"`
	Messages      []Message      `json:"messages"`
	Temperature   float64        `json:"temperature,omitempty"`
	MaxTokens     int            `json:"max_tokens,omitempty"`
	TopP          float64        `json:"top_p,omitempty"`
	StopSequences []string       `json:"stop_sequences,omitempty"`
	SystemPrompt  string         `json:"system_prompt,omitempty"`
	Stream        bool           `json:"stream,omitempty"`
	Metadata      map[string]any `json:"metadata,omitempty"`

	// ResponseFormat specifies structured output requirements
	// nil = standard text completion (backward compatible)
	ResponseFormat *types.ResponseFormat `json:"response_format,omitempty"`
}

// Validate checks if the completion request is valid
func (r CompletionRequest) Validate() error {
	if r.Model == "" {
		return fmt.Errorf("model is required")
	}

	if len(r.Messages) == 0 {
		return fmt.Errorf("at least one message is required")
	}

	for i, msg := range r.Messages {
		if err := msg.Validate(); err != nil {
			return fmt.Errorf("message %d: %w", i, err)
		}
	}

	if r.Temperature < 0 || r.Temperature > 1 {
		return fmt.Errorf("temperature must be between 0 and 1, got %f", r.Temperature)
	}

	if r.TopP < 0 || r.TopP > 1 {
		return fmt.Errorf("top_p must be between 0 and 1, got %f", r.TopP)
	}

	if r.MaxTokens < 0 {
		return fmt.Errorf("max_tokens must be non-negative, got %d", r.MaxTokens)
	}

	return nil
}

// WithMetadata sets metadata on the request
func (r CompletionRequest) WithMetadata(key string, value any) CompletionRequest {
	if r.Metadata == nil {
		r.Metadata = make(map[string]any)
	}
	r.Metadata[key] = value
	return r
}

// CompletionResponse represents the response from an LLM completion request
type CompletionResponse struct {
	// ID is a unique identifier for this completion
	ID string `json:"id"`

	// Model is the model that generated this response
	Model string `json:"model"`

	// Message is the assistant's response message
	Message Message `json:"message"`

	// FinishReason indicates why generation stopped
	FinishReason FinishReason `json:"finish_reason"`

	// Usage contains token usage statistics for this completion
	Usage CompletionTokenUsage `json:"usage"`

	// Metadata contains arbitrary metadata from the provider
	Metadata map[string]any `json:"metadata,omitempty"`

	// StructuredData contains parsed JSON when ResponseFormat was specified
	// nil for standard text completions
	StructuredData any `json:"-"`

	// RawJSON contains the raw JSON string before parsing
	// Useful for debugging validation failures
	RawJSON string `json:"-"`
}

// FinishReason indicates why LLM generation stopped
type FinishReason string

const (
	FinishReasonStop          FinishReason = "stop"
	FinishReasonLength        FinishReason = "length"
	FinishReasonToolCalls     FinishReason = "tool_calls"
	FinishReasonContentFilter FinishReason = "content_filter"
	FinishReasonError         FinishReason = "error"
)

// String returns the string representation of FinishReason
func (f FinishReason) String() string {
	return string(f)
}

// IsValid checks if the finish reason is valid
func (f FinishReason) IsValid() bool {
	switch f {
	case FinishReasonStop, FinishReasonLength, FinishReasonToolCalls,
		FinishReasonContentFilter, FinishReasonError:
		return true
	default:
		return false
	}
}

// StreamChunk represents a single chunk in a streaming response
type StreamChunk struct {
	Delta        StreamDelta  `json:"delta"`
	FinishReason FinishReason `json:"finish_reason,omitempty"`
	Error        error        `json:"error,omitempty"`
}

// StreamDelta represents the incremental changes in a stream chunk
type StreamDelta struct {
	// Role is set in the first chunk to indicate the message role
	Role Role `json:"role,omitempty"`

	// Content contains incremental text content
	Content string `json:"content,omitempty"`

	// ToolCallDelta contains incremental tool call information
	ToolCallDelta *ToolCallDelta `json:"tool_call_delta,omitempty"`
}

// CompletionTokenUsage contains token usage statistics for an LLM completion.
// This type is used in CompletionResponse to track token consumption.
type CompletionTokenUsage struct {
	// PromptTokens is the number of tokens in the prompt
	PromptTokens int `json:"prompt_tokens"`

	// CompletionTokens is the number of tokens in the completion
	CompletionTokens int `json:"completion_tokens"`

	// TotalTokens is the total number of tokens used
	TotalTokens int `json:"total_tokens"`
}
