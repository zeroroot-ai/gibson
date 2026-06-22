package llm

import (
	"encoding/json"
	"fmt"

	"github.com/zeroroot-ai/sdk/schema"
)

// ToolDef defines a tool that an LLM can call during completion.
// Tools allow LLMs to interact with external systems and retrieve information.
type ToolDef struct {
	// Name is the unique identifier for this tool
	Name string `json:"name"`

	// Description explains what the tool does and when to use it
	Description string `json:"description"`

	// Parameters defines the JSON schema for the tool's input parameters
	Parameters schema.JSON `json:"parameters"`
}

// Validate checks if the tool definition is valid
func (t ToolDef) Validate() error {
	if t.Name == "" {
		return fmt.Errorf("tool name is required")
	}

	if t.Description == "" {
		return fmt.Errorf("tool description is required")
	}

	// Ensure parameters is an object schema
	if t.Parameters.Type != "" && t.Parameters.Type != "object" {
		return fmt.Errorf("tool parameters must be an object schema, got %s", t.Parameters.Type)
	}

	return nil
}

// ToolCall represents a tool call made by the LLM during completion.
// The LLM specifies which tool to call and what arguments to provide.
type ToolCall struct {
	// ID is a unique identifier for this tool call
	ID string `json:"id"`

	// Type indicates the type of tool call (typically "function")
	Type string `json:"type"`

	// Name is the name of the tool to call
	Name string `json:"name"`

	// Arguments contains the JSON-encoded arguments for the tool
	Arguments string `json:"arguments"`
}

// ParseArguments deserializes the tool call arguments into the provided type.
// This is a generic helper that unmarshals the JSON arguments into a Go struct.
//
// Example:
//
//	type WeatherArgs struct {
//	    Location string `json:"location"`
//	    Unit     string `json:"unit"`
//	}
//
//	var args WeatherArgs
//	if err := toolCall.ParseArguments(&args); err != nil {
//	    return err
//	}
func (t ToolCall) ParseArguments(v any) error {
	if t.Arguments == "" {
		return fmt.Errorf("tool call arguments are empty")
	}

	if err := json.Unmarshal([]byte(t.Arguments), v); err != nil {
		return fmt.Errorf("failed to parse tool call arguments: %w", err)
	}

	return nil
}

// Validate checks if the tool call is valid
func (t ToolCall) Validate() error {
	if t.ID == "" {
		return fmt.Errorf("tool call ID is required")
	}

	if t.Name == "" {
		return fmt.Errorf("tool call name is required")
	}

	if t.Arguments == "" {
		return fmt.Errorf("tool call arguments are required")
	}

	// Validate that arguments is valid JSON
	var tmp any
	if err := json.Unmarshal([]byte(t.Arguments), &tmp); err != nil {
		return fmt.Errorf("tool call arguments must be valid JSON: %w", err)
	}

	return nil
}

// ToolResult represents the result of executing a tool call.
// This is returned to the LLM so it can incorporate the result into its response.
type ToolResult struct {
	// ToolCallID is the ID of the tool call this result corresponds to
	ToolCallID string `json:"tool_call_id"`

	// Content is the result content to return to the LLM
	Content string `json:"content"`

	// IsError indicates whether the tool execution resulted in an error
	IsError bool `json:"is_error,omitempty"`
}

// NewToolResult creates a successful tool result
func NewToolResult(toolCallID string, content string) ToolResult {
	return ToolResult{
		ToolCallID: toolCallID,
		Content:    content,
		IsError:    false,
	}
}

// NewToolError creates an error tool result
func NewToolError(toolCallID string, errorMessage string) ToolResult {
	return ToolResult{
		ToolCallID: toolCallID,
		Content:    errorMessage,
		IsError:    true,
	}
}

// Validate checks if the tool result is valid
func (r ToolResult) Validate() error {
	if r.ToolCallID == "" {
		return fmt.Errorf("tool call ID is required")
	}

	if r.Content == "" {
		return fmt.Errorf("tool result content is required")
	}

	return nil
}

// ToolCallDelta represents incremental tool call information in a streaming response.
// This allows LLMs to stream tool calls as they're being generated.
type ToolCallDelta struct {
	// Index is the index of the tool call being updated
	Index int `json:"index"`

	// ID is set in the first delta for a new tool call
	ID string `json:"id,omitempty"`

	// Type is set in the first delta for a new tool call
	Type string `json:"type,omitempty"`

	// Name is set in the first delta for a new tool call
	Name string `json:"name,omitempty"`

	// Arguments contains incremental JSON arguments being added
	Arguments string `json:"arguments,omitempty"`
}

// NewToolDef creates a new tool definition with the given name, description, and parameters
func NewToolDef(name, description string, params schema.JSON) ToolDef {
	// Ensure parameters is an object schema
	if params.Type == "" {
		params.Type = "object"
	}

	return ToolDef{
		Name:        name,
		Description: description,
		Parameters:  params,
	}
}
