// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package modelclient

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Item types of Open Responses that the client builds or reads.
const (
	ItemMessage            = "message"
	ItemFunctionCall       = "function_call"
	ItemFunctionCallOutput = "function_call_output"
)

// Content part types.
const (
	PartInputText  = "input_text"
	PartOutputText = "output_text"
)

// Roles of a message item.
const (
	RoleUser      = "user"
	RoleAssistant = "assistant"
	RoleSystem    = "system"
	RoleDeveloper = "developer"
)

// ContentPart is one part of a message item.
type ContentPart struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

// Item is one item of the input or of the output of a call.
//
// An item that the client reads keeps its exact bytes in Raw. When Raw is set,
// MarshalJSON writes Raw, so an item that the gateway returned (a reasoning
// item, for example) goes back to the model without a change.
type Item struct {
	Type      string        `json:"type"`
	ID        string        `json:"id,omitempty"`
	Role      string        `json:"role,omitempty"`
	Status    string        `json:"status,omitempty"`
	Content   []ContentPart `json:"content,omitempty"`
	CallID    string        `json:"call_id,omitempty"`
	Name      string        `json:"name,omitempty"`
	Arguments string        `json:"arguments,omitempty"`
	Output    string        `json:"output,omitempty"`

	// Raw is the exact JSON of an item that the client read.
	Raw json.RawMessage `json:"-"`
}

// MarshalJSON writes Raw when it is set, and the fields otherwise.
func (i Item) MarshalJSON() ([]byte, error) {
	if len(i.Raw) > 0 {
		return i.Raw, nil
	}
	type plain Item
	b, err := json.Marshal(plain(i))
	if err != nil {
		return nil, fmt.Errorf("marshal item: %w", err)
	}
	return b, nil
}

// UnmarshalJSON reads the fields and keeps the exact bytes in Raw.
func (i *Item) UnmarshalJSON(b []byte) error {
	type plain Item
	var p plain
	if err := json.Unmarshal(b, &p); err != nil {
		return fmt.Errorf("unmarshal item: %w", err)
	}
	*i = Item(p)
	i.Raw = append(json.RawMessage(nil), b...)
	return nil
}

// UserMessage returns a user message item with one text part.
func UserMessage(text string) Item { return message(RoleUser, PartInputText, text) }

// SystemMessage returns a system message item with one text part.
func SystemMessage(text string) Item { return message(RoleSystem, PartInputText, text) }

// AssistantMessage returns an assistant message item with one text part. Use it
// to replay a past answer of the model.
func AssistantMessage(text string) Item { return message(RoleAssistant, PartOutputText, text) }

func message(role, partType, text string) Item {
	return Item{Type: ItemMessage, Role: role, Content: []ContentPart{{Type: partType, Text: text}}}
}

// FunctionCall returns the item for a tool call that the model made. Use it to
// replay a past tool call.
func FunctionCall(callID, name, arguments string) Item {
	return Item{Type: ItemFunctionCall, CallID: callID, Name: name, Arguments: arguments}
}

// FunctionCallOutput returns the item that gives the result of a tool call back
// to the model.
func FunctionCallOutput(callID, output string) Item {
	return Item{Type: ItemFunctionCallOutput, CallID: callID, Output: output}
}

// Tool is a function that the model may call.
type Tool struct {
	Type        string          `json:"type"`
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Parameters  json.RawMessage `json:"parameters,omitempty"`
	Strict      bool            `json:"strict,omitempty"`
}

// FunctionTool returns a function tool. The parameters are a JSON Schema.
func FunctionTool(name, description string, parameters json.RawMessage) Tool {
	return Tool{Type: "function", Name: name, Description: description, Parameters: parameters}
}

// TextFormat asks for structured output.
type TextFormat struct {
	Type   string          `json:"type"`
	Name   string          `json:"name,omitempty"`
	Schema json.RawMessage `json:"schema,omitempty"`
	Strict bool            `json:"strict,omitempty"`
}

// TextConfig is the "text" field of a request.
type TextConfig struct {
	Format TextFormat `json:"format"`
}

// JSONSchemaFormat returns a text config that asks for output that matches the
// JSON Schema.
func JSONSchemaFormat(name string, schema json.RawMessage) *TextConfig {
	return &TextConfig{Format: TextFormat{Type: "json_schema", Name: name, Schema: schema, Strict: true}}
}

// Request is an Open Responses request. Model is the one exact model name.
type Request struct {
	Model           string      `json:"model"`
	Input           []Item      `json:"input"`
	Instructions    string      `json:"instructions,omitempty"`
	Tools           []Tool      `json:"tools,omitempty"`
	ToolChoice      string      `json:"tool_choice,omitempty"`
	Text            *TextConfig `json:"text,omitempty"`
	MaxOutputTokens int         `json:"max_output_tokens,omitempty"`
	Temperature     *float64    `json:"temperature,omitempty"`
	Stream          bool        `json:"stream,omitempty"`
}

// Usage is the token count of a response.
type Usage struct {
	InputTokens        int `json:"input_tokens"`
	OutputTokens       int `json:"output_tokens"`
	TotalTokens        int `json:"total_tokens"`
	InputTokensDetails struct {
		CachedTokens int `json:"cached_tokens"`
	} `json:"input_tokens_details"`
}

// ResponseError is the error object of a failed response.
type ResponseError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Response is an Open Responses response.
type Response struct {
	ID     string         `json:"id"`
	Status string         `json:"status"`
	Model  string         `json:"model"`
	Output []Item         `json:"output"`
	Usage  Usage          `json:"usage"`
	Error  *ResponseError `json:"error"`
}

// OutputText returns the text of the assistant messages of the output, joined.
func (r *Response) OutputText() string {
	var b strings.Builder
	for _, it := range r.Output {
		if it.Type != ItemMessage {
			continue
		}
		for _, p := range it.Content {
			if p.Type == PartOutputText {
				b.WriteString(p.Text)
			}
		}
	}
	return b.String()
}

// FunctionCalls returns the tool calls that the model made.
func (r *Response) FunctionCalls() []Item {
	var out []Item
	for _, it := range r.Output {
		if it.Type == ItemFunctionCall {
			out = append(out, it)
		}
	}
	return out
}
