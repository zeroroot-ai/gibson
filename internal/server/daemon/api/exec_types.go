// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import "github.com/zeroroot-ai/sdk/schema"

// The request of an ExecuteLLM call, between the proto message and the Open
// Responses request. These types are local to the ExecuteLLM handler.

// execRole is the role of a message of an ExecuteLLM request.
type execRole string

// The roles of a message.
const (
	roleSystem    execRole = "system"
	roleAssistant execRole = "assistant"
	roleTool      execRole = "tool"
)

// execToolCall is a tool call that an assistant message made.
type execToolCall struct {
	ID        string
	Name      string
	Arguments string
}

// execMessage is one message of an ExecuteLLM request.
type execMessage struct {
	Role       execRole
	Content    string
	Name       string
	ToolCalls  []execToolCall
	ToolCallID string
}

// execToolDef is a tool that the model may call.
type execToolDef struct {
	Name        string
	Description string
	Parameters  schema.JSON
}

// execRequest is the model, the messages and the output limit of a call.
type execRequest struct {
	Model     string
	Messages  []execMessage
	MaxTokens int
}
