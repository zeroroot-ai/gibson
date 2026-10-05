// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package observability

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenAIAttributeKeyConstants(t *testing.T) {
	// Test that attribute keys follow the correct naming convention
	tests := []struct {
		name     string
		constant string
		expected string
	}{
		{"GenAI System", GenAISystem, "gen_ai.system"},
		{"GenAI Request Model", GenAIRequestModel, "gen_ai.request.model"},
		{"GenAI Request Temperature", GenAIRequestTemperature, "gen_ai.request.temperature"},
		{"GenAI Request Max Tokens", GenAIRequestMaxTokens, "gen_ai.request.max_tokens"},
		{"GenAI Request Top P", GenAIRequestTopP, "gen_ai.request.top_p"},
		{"GenAI Response Model", GenAIResponseModel, "gen_ai.response.model"},
		{"GenAI Response Finish Reason", GenAIResponseFinishReason, "gen_ai.response.finish_reason"},
		{"GenAI Usage Input Tokens", GenAIUsageInputTokens, "gen_ai.usage.input_tokens"},
		{"GenAI Usage Output Tokens", GenAIUsageOutputTokens, "gen_ai.usage.output_tokens"},
		{"GenAI Prompt", GenAIPrompt, "gen_ai.prompt"},
		{"GenAI Completion", GenAICompletion, "gen_ai.completion"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.constant)
		})
	}
}

func TestGenAISpanNameConstants(t *testing.T) {
	// Test that span names follow the correct naming convention
	tests := []struct {
		name     string
		constant string
		expected string
	}{
		{"Chat Span", SpanGenAIChat, "gen_ai.chat"},
		{"Chat Stream Span", SpanGenAIChatStream, "gen_ai.chat.stream"},
		{"Tool Span", SpanGenAITool, "gen_ai.tool"},
		{"Embeddings Span", SpanGenAIEmbeddings, "gen_ai.embeddings"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.constant)
		})
	}
}

func TestToolAttributeConstants(t *testing.T) {
	// Test that tool-related attribute keys follow the correct naming convention
	tests := []struct {
		name     string
		constant string
		expected string
	}{
		{"GenAI Tools Provided", GenAIToolsProvided, "gen_ai.request.tools_provided"},
		{"GenAI Tool Choice", GenAIToolChoice, "gen_ai.request.tool_choice"},
		{"GenAI Tool Call ID", GenAIToolCallID, "gen_ai.tool_call.id"},
		{"GenAI Tool Call Name", GenAIToolCallName, "gen_ai.tool_call.name"},
		{"GenAI Tool Call Arguments", GenAIToolCallArguments, "gen_ai.tool_call.arguments"},
		{"GenAI Tool Call Result", GenAIToolCallResult, "gen_ai.tool_call.result"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.constant)
		})
	}
}

func TestEventNameConstants(t *testing.T) {
	// Test that event name constants follow the correct naming convention
	tests := []struct {
		name     string
		constant string
		expected string
	}{
		{"Event GenAI Content Prompt", EventGenAIContentPrompt, "gen_ai.content.prompt"},
		{"Event GenAI Content Completion", EventGenAIContentCompletion, "gen_ai.content.completion"},
		{"Event GenAI Tool Call Input", EventGenAIToolCallInput, "gen_ai.tool_call.input"},
		{"Event GenAI Tool Call Output", EventGenAIToolCallOutput, "gen_ai.tool_call.output"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.constant)
		})
	}
}
