// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

// service_llm_test.go drives CompleteWithTools and CompleteStructured through
// the proto boundary, with the real LLMRegistryAdapter behind them.
//
// The seam between the two is a JSON string, so a field-name mismatch on
// either side is invisible to the compiler and to any test that stops at the
// adapter. These tests assert on the protobuf messages the component actually
// receives, which is where the loss showed up (zerocool-plugins#6): tool calls
// arrived with an empty arguments_json, so opencode's agent loop invoked every
// tool with no arguments while appearing to work.

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
	"github.com/zeroroot-ai/sdk/auth"

	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// llmSeamServer wires the real adapter into a ComponentServiceServer, so a
// test exercises the same path a component's RPC takes.
func llmSeamServer(provider *mockLLMProvider) *ComponentServiceServer {
	return NewComponentServiceServer(&noopRegistry{}, &noopWorkQueue{}, testLogger(), nil, nil, nil, nil).
		WithLLMToolCompleter(newTestAdapter(provider))
}

func llmSeamContext() context.Context {
	return auth.ContextWithTenantString(context.Background(), adapterTestTenant)
}

func TestCompleteWithTools_ToolCallArgumentsReachTheComponent(t *testing.T) {
	provider := &mockLLMProvider{
		name:   "p",
		models: []llm.ModelInfo{{Name: "m"}},
		toolCompleteResp: &llm.CompletionResponse{
			Model: "m",
			Message: llm.Message{
				Role: "assistant",
				ToolCalls: []llm.ToolCall{{
					ID:        "call_1",
					Type:      "function",
					Name:      "read_file",
					Arguments: `{"path":"/etc/hosts"}`,
				}},
			},
			FinishReason: llm.FinishReasonToolCalls,
			Usage:        llm.CompletionTokenUsage{PromptTokens: 12, CompletionTokens: 4},
		},
	}

	resp, err := llmSeamServer(provider).CompleteWithTools(llmSeamContext(), &componentpb.CompleteWithToolsRequest{
		Slot:     "p",
		Messages: []*componentpb.LLMMessage{{Role: "user", Content: "read /etc/hosts"}},
		Tools: []*componentpb.ToolDefinition{{
			Name:            "read_file",
			InputSchemaJson: `{"type":"object"}`,
		}},
	})

	require.NoError(t, err)
	require.Len(t, resp.ToolCalls, 1)
	assert.Equal(t, "call_1", resp.ToolCalls[0].Id)
	assert.Equal(t, "read_file", resp.ToolCalls[0].Name)
	assert.JSONEq(t, `{"path":"/etc/hosts"}`, resp.ToolCalls[0].ArgumentsJson,
		"a tool call with no arguments makes the agent loop call every tool empty-handed")
	assert.Equal(t, "tool_calls", resp.FinishReason)
}

func TestCompleteWithTools_NoToolCalls_LeavesToolCallsEmpty(t *testing.T) {
	provider := &mockLLMProvider{
		name:   "p",
		models: []llm.ModelInfo{{Name: "m"}},
		toolCompleteResp: &llm.CompletionResponse{
			Model:        "m",
			Message:      llm.Message{Role: "assistant", Content: "no tool needed"},
			FinishReason: llm.FinishReasonStop,
		},
	}

	resp, err := llmSeamServer(provider).CompleteWithTools(llmSeamContext(), &componentpb.CompleteWithToolsRequest{
		Slot:     "p",
		Messages: []*componentpb.LLMMessage{{Role: "user", Content: "hi"}},
	})

	require.NoError(t, err)
	assert.Empty(t, resp.ToolCalls)
	assert.Equal(t, "no tool needed", resp.Response.GetContent())
}

func TestCompleteStructured_EnforcesTheCallersSchema(t *testing.T) {
	provider := &mockStructuredProvider{
		mockLLMProvider: mockLLMProvider{
			name:   "p",
			models: []llm.ModelInfo{{Name: "m"}},
		},
		structuredResp: &llm.CompletionResponse{
			Model:   "m",
			Message: llm.Message{Role: "assistant", Content: `{"severity":"high"}`},
			Usage:   llm.CompletionTokenUsage{PromptTokens: 9, CompletionTokens: 3},
		},
	}

	svc := NewComponentServiceServer(&noopRegistry{}, &noopWorkQueue{}, testLogger(), nil, nil, nil, nil).
		WithLLMToolCompleter(newTestAdapterForProvider("p", provider))

	out, err := svc.CompleteStructured(llmSeamContext(), &componentpb.CompleteStructuredRequest{
		Slot:       "p",
		Messages:   []*componentpb.LLMMessage{{Role: "user", Content: "classify"}},
		SchemaJson: `{"type":"object","properties":{"severity":{"type":"string"}},"required":["severity"]}`,
	})

	require.NoError(t, err)
	assert.JSONEq(t, `{"severity":"high"}`, out.ResultJson)
	assert.Equal(t, int32(9), out.Usage.GetInputTokens())

	require.NotNil(t, provider.gotRequest, "the provider's structured path must be the one called")
	require.NotNil(t, provider.gotRequest.ResponseFormat, "the schema must reach the provider")
	assert.Equal(t, types.ResponseFormatJSONSchema, provider.gotRequest.ResponseFormat.Type)
	require.NotNil(t, provider.gotRequest.ResponseFormat.Schema)
	assert.Equal(t, "object", provider.gotRequest.ResponseFormat.Schema.Type)
	assert.Contains(t, provider.gotRequest.ResponseFormat.Schema.Properties, "severity")
	assert.Equal(t, []string{"severity"}, provider.gotRequest.ResponseFormat.Schema.Required)
	assert.Equal(t, 1, provider.calls, "exactly one provider call, on the schema-enforcing path")
}

func TestCompleteStructured_ProviderWithoutSchemaSupport_IsRefused(t *testing.T) {
	// mockLLMProvider does not implement llm.StructuredOutputProvider.
	provider := &mockLLMProvider{
		name:         "p",
		models:       []llm.ModelInfo{{Name: "m"}},
		completeResp: &llm.CompletionResponse{Message: llm.Message{Content: "free text, not JSON"}},
	}

	_, err := llmSeamServer(provider).CompleteStructured(llmSeamContext(), &componentpb.CompleteStructuredRequest{
		Slot:       "p",
		Messages:   []*componentpb.LLMMessage{{Role: "user", Content: "classify"}},
		SchemaJson: `{"type":"object"}`,
	})

	require.Error(t, err)
	s, _ := status.FromError(err)
	assert.Equal(t, codes.Unimplemented, s.Code())
	assert.Zero(t, provider.calls, "an unenforceable schema must not degrade to free text")
}

func TestCompleteStructured_MissingOrMalformedSchema_IsInvalidArgument(t *testing.T) {
	provider := &mockStructuredProvider{
		mockLLMProvider: mockLLMProvider{name: "p", models: []llm.ModelInfo{{Name: "m"}}},
		structuredResp:  &llm.CompletionResponse{Message: llm.Message{Content: "{}"}},
	}
	svc := NewComponentServiceServer(&noopRegistry{}, &noopWorkQueue{}, testLogger(), nil, nil, nil, nil).
		WithLLMToolCompleter(newTestAdapterForProvider("p", provider))

	// The RPC's own guard rejects an absent schema before the seam sees it;
	// the seam repeats the check because it is reachable from the harness too.
	for name, schema := range map[string]string{
		"malformed":     "{not json",
		"not an object": `"a bare string"`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := svc.CompleteStructured(llmSeamContext(), &componentpb.CompleteStructuredRequest{
				Slot:       "p",
				Messages:   []*componentpb.LLMMessage{{Role: "user", Content: "classify"}},
				SchemaJson: schema,
			})
			require.Error(t, err)
			s, _ := status.FromError(err)
			assert.Equal(t, codes.InvalidArgument, s.Code())
		})
	}

	t.Run("empty", func(t *testing.T) {
		_, _, _, err := newTestAdapterForProvider("p", provider).CompleteStructured(
			context.Background(), adapterTestTenant, "m", "p", validMessagesJSON(), "", 512, 0.5,
		)
		require.Error(t, err)
		s, _ := status.FromError(err)
		assert.Equal(t, codes.InvalidArgument, s.Code())
	})

	assert.Zero(t, provider.calls, "a schema the seam cannot read must never reach the provider")
}

func TestCompleteWithTools_KeepsTheSeamsOwnCode(t *testing.T) {
	// The tenant has no usable provider — a configuration answer the component
	// can act on, so Unavailable must not arrive as Internal.
	svc := NewComponentServiceServer(&noopRegistry{}, &noopWorkQueue{}, testLogger(), nil, nil, nil, nil).
		WithLLMToolCompleter(newEmptyTenantAdapter())

	_, err := svc.CompleteWithTools(llmSeamContext(), &componentpb.CompleteWithToolsRequest{
		Slot:     "p",
		Messages: []*componentpb.LLMMessage{{Role: "user", Content: "hi"}},
	})

	require.Error(t, err)
	s, _ := status.FromError(err)
	assert.Equal(t, codes.Unavailable, s.Code())
}

func TestCompletionStatus_UntypedErrorBecomesInternal(t *testing.T) {
	err := completionStatus(errors.New("the socket went away"))

	s, _ := status.FromError(err)
	assert.Equal(t, codes.Internal, s.Code())
	assert.Contains(t, s.Message(), "the socket went away")
}
