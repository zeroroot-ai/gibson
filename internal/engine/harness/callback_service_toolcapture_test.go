// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// capturedTool records what the wired ToolCallSink received.
type capturedTool struct {
	tenant string
	call   ToolCallRecord
}

// TestCallToolProto_FeedsToolCallSink_OnSuccess is the gibson#271
// flight-recorder unit for the tool-I/O half: a successful CallToolProto
// invocation surfaces as a ToolCallRecord carrying the full arguments and
// result JSON, stamped with mission context — the gap where tool I/O
// previously reached the daemon only as bare tool.call.* pub/sub metadata
// with no argument/result text.
func TestCallToolProto_FeedsToolCallSink_OnSuccess(t *testing.T) {
	fdsBase64 := createTestFileDescriptorSetForCallback()
	var captured []capturedTool
	mockHarness := &mockHarnessWithResolver{
		toolDescriptors: map[string]*ToolDescriptor{
			"test-external-tool": {
				Name:            "test-external-tool",
				Description:     "A test tool with dynamic types",
				InputProtoType:  "testtool.ToolInput",
				OutputProtoType: "testtool.ToolOutput",
				Metadata:        map[string]string{"file_descriptor_set": fdsBase64},
			},
		},
		toolHandler: func(_ context.Context, _ string, _, response proto.Message) error {
			outputRefl := response.ProtoReflect()
			outputRefl.Set(outputRefl.Descriptor().Fields().ByName("result"), protoreflect.ValueOfString("success"))
			outputRefl.Set(outputRefl.Descriptor().Fields().ByName("count"), protoreflect.ValueOfInt32(42))
			return nil
		},
	}
	registry := NewCallbackHarnessRegistry()
	registry.Register("test-mission-123", "test-agent", mockHarness)
	svc := NewHarnessCallbackServiceWithRegistry(
		slog.New(slog.NewTextHandler(os.Stdout, nil)),
		registry,
		WithToolCallSink(func(_ context.Context, tn string, call ToolCallRecord) {
			captured = append(captured, capturedTool{tenant: tn, call: call})
		}),
	)

	req := &harnesspb.CallToolProtoRequest{
		Context: &harnesspb.ContextInfo{
			TaskId: "task-123", AgentName: "test-agent", MissionId: "test-mission-123",
			MissionRunId: "run-1", ToolExecutionId: "tool-exec-1",
		},
		Name:       "test-external-tool",
		InputType:  "testtool.ToolInput",
		InputJson:  []byte(`{"query": "test query", "limit": 10}`),
		OutputType: "testtool.ToolOutput",
	}

	ctx := testCtxWithTenant()
	resp, err := svc.CallToolProto(ctx, req)
	require.NoError(t, err)
	require.Nil(t, resp.Error)

	require.Len(t, captured, 1, "exactly one tool call should be captured")
	got := captured[0]
	assert.Equal(t, "test-tenant", got.tenant)
	assert.Equal(t, "tool-exec-1", got.call.ToolCallID, "identity is the SDK-stamped ToolExecutionId")
	assert.Equal(t, "test-mission-123", got.call.MissionID)
	assert.Equal(t, "run-1", got.call.RunID)
	assert.Equal(t, "test-external-tool", got.call.ToolName)
	assert.JSONEq(t, `{"query": "test query", "limit": 10}`, got.call.Arguments, "arguments captured full-fidelity")
	assert.Empty(t, got.call.Err)
	assert.NotZero(t, got.call.RecordedAtUnixNano)

	var result map[string]any
	require.NoError(t, json.Unmarshal([]byte(got.call.Result), &result))
	assert.Equal(t, "success", result["result"], "result captured full-fidelity")
}

// TestCallToolProto_FeedsToolCallSink_OnFailure proves a failed tool call is
// captured too — the arguments the agent sent and why it failed — not only
// the calls that succeeded.
func TestCallToolProto_FeedsToolCallSink_OnFailure(t *testing.T) {
	fdsBase64 := createTestFileDescriptorSetForCallback()
	var captured []capturedTool
	mockHarness := &mockHarnessWithResolver{
		toolDescriptors: map[string]*ToolDescriptor{
			"test-external-tool": {
				Name:            "test-external-tool",
				InputProtoType:  "testtool.ToolInput",
				OutputProtoType: "testtool.ToolOutput",
				Metadata:        map[string]string{"file_descriptor_set": fdsBase64},
			},
		},
		toolHandler: func(_ context.Context, _ string, _, _ proto.Message) error {
			return errors.New("connection refused")
		},
	}
	registry := NewCallbackHarnessRegistry()
	registry.Register("test-mission-123", "test-agent", mockHarness)
	svc := NewHarnessCallbackServiceWithRegistry(
		slog.New(slog.NewTextHandler(os.Stdout, nil)),
		registry,
		WithToolCallSink(func(_ context.Context, tn string, call ToolCallRecord) {
			captured = append(captured, capturedTool{tenant: tn, call: call})
		}),
	)

	req := &harnesspb.CallToolProtoRequest{
		Context: &harnesspb.ContextInfo{
			TaskId: "task-1", AgentName: "test-agent", MissionId: "test-mission-123",
			ToolExecutionId: "tool-exec-2",
		},
		Name:       "test-external-tool",
		InputType:  "testtool.ToolInput",
		InputJson:  []byte(`{"query": "boom", "limit": 1}`),
		OutputType: "testtool.ToolOutput",
	}

	ctx := testCtxWithTenant()
	resp, err := svc.CallToolProto(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp.Error, "the RPC itself reports the tool error")

	require.Len(t, captured, 1, "a failed tool call must still be captured")
	got := captured[0].call
	assert.Equal(t, "tool-exec-2", got.ToolCallID)
	assert.JSONEq(t, `{"query": "boom", "limit": 1}`, got.Arguments)
	assert.Equal(t, "connection refused", got.Err)
	assert.Empty(t, got.Result)
}

// TestCallToolProto_ToolCallIDFallsBackToFreshUUID proves capture never
// silently drops a call just because the SDK left ToolExecutionId unset — it
// is simply not correlated to a PRODUCED-edge provenance chain.
func TestCallToolProto_ToolCallIDFallsBackToFreshUUID(t *testing.T) {
	fdsBase64 := createTestFileDescriptorSetForCallback()
	var captured []capturedTool
	mockHarness := &mockHarnessWithResolver{
		toolDescriptors: map[string]*ToolDescriptor{
			"test-external-tool": {
				Name:            "test-external-tool",
				InputProtoType:  "testtool.ToolInput",
				OutputProtoType: "testtool.ToolOutput",
				Metadata:        map[string]string{"file_descriptor_set": fdsBase64},
			},
		},
		toolHandler: func(_ context.Context, _ string, _, _ proto.Message) error {
			return nil
		},
	}
	registry := NewCallbackHarnessRegistry()
	registry.Register("test-mission-123", "test-agent", mockHarness)
	svc := NewHarnessCallbackServiceWithRegistry(
		slog.New(slog.NewTextHandler(os.Stdout, nil)),
		registry,
		WithToolCallSink(func(_ context.Context, tn string, call ToolCallRecord) {
			captured = append(captured, capturedTool{tenant: tn, call: call})
		}),
	)

	req := &harnesspb.CallToolProtoRequest{
		Context:    &harnesspb.ContextInfo{TaskId: "task-1", AgentName: "test-agent", MissionId: "test-mission-123"},
		Name:       "test-external-tool",
		InputType:  "testtool.ToolInput",
		InputJson:  []byte(`{"query": "q", "limit": 1}`),
		OutputType: "testtool.ToolOutput",
	}

	ctx := testCtxWithTenant()
	_, err := svc.CallToolProto(ctx, req)
	require.NoError(t, err)

	require.Len(t, captured, 1)
	assert.NotEmpty(t, captured[0].call.ToolCallID, "a fresh id must be minted when the SDK left ToolExecutionId unset")
}

// TestCaptureToolCall_NoTenantInContext_NoOp exercises captureToolCall's
// defensive no-tenant guard directly: a context with no tenant string must
// never reach the sink, even though in practice CallToolProto's own
// getHarness tenant-isolation check makes this unreachable on that path — the
// guard exists so captureToolCall stays safe to call from anywhere.
func TestCaptureToolCall_NoTenantInContext_NoOp(t *testing.T) {
	var called bool
	svc := &HarnessCallbackService{
		toolCallSink: func(context.Context, string, ToolCallRecord) { called = true },
	}
	svc.captureToolCall(context.Background(), &harnesspb.ContextInfo{MissionId: "m1"}, "nmap", "{}", "{}", "")
	if called {
		t.Fatal("captureToolCall must no-op when the context carries no tenant")
	}
}

// TestCallToolProto_NoSink_NoPanic ensures tool-call capture is a clean no-op
// when the sink is unwired.
func TestCallToolProto_NoSink_NoPanic(t *testing.T) {
	fdsBase64 := createTestFileDescriptorSetForCallback()
	mockHarness := &mockHarnessWithResolver{
		toolDescriptors: map[string]*ToolDescriptor{
			"test-external-tool": {
				Name:            "test-external-tool",
				InputProtoType:  "testtool.ToolInput",
				OutputProtoType: "testtool.ToolOutput",
				Metadata:        map[string]string{"file_descriptor_set": fdsBase64},
			},
		},
		toolHandler: func(_ context.Context, _ string, _, _ proto.Message) error {
			return nil
		},
	}
	registry := NewCallbackHarnessRegistry()
	registry.Register("test-mission-123", "test-agent", mockHarness)
	svc := NewHarnessCallbackServiceWithRegistry(slog.New(slog.NewTextHandler(os.Stdout, nil)), registry)

	req := &harnesspb.CallToolProtoRequest{
		Context:    &harnesspb.ContextInfo{TaskId: "task-1", AgentName: "test-agent", MissionId: "test-mission-123"},
		Name:       "test-external-tool",
		InputType:  "testtool.ToolInput",
		InputJson:  []byte(`{"query": "q", "limit": 1}`),
		OutputType: "testtool.ToolOutput",
	}
	ctx := testCtxWithTenant()
	resp, err := svc.CallToolProto(ctx, req)
	require.NoError(t, err)
	require.Nil(t, resp.Error)
}
