// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"
)

// TestCallToolProto_FeedsToolCallSink_OnMarshalFailure is the gibson#380 /
// ADR-0131 coverage unit for the narrower gap fixed in callback_service.go:
// a tool that executed successfully but whose response failed to marshal to
// JSON used to return an error to the agent with no independent record that
// the tool actually ran. It forces the real protojson.Marshal failure mode —
// an Any-typed field carrying a type_url the resolver cannot resolve — rather
// than mocking the marshaler, so this exercises the exact branch in
// production CallToolProto, not a stand-in for it.
func TestCallToolProto_FeedsToolCallSink_OnMarshalFailure(t *testing.T) {
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
		toolHandler: func(_ context.Context, _ string, _, response proto.Message) error {
			// The tool "succeeds" but hands back a discovery_result Any whose
			// type_url names a message no resolver has ever heard of. protojson
			// treats a well-known-named Any specially and must resolve its
			// type_url before it can marshal — that resolution fails, so
			// Marshal itself fails even though CallToolProto returned nil.
			outputRefl := response.ProtoReflect()
			fd := outputRefl.Descriptor().Fields().ByName("discovery_result")
			anyMsg := dynamicpb.NewMessage(fd.Message())
			anyRefl := anyMsg.ProtoReflect()
			anyRefl.Set(
				anyRefl.Descriptor().Fields().ByName("type_url"),
				protoreflect.ValueOfString("type.googleapis.com/totally.bogus.Unregistered"),
			)
			outputRefl.Set(fd, protoreflect.ValueOfMessage(anyRefl))
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
			TaskId: "task-1", AgentName: "test-agent", MissionId: "test-mission-123",
			ToolExecutionId: "tool-exec-marshalfail",
		},
		Name:       "test-external-tool",
		InputType:  "testtool.ToolInput",
		InputJson:  []byte(`{"query":"q","limit":1}`),
		OutputType: "testtool.ToolOutput",
	}

	ctx := testCtxWithTenant()
	resp, err := svc.CallToolProto(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp.Error, "a response the agent cannot use must still surface as an RPC-level error")

	require.Len(t, captured, 1, "a tool that ran but failed to marshal must still be captured")
	got := captured[0].call
	require.Equal(t, "tool-exec-marshalfail", got.ToolCallID)
	require.Contains(t, got.Err, "failed to marshal response")
	require.Empty(t, got.Result, "an unmarshalable result has nothing usable to record")
}
