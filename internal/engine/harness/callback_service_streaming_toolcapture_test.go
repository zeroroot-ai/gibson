// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	commonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/common/v1"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
)

// fakeStreamSendServer implements harnesspb.HarnessCallbackService_CallToolProtoStreamServer
// just enough to drive CallToolProtoStream: a real context and a Send that
// records what was sent.
type fakeStreamSendServer struct {
	grpc.ServerStream
	ctx  context.Context
	sent []*harnesspb.CallToolProtoStreamResponse
}

func (f *fakeStreamSendServer) Context() context.Context { return f.ctx }
func (f *fakeStreamSendServer) Send(r *harnesspb.CallToolProtoStreamResponse) error {
	f.sent = append(f.sent, r)
	return nil
}

func streamRequest(contextInfo *harnesspb.ContextInfo) *harnesspb.CallToolProtoStreamRequest {
	return &harnesspb.CallToolProtoStreamRequest{
		Context:    contextInfo,
		Name:       "test-external-tool",
		InputType:  "testtool.ToolInput",
		InputJson:  []byte(`{"query":"q"}`),
		OutputType: "testtool.ToolOutput",
	}
}

// TestCallToolProtoStream_FeedsToolCallSink_OnComplete proves that a streamed
// tool call takes the dispatch of the unary handler, sends one Complete event,
// and leaves exactly one flight recorder record (ADR-0131, gibson#755).
func TestCallToolProtoStream_FeedsToolCallSink_OnComplete(t *testing.T) {
	var captured []capturedTool
	svc, _, contextInfo := newStreamCaptureSvc(t, &captured, nil)
	stream := &fakeStreamSendServer{ctx: testCtxWithTenant()}

	require.NoError(t, svc.CallToolProtoStream(streamRequest(contextInfo), stream))

	require.Len(t, stream.sent, 1, "one terminal event")
	require.NotNil(t, stream.sent[0].GetComplete(), "the event is the Complete payload")
	require.Contains(t, string(stream.sent[0].GetComplete().GetOutputJson()), "success")
	require.Len(t, captured, 1, "exactly one record of the call")
	require.Empty(t, captured[0].call.Err)
}

// TestCallToolProtoStream_FeedsToolCallSink_OnError proves that a tool that
// fails after dispatch sends one Error event and leaves one failure record.
func TestCallToolProtoStream_FeedsToolCallSink_OnError(t *testing.T) {
	var captured []capturedTool
	svc, _, contextInfo := newStreamCaptureSvc(t, &captured, errors.New("tool boom"))
	stream := &fakeStreamSendServer{ctx: testCtxWithTenant()}

	require.NoError(t, svc.CallToolProtoStream(streamRequest(contextInfo), stream))

	require.Len(t, stream.sent, 1, "one terminal event")
	require.NotNil(t, stream.sent[0].GetError(), "the event is the Error payload")
	require.True(t, stream.sent[0].GetError().GetFatal())
	require.Equal(t, commonpb.ErrorCode_ERROR_CODE_INTERNAL, stream.sent[0].GetError().GetError().GetCode())
	require.Len(t, captured, 1, "exactly one record of the failed call")
	require.NotEmpty(t, captured[0].call.Err)
}

// TestCallToolProtoStream_NoRunContextIsRefused proves that a streamed call
// with no resolvable harness returns the error of the unary handler and sends
// no event.
func TestCallToolProtoStream_NoRunContextIsRefused(t *testing.T) {
	var captured []capturedTool
	svc, _, _ := newStreamCaptureSvc(t, &captured, nil)
	stream := &fakeStreamSendServer{ctx: testCtxWithTenant()}

	require.Error(t, svc.CallToolProtoStream(streamRequest(nil), stream))
	require.Empty(t, stream.sent)
	require.Empty(t, captured)
}

// newStreamCaptureSvc builds a callback service whose harness serves one
// tool. toolErr, when set, is the error of the tool.
func newStreamCaptureSvc(t *testing.T, captured *[]capturedTool, toolErr error) (*HarnessCallbackService, *mockHarnessWithResolver, *harnesspb.ContextInfo) {
	t.Helper()
	mockHarness := &mockHarnessWithResolver{
		toolDescriptors: map[string]*ToolDescriptor{
			"test-external-tool": {
				Name:            "test-external-tool",
				InputProtoType:  "testtool.ToolInput",
				OutputProtoType: "testtool.ToolOutput",
				Metadata:        map[string]string{"file_descriptor_set": createTestFileDescriptorSetForCallback()},
			},
		},
		toolHandler: func(_ context.Context, _ string, _, response proto.Message) error {
			if toolErr != nil {
				return toolErr
			}
			out := response.ProtoReflect()
			out.Set(out.Descriptor().Fields().ByName("result"), protoreflect.ValueOfString("success"))
			return nil
		},
	}
	registry := NewCallbackHarnessRegistry()
	registry.Register("test-mission-123", "test-agent", mockHarness)
	svc := NewHarnessCallbackServiceWithRegistry(slog.Default(), registry,
		WithToolCallSink(func(_ context.Context, tn string, call ToolCallRecord) {
			*captured = append(*captured, capturedTool{tenant: tn, call: call})
		}),
	)
	contextInfo := &harnesspb.ContextInfo{
		TaskId: "task-123", AgentName: "test-agent", MissionId: "test-mission-123",
		MissionRunId: "run-1", ToolExecutionId: "tool-exec-stream-1",
	}
	return svc, mockHarness, contextInfo
}
