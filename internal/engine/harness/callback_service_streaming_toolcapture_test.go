// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"

	commonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/common/v1"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	toolpb "github.com/zeroroot-ai/sdk/api/gen/gibson/tool/v1"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/tool"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/platform/component"
)

// This file proves the gibson#380 fix for the streaming bypass named in
// ADR-0030 §3: before this, CallToolProtoStream (the streaming counterpart of
// CallToolProto) never called captureToolCall at all, on any outcome — a
// streamed tool call could complete and hand the agent a real result with
// zero independent flight-recorder record. See internal/engine/harness/
// callback_service_streaming.go.

// fakeStreamToolServer is a minimal toolpb.ToolServiceServer: it reads the
// Start message and replies with exactly one terminal event (Complete or
// Error), enough to drive CallToolProtoStream's forwarding loop to its two
// capture-worthy outcomes.
type fakeStreamToolServer struct {
	toolpb.UnimplementedToolServiceServer
	sendComplete bool
	outputJSON   string
	errMessage   string
}

func (f *fakeStreamToolServer) StreamExecute(stream toolpb.ToolService_StreamExecuteServer) error {
	if _, err := stream.Recv(); err != nil {
		return err
	}
	if f.sendComplete {
		return stream.Send(&toolpb.StreamExecuteResponse{
			Payload: &toolpb.StreamExecuteResponse_Complete{
				Complete: &toolpb.ToolComplete{OutputJson: f.outputJSON},
			},
		})
	}
	return stream.Send(&toolpb.StreamExecuteResponse{
		Payload: &toolpb.StreamExecuteResponse_Error{
			Error: &toolpb.ToolError{
				Error: &commonpb.Error{Code: "internal", Message: f.errMessage},
				Fatal: true,
			},
		},
	})
}

// startFakeToolServer boots the fake tool service on an ephemeral local port
// and returns a dialed client connection plus a cleanup func.
func startFakeToolServer(t *testing.T, srv *fakeStreamToolServer) *grpc.ClientConn {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	gs := grpc.NewServer()
	toolpb.RegisterToolServiceServer(gs, srv)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// streamConnTool is a tool.Tool that also exposes GetConn, satisfying the
// unexported connTool interface CallToolProtoStream type-asserts against.
type streamConnTool struct {
	conn *grpc.ClientConn
}

func (streamConnTool) Name() string              { return "stream-tool" }
func (streamConnTool) Version() string           { return "v1" }
func (streamConnTool) Description() string       { return "test streaming tool" }
func (streamConnTool) Tags() []string            { return nil }
func (streamConnTool) InputMessageType() string  { return "testtool.ToolInput" }
func (streamConnTool) OutputMessageType() string { return "testtool.ToolOutput" }
func (streamConnTool) ExecuteProto(context.Context, proto.Message) (proto.Message, error) {
	return nil, errors.New("not used by streaming path")
}
func (streamConnTool) Health(context.Context) types.HealthStatus {
	return types.HealthStatus{}
}
func (t streamConnTool) GetConn() *grpc.ClientConn { return t.conn }

// fakeStreamDiscovery is a component.ComponentDiscovery that resolves every
// tool lookup to the same streamConnTool, and satisfies the rest of the
// interface with unused stubs.
type fakeStreamDiscovery struct {
	t tool.Tool
}

func (f fakeStreamDiscovery) DiscoverAgent(context.Context, string) (agent.Agent, error) {
	return nil, errors.New("not used")
}
func (f fakeStreamDiscovery) DiscoverTool(context.Context, string) (tool.Tool, error) {
	return f.t, nil
}
func (f fakeStreamDiscovery) ListAgents(context.Context) ([]component.AgentInfo, error) {
	return nil, nil
}
func (f fakeStreamDiscovery) ListTools(context.Context) ([]component.ToolInfo, error) {
	return nil, nil
}
func (f fakeStreamDiscovery) ListPlugins(context.Context) ([]component.PluginInfo, error) {
	return nil, nil
}
func (f fakeStreamDiscovery) DelegateToAgent(context.Context, string, agent.Task, agent.AgentHarness) (agent.Result, error) {
	return agent.Result{}, errors.New("not used")
}

func newStreamingTestHarness(conn *grpc.ClientConn) *DefaultAgentHarness {
	return &DefaultAgentHarness{
		registryAdapter: fakeStreamDiscovery{t: streamConnTool{conn: conn}},
		logger:          slog.New(slog.NewTextHandler(os.Stdout, nil)),
		tracer:          trace.NewNoopTracerProvider().Tracer("test"),
		missionCtx:      MissionContext{TenantID: "test-tenant"},
	}
}

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

func TestCallToolProtoStream_FeedsToolCallSink_OnComplete(t *testing.T) {
	conn := startFakeToolServer(t, &fakeStreamToolServer{sendComplete: true, outputJSON: `{"ok":true}`})

	registry := NewCallbackHarnessRegistry()
	registry.Register("test-mission-stream", "test-agent", newStreamingTestHarness(conn))

	var captured []capturedTool
	svc := NewHarnessCallbackServiceWithRegistry(
		slog.New(slog.NewTextHandler(os.Stdout, nil)),
		registry,
		WithToolCallSink(func(_ context.Context, tn string, call ToolCallRecord) {
			captured = append(captured, capturedTool{tenant: tn, call: call})
		}),
	)

	req := &harnesspb.CallToolProtoStreamRequest{
		Context: &harnesspb.ContextInfo{
			TaskId: "task-1", AgentName: "test-agent", MissionId: "test-mission-stream",
			MissionRunId: "run-1", ToolExecutionId: "tool-exec-stream-1",
		},
		Name:       "stream-tool",
		InputType:  "testtool.ToolInput",
		InputJson:  []byte(`{"query":"streamed"}`),
		OutputType: "testtool.ToolOutput",
		TimeoutMs:  5000,
	}
	stream := &fakeStreamSendServer{ctx: testCtxWithTenant()}

	deadline := time.Now().Add(10 * time.Second)
	err := svc.CallToolProtoStream(req, stream)
	require.NoError(t, err)
	require.True(t, time.Now().Before(deadline), "streaming call must not hang")

	require.Len(t, captured, 1, "a completed streamed tool call must be captured exactly once")
	got := captured[0]
	require.Equal(t, "test-tenant", got.tenant)
	require.Equal(t, "tool-exec-stream-1", got.call.ToolCallID)
	require.Equal(t, "stream-tool", got.call.ToolName)
	require.JSONEq(t, `{"query":"streamed"}`, got.call.Arguments)
	require.Equal(t, `{"ok":true}`, got.call.Result)
	require.Empty(t, got.call.Err)
}

func TestCallToolProtoStream_FeedsToolCallSink_OnError(t *testing.T) {
	conn := startFakeToolServer(t, &fakeStreamToolServer{sendComplete: false, errMessage: "boom"})

	registry := NewCallbackHarnessRegistry()
	registry.Register("test-mission-stream", "test-agent", newStreamingTestHarness(conn))

	var captured []capturedTool
	svc := NewHarnessCallbackServiceWithRegistry(
		slog.New(slog.NewTextHandler(os.Stdout, nil)),
		registry,
		WithToolCallSink(func(_ context.Context, tn string, call ToolCallRecord) {
			captured = append(captured, capturedTool{tenant: tn, call: call})
		}),
	)

	req := &harnesspb.CallToolProtoStreamRequest{
		Context: &harnesspb.ContextInfo{
			TaskId: "task-1", AgentName: "test-agent", MissionId: "test-mission-stream",
			ToolExecutionId: "tool-exec-stream-2",
		},
		Name:       "stream-tool",
		InputType:  "testtool.ToolInput",
		InputJson:  []byte(`{"query":"boom"}`),
		OutputType: "testtool.ToolOutput",
		TimeoutMs:  5000,
	}
	stream := &fakeStreamSendServer{ctx: testCtxWithTenant()}

	err := svc.CallToolProtoStream(req, stream)
	require.NoError(t, err)

	require.Len(t, captured, 1, "a failed streamed tool call must be captured too")
	got := captured[0].call
	require.Equal(t, "tool-exec-stream-2", got.ToolCallID)
	require.Equal(t, "boom", got.Err)
	require.Empty(t, got.Result)
}
