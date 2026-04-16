package harness

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/agent"
	"github.com/zero-day-ai/gibson/internal/component"
	"github.com/zero-day-ai/gibson/internal/llm"
	"github.com/zero-day-ai/gibson/internal/plugin"
	"github.com/zero-day-ai/gibson/internal/tool"
	"github.com/zero-day-ai/gibson/internal/types"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// fakeDiscovery is a file-local mock of component.ComponentDiscovery that
// serves a single tool through DiscoverTool. Used by the three tracing tests
// below to exercise CallToolProto's dispatch via the ComponentRegistry path
// (Path 2) now that the in-process tool registry has been removed.
type fakeDiscovery struct {
	tool tool.Tool
}

func (f *fakeDiscovery) DiscoverTool(_ context.Context, name string) (tool.Tool, error) {
	if f.tool != nil && f.tool.Name() == name {
		return f.tool, nil
	}
	return nil, &component.ToolNotFoundError{Name: name}
}
func (f *fakeDiscovery) DiscoverAgent(_ context.Context, _ string) (agent.Agent, error) {
	return nil, errors.New("not implemented")
}
func (f *fakeDiscovery) DiscoverPlugin(_ context.Context, _ string) (plugin.Plugin, error) {
	return nil, errors.New("not implemented")
}
func (f *fakeDiscovery) ListAgents(_ context.Context) ([]component.AgentInfo, error) {
	return nil, nil
}
func (f *fakeDiscovery) ListTools(_ context.Context) ([]component.ToolInfo, error) {
	return nil, nil
}
func (f *fakeDiscovery) ListPlugins(_ context.Context) ([]component.PluginInfo, error) {
	return nil, nil
}
func (f *fakeDiscovery) DelegateToAgent(_ context.Context, _ string, _ agent.Task, _ agent.AgentHarness) (agent.Result, error) {
	return agent.Result{}, errors.New("not implemented")
}

// TestCallToolProto_TracingAttributes verifies that tool execution creates spans
// with the required attributes: tool.name, tool.input_size, tool.duration_ms, tool.status
func TestCallToolProto_TracingAttributes(t *testing.T) {
	// Setup span recorder to capture spans
	spanRecorder := tracetest.NewSpanRecorder()
	tracerProvider := sdktrace.NewTracerProvider(
		sdktrace.WithSpanProcessor(spanRecorder),
	)
	tracer := tracerProvider.Tracer("test")

	// Create mock tool
	mockTool := &mockProtoTool{
		name:              "test-tool",
		inputMessageType:  "google.protobuf.StringValue",
		outputMessageType: "google.protobuf.StringValue",
		executeFn: func(ctx context.Context, input proto.Message) (proto.Message, error) {
			// Simulate some work
			time.Sleep(10 * time.Millisecond)
			return wrapperspb.String("output"), nil
		},
	}

	discovery := &fakeDiscovery{tool: mockTool}

	// Create harness with tracer
	llmRegistry := llm.NewLLMRegistry()
	slotManager := llm.NewSlotManager(llmRegistry)

	cfg := &HarnessConfig{
		SlotManager:     slotManager,
		RegistryAdapter: discovery,
		Tracer:          tracer,
	}
	cfg.ApplyDefaults()

	factory, err := NewHarnessFactory(*cfg)
	require.NoError(t, err)

	harness, err := factory.Create("test-agent", MissionContext{ID: "test-mission"}, TargetInfo{ID: "test-target"})
	require.NoError(t, err)

	// Execute tool
	ctx := context.Background()
	request := wrapperspb.String("input")
	response := &wrapperspb.StringValue{}

	err = harness.CallToolProto(ctx, "test-tool", request, response)
	require.NoError(t, err)

	// Verify span was created
	spans := spanRecorder.Ended()
	require.Len(t, spans, 1, "Expected exactly one span to be created")

	span := spans[0]

	// Verify span name
	assert.Equal(t, "harness.CallToolProto", span.Name())

	// Verify span status
	assert.Equal(t, codes.Ok, span.Status().Code)
	assert.Equal(t, "tool execution successful", span.Status().Description)

	// Verify required attributes are present
	attrs := span.Attributes()
	attrMap := make(map[string]attribute.Value)
	for _, attr := range attrs {
		attrMap[string(attr.Key)] = attr.Value
	}

	// Check tool.name
	assert.Contains(t, attrMap, "tool.name")
	assert.Equal(t, "test-tool", attrMap["tool.name"].AsString())

	// Check tool.input_size (should be > 0 for StringValue)
	assert.Contains(t, attrMap, "tool.input_size")
	assert.Greater(t, attrMap["tool.input_size"].AsInt64(), int64(0))

	// Check tool.duration_ms (should be >= 10ms since we sleep for 10ms)
	assert.Contains(t, attrMap, "tool.duration_ms")
	assert.GreaterOrEqual(t, attrMap["tool.duration_ms"].AsInt64(), int64(10))

	// Check tool.status
	assert.Contains(t, attrMap, "tool.status")
	assert.Equal(t, "success", attrMap["tool.status"].AsString())
}

// TestCallToolProto_TracingError verifies that errors are properly recorded in spans
func TestCallToolProto_TracingError(t *testing.T) {
	// Setup span recorder to capture spans
	spanRecorder := tracetest.NewSpanRecorder()
	tracerProvider := sdktrace.NewTracerProvider(
		sdktrace.WithSpanProcessor(spanRecorder),
	)
	tracer := tracerProvider.Tracer("test")

	// Create mock tool that returns an error
	testErr := errors.New("tool execution failed")
	mockTool := &mockProtoTool{
		name:              "failing-tool",
		inputMessageType:  "google.protobuf.Empty",
		outputMessageType: "google.protobuf.Empty",
		executeFn: func(ctx context.Context, input proto.Message) (proto.Message, error) {
			return nil, testErr
		},
	}

	discovery := &fakeDiscovery{tool: mockTool}

	// Create harness with tracer
	llmRegistry := llm.NewLLMRegistry()
	slotManager := llm.NewSlotManager(llmRegistry)

	cfg := &HarnessConfig{
		SlotManager:     slotManager,
		RegistryAdapter: discovery,
		Tracer:          tracer,
	}
	cfg.ApplyDefaults()

	factory, err := NewHarnessFactory(*cfg)
	require.NoError(t, err)

	harness, err := factory.Create("test-agent", MissionContext{ID: "test-mission"}, TargetInfo{ID: "test-target"})
	require.NoError(t, err)

	// Execute tool (should fail)
	ctx := context.Background()
	request := &emptypb.Empty{}
	response := &emptypb.Empty{}

	err = harness.CallToolProto(ctx, "failing-tool", request, response)
	require.Error(t, err)

	// Verify span was created
	spans := spanRecorder.Ended()
	require.Len(t, spans, 1, "Expected exactly one span to be created")

	span := spans[0]

	// Verify span status is error
	assert.Equal(t, codes.Error, span.Status().Code)
	assert.Contains(t, span.Status().Description, "tool execution failed")

	// Verify error was recorded
	events := span.Events()
	hasErrorEvent := false
	for _, event := range events {
		if event.Name == "exception" {
			hasErrorEvent = true
			break
		}
	}
	assert.True(t, hasErrorEvent, "Expected error event to be recorded")

	// Verify tool.status attribute is "error"
	attrs := span.Attributes()
	attrMap := make(map[string]attribute.Value)
	for _, attr := range attrs {
		attrMap[string(attr.Key)] = attr.Value
	}

	assert.Contains(t, attrMap, "tool.status")
	assert.Equal(t, "error", attrMap["tool.status"].AsString())
}

// TestCallToolProto_TracingWithNoopTracer verifies that tracing doesn't break
// when using a no-op tracer (OTel not configured)
func TestCallToolProto_TracingWithNoopTracer(t *testing.T) {
	// Create mock tool
	mockTool := &mockProtoTool{
		name:              "test-tool",
		inputMessageType:  "google.protobuf.Empty",
		outputMessageType: "google.protobuf.Empty",
		executeFn: func(ctx context.Context, input proto.Message) (proto.Message, error) {
			return &emptypb.Empty{}, nil
		},
	}

	discovery := &fakeDiscovery{tool: mockTool}

	// Create harness WITHOUT tracer (will default to no-op)
	llmRegistry := llm.NewLLMRegistry()
	slotManager := llm.NewSlotManager(llmRegistry)

	cfg := &HarnessConfig{
		SlotManager:     slotManager,
		RegistryAdapter: discovery,
		// Tracer is nil - will use no-op tracer
	}
	cfg.ApplyDefaults()

	factory, err := NewHarnessFactory(*cfg)
	require.NoError(t, err)

	harness, err := factory.Create("test-agent", MissionContext{ID: "test-mission"}, TargetInfo{ID: "test-target"})
	require.NoError(t, err)

	// Execute tool - should not panic or error due to tracing
	ctx := context.Background()
	request := &emptypb.Empty{}
	response := &emptypb.Empty{}

	err = harness.CallToolProto(ctx, "test-tool", request, response)
	assert.NoError(t, err, "Tool execution should succeed with no-op tracer")
}

// mockProtoTool is a test implementation of a tool that supports proto execution
type mockProtoTool struct {
	name              string
	description       string
	version           string
	inputMessageType  string
	outputMessageType string
	executeFn         func(context.Context, proto.Message) (proto.Message, error)
}

func (m *mockProtoTool) Name() string        { return m.name }
func (m *mockProtoTool) Description() string { return m.description }
func (m *mockProtoTool) Version() string     { return m.version }
func (m *mockProtoTool) Tags() []string      { return []string{"test"} }
func (m *mockProtoTool) InputMessageType() string {
	return m.inputMessageType
}
func (m *mockProtoTool) OutputMessageType() string {
	return m.outputMessageType
}
func (m *mockProtoTool) ExecuteProto(ctx context.Context, input proto.Message) (proto.Message, error) {
	if m.executeFn != nil {
		return m.executeFn(ctx, input)
	}
	return nil, nil
}
func (m *mockProtoTool) Health(ctx context.Context) types.HealthStatus {
	return types.Healthy("mock tool healthy")
}
