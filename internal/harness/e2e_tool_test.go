//go:build integration

package harness

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/agent"
	"github.com/zero-day-ai/gibson/internal/component"
	"github.com/zero-day-ai/gibson/internal/plugin"
	"github.com/zero-day-ai/gibson/internal/tool"
	"github.com/zero-day-ai/gibson/internal/types"
	graphragpb "github.com/zero-day-ai/sdk/api/gen/gibson/graphrag/v1"
	"github.com/zero-day-ai/sdk/graphrag"
	"github.com/zero-day-ai/sdk/protoresolver"
	sdktypes "github.com/zero-day-ai/sdk/types"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
	"google.golang.org/protobuf/types/known/anypb"
)

// TestE2ERemoteToolExecution tests the complete flow of executing a remote tool
// that is not compiled into the daemon. This validates:
// 1. Tool discovery via mock registry
// 2. ProtoResolver dynamically creating message instances from FileDescriptorSet
// 3. Tool execution via CallToolProto
// 4. Response type validation (dynamicpb.Message)
// 5. DiscoveryResult extraction from response
func TestE2ERemoteToolExecution(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	ctx := context.Background()

	// Create FileDescriptorSet for a mock remote tool
	fdsBase64, inputTypeName, outputTypeName := createMockToolFileDescriptorSet(t)

	// Create mock registry that returns our remote tool
	mockRegistry := &mockComponentDiscovery{
		tools: map[string]mockRemoteTool{
			"httpx": {
				name:                 "httpx",
				version:              "1.0.0",
				inputMessageType:     inputTypeName,
				outputMessageType:    outputTypeName,
				fileDescriptorSet:    fdsBase64,
				mockExecutionHandler: createMockToolHandler(t, inputTypeName, outputTypeName),
			},
		},
	}

	// Create harness with ProtoResolver
	harness := createHarnessWithResolver(t, mockRegistry)

	// Execute tool via CallToolProto
	t.Run("ExecuteRemoteTool", func(t *testing.T) {
		// Create input message using resolver
		resolver := harness.(*DefaultAgentHarness).resolver
		require.NotNil(t, resolver, "harness should have resolver")

		metadata := map[string]string{
			"tool_name":           "httpx",
			"file_descriptor_set": fdsBase64,
		}

		inputMsg, err := resolver.ResolveInputType(ctx, inputTypeName, metadata)
		require.NoError(t, err, "should resolve input type")
		require.NotNil(t, inputMsg, "input message should not be nil")

		// Verify input is dynamic message
		_, isDynamic := inputMsg.(*dynamicpb.Message)
		assert.True(t, isDynamic, "input should be dynamicpb.Message for remote tool")

		// Set input fields using reflection
		inputRefl := inputMsg.ProtoReflect()
		fields := inputRefl.Descriptor().Fields()

		urlField := fields.ByName("url")
		require.NotNil(t, urlField, "url field should exist")
		inputRefl.Set(urlField, protoreflect.ValueOfString("https://example.com"))

		methodField := fields.ByName("method")
		require.NotNil(t, methodField, "method field should exist")
		inputRefl.Set(methodField, protoreflect.ValueOfString("GET"))

		// Create output message using resolver
		outputMsg, err := resolver.ResolveOutputType(ctx, outputTypeName, metadata)
		require.NoError(t, err, "should resolve output type")
		require.NotNil(t, outputMsg, "output message should not be nil")

		// Verify output is dynamic message
		_, isDynamic = outputMsg.(*dynamicpb.Message)
		assert.True(t, isDynamic, "output should be dynamicpb.Message for remote tool")

		// Execute the tool
		err = harness.CallToolProto(ctx, "httpx", inputMsg, outputMsg)
		require.NoError(t, err, "tool execution should succeed")

		// Verify response fields
		outputRefl := outputMsg.ProtoReflect()
		outputFields := outputRefl.Descriptor().Fields()

		statusField := outputFields.ByName("status_code")
		require.NotNil(t, statusField, "status_code field should exist")
		assert.True(t, outputRefl.Has(statusField), "status_code should be set")
		assert.Equal(t, int32(200), outputRefl.Get(statusField).Int(), "status_code should be 200")

		bodyField := outputFields.ByName("body")
		require.NotNil(t, bodyField, "body field should exist")
		assert.True(t, outputRefl.Has(bodyField), "body should be set")
		assert.Equal(t, "response body", outputRefl.Get(bodyField).String(), "body should match")
	})

	// Validate DiscoveryResult extraction
	t.Run("ExtractDiscoveryResult", func(t *testing.T) {
		// Execute tool again to get fresh output
		resolver := harness.(*DefaultAgentHarness).resolver
		metadata := map[string]string{
			"tool_name":           "httpx",
			"file_descriptor_set": fdsBase64,
		}

		inputMsg, err := resolver.ResolveInputType(ctx, inputTypeName, metadata)
		require.NoError(t, err)

		inputRefl := inputMsg.ProtoReflect()
		urlField := inputRefl.Descriptor().Fields().ByName("url")
		inputRefl.Set(urlField, protoreflect.ValueOfString("https://test.com"))

		outputMsg, err := resolver.ResolveOutputType(ctx, outputTypeName, metadata)
		require.NoError(t, err)

		err = harness.CallToolProto(ctx, "httpx", inputMsg, outputMsg)
		require.NoError(t, err)

		// Extract DiscoveryResult using SDK function
		discovery := graphrag.ExtractDiscovery(outputMsg)
		require.NotNil(t, discovery, "should extract discovery result from dynamic message")

		// Validate discovery content
		assert.NotEmpty(t, discovery.Hosts, "should have hosts")
		assert.NotNil(t, discovery.Hosts[0].Hostname, "hostname should not be nil")
		assert.Equal(t, "test.com", *discovery.Hosts[0].Hostname, "hostname should be test.com")
	})
}

// createMockToolFileDescriptorSet creates a FileDescriptorSet for a mock HTTP tool
// Returns: (base64-encoded FDS, input type name, output type name)
func createMockToolFileDescriptorSet(t *testing.T) (string, string, string) {
	t.Helper()

	// Define google.protobuf.Any dependency
	googleProtobufAnyFile := &descriptorpb.FileDescriptorProto{
		Name:    proto.String("google/protobuf/any.proto"),
		Package: proto.String("google.protobuf"),
		MessageType: []*descriptorpb.DescriptorProto{
			{
				Name: proto.String("Any"),
				Field: []*descriptorpb.FieldDescriptorProto{
					{
						Name:   proto.String("type_url"),
						Number: proto.Int32(1),
						Type:   descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(),
						Label:  descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
					},
					{
						Name:   proto.String("value"),
						Number: proto.Int32(2),
						Type:   descriptorpb.FieldDescriptorProto_TYPE_BYTES.Enum(),
						Label:  descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
					},
				},
			},
		},
	}

	// Define graphragpb.DiscoveryResult dependency (simplified)
	graphragFile := &descriptorpb.FileDescriptorProto{
		Name:    proto.String("graphrag/discovery.proto"),
		Package: proto.String("graphrag"),
		MessageType: []*descriptorpb.DescriptorProto{
			{
				Name: proto.String("Host"),
				Field: []*descriptorpb.FieldDescriptorProto{
					{
						Name:   proto.String("hostname"),
						Number: proto.Int32(1),
						Type:   descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(),
						Label:  descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
					},
					{
						Name:   proto.String("ip_address"),
						Number: proto.Int32(2),
						Type:   descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(),
						Label:  descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
					},
				},
			},
			{
				Name: proto.String("DiscoveryResult"),
				Field: []*descriptorpb.FieldDescriptorProto{
					{
						Name:     proto.String("hosts"),
						Number:   proto.Int32(1),
						Type:     descriptorpb.FieldDescriptorProto_TYPE_MESSAGE.Enum(),
						TypeName: proto.String(".graphrag.Host"),
						Label:    descriptorpb.FieldDescriptorProto_LABEL_REPEATED.Enum(),
					},
				},
			},
		},
	}

	// Define mock tool messages
	httpxToolFile := &descriptorpb.FileDescriptorProto{
		Name:    proto.String("tools/httpx.proto"),
		Package: proto.String("toolspb"),
		Dependency: []string{
			"google/protobuf/any.proto",
			"graphrag/discovery.proto",
		},
		MessageType: []*descriptorpb.DescriptorProto{
			{
				Name: proto.String("HttpxRequest"),
				Field: []*descriptorpb.FieldDescriptorProto{
					{
						Name:   proto.String("url"),
						Number: proto.Int32(1),
						Type:   descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(),
						Label:  descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
					},
					{
						Name:   proto.String("method"),
						Number: proto.Int32(2),
						Type:   descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(),
						Label:  descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
					},
				},
			},
			{
				Name: proto.String("HttpxResponse"),
				Field: []*descriptorpb.FieldDescriptorProto{
					{
						Name:   proto.String("status_code"),
						Number: proto.Int32(1),
						Type:   descriptorpb.FieldDescriptorProto_TYPE_INT32.Enum(),
						Label:  descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
					},
					{
						Name:   proto.String("body"),
						Number: proto.Int32(2),
						Type:   descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(),
						Label:  descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
					},
					{
						Name:     proto.String("discovery_result"),
						Number:   proto.Int32(100),
						Type:     descriptorpb.FieldDescriptorProto_TYPE_MESSAGE.Enum(),
						TypeName: proto.String(".google.protobuf.Any"),
						Label:    descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
					},
				},
			},
		},
	}

	// Create FileDescriptorSet
	fds := &descriptorpb.FileDescriptorSet{
		File: []*descriptorpb.FileDescriptorProto{
			googleProtobufAnyFile,
			graphragFile,
			httpxToolFile,
		},
	}

	// Marshal to bytes
	fdsBytes, err := proto.Marshal(fds)
	require.NoError(t, err, "should marshal FileDescriptorSet")

	// Encode to base64
	fdsBase64 := base64.StdEncoding.EncodeToString(fdsBytes)

	return fdsBase64, "toolspb.HttpxRequest", "toolspb.HttpxResponse"
}

// mockRemoteTool represents a remote tool with proto schema
type mockRemoteTool struct {
	name                 string
	version              string
	inputMessageType     string
	outputMessageType    string
	fileDescriptorSet    string // base64-encoded
	mockExecutionHandler func(ctx context.Context, input proto.Message) (proto.Message, error)
}

// mockComponentDiscovery is a mock registry adapter for testing
type mockComponentDiscovery struct {
	tools map[string]mockRemoteTool
}

// DiscoverTool returns a mock gRPC tool client
func (m *mockComponentDiscovery) DiscoverTool(ctx context.Context, name string) (tool.Tool, error) {
	mockTool, ok := m.tools[name]
	if !ok {
		return nil, fmt.Errorf("tool not found: %s", name)
	}

	return &mockGRPCToolClient{
		toolName:         mockTool.name,
		toolVersion:      mockTool.version,
		inputType:        mockTool.inputMessageType,
		outputType:       mockTool.outputMessageType,
		fdsBase64:        mockTool.fileDescriptorSet,
		executionHandler: mockTool.mockExecutionHandler,
	}, nil
}

// Stub implementations for other discovery methods
func (m *mockComponentDiscovery) DiscoverAgent(ctx context.Context, name string) (agent.Agent, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockComponentDiscovery) DiscoverPlugin(ctx context.Context, name string) (plugin.Plugin, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockComponentDiscovery) ListAgents(ctx context.Context) ([]component.AgentInfo, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockComponentDiscovery) ListTools(ctx context.Context) ([]component.ToolInfo, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockComponentDiscovery) ListPlugins(ctx context.Context) ([]component.PluginInfo, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockComponentDiscovery) DelegateToAgent(ctx context.Context, name string, task agent.Task, harness agent.AgentHarness) (agent.Result, error) {
	return agent.Result{}, fmt.Errorf("not implemented")
}

// mockGRPCToolClient simulates a gRPC tool client for testing
type mockGRPCToolClient struct {
	toolName         string
	toolVersion      string
	inputType        string
	outputType       string
	fdsBase64        string
	executionHandler func(ctx context.Context, input proto.Message) (proto.Message, error)
}

func (m *mockGRPCToolClient) Name() string        { return m.toolName }
func (m *mockGRPCToolClient) Description() string { return "Mock HTTP tool" }
func (m *mockGRPCToolClient) Version() string     { return m.toolVersion }
func (m *mockGRPCToolClient) Tags() []string      { return []string{"http", "network"} }

func (m *mockGRPCToolClient) InputMessageType() string  { return m.inputType }
func (m *mockGRPCToolClient) OutputMessageType() string { return m.outputType }

func (m *mockGRPCToolClient) Metadata() map[string]string {
	return map[string]string{
		"file_descriptor_set": m.fdsBase64,
		"tool_name":           m.toolName,
	}
}

func (m *mockGRPCToolClient) ExecuteProto(ctx context.Context, input proto.Message) (proto.Message, error) {
	if m.executionHandler != nil {
		return m.executionHandler(ctx, input)
	}
	return nil, fmt.Errorf("no execution handler configured")
}

// Stub implementations for legacy methods
func (m *mockGRPCToolClient) GetCapabilities(ctx context.Context) (*sdktypes.Capabilities, error) {
	return &sdktypes.Capabilities{}, nil
}

func (m *mockGRPCToolClient) Health(ctx context.Context) types.HealthStatus {
	return types.Healthy("ok")
}

// createMockToolHandler creates a handler that validates input and returns mock output
func createMockToolHandler(t *testing.T, inputTypeName, outputTypeName string) func(ctx context.Context, input proto.Message) (proto.Message, error) {
	return func(ctx context.Context, input proto.Message) (proto.Message, error) {
		t.Helper()

		// Validate input type
		actualInputType := string(input.ProtoReflect().Descriptor().FullName())
		if actualInputType != inputTypeName {
			return nil, fmt.Errorf("unexpected input type: got %s, want %s", actualInputType, inputTypeName)
		}

		// Extract URL from input using reflection
		inputRefl := input.ProtoReflect()
		urlField := inputRefl.Descriptor().Fields().ByName("url")
		if urlField == nil {
			return nil, fmt.Errorf("url field not found in input")
		}
		url := inputRefl.Get(urlField).String()

		// Create output message dynamically
		// First, decode the FDS that was used to create this message
		// We'll reconstruct it from the input's descriptor
		outputDescriptor := createOutputDescriptorFromInput(input)
		outputMsg := dynamicpb.NewMessage(outputDescriptor)
		outputRefl := outputMsg.ProtoReflect()

		// Set status_code field
		statusField := outputRefl.Descriptor().Fields().ByName("status_code")
		if statusField != nil {
			outputRefl.Set(statusField, protoreflect.ValueOfInt32(200))
		}

		// Set body field
		bodyField := outputRefl.Descriptor().Fields().ByName("body")
		if bodyField != nil {
			outputRefl.Set(bodyField, protoreflect.ValueOfString("response body"))
		}

		// Create and set DiscoveryResult in field 100
		discoveryField := outputRefl.Descriptor().Fields().ByNumber(100)
		if discoveryField != nil {
			// Create a DiscoveryResult
			hostname := extractHostFromURL(url)
			discovery := &graphragpb.DiscoveryResult{
				Hosts: []*graphragpb.Host{
					{
						Hostname: &hostname,
					},
				},
			}

			// Wrap in google.protobuf.Any
			anyMsg, err := anypb.New(discovery)
			if err != nil {
				return nil, fmt.Errorf("failed to create Any message: %w", err)
			}

			outputRefl.Set(discoveryField, protoreflect.ValueOfMessage(anyMsg.ProtoReflect()))
		}

		return outputMsg, nil
	}
}

// createOutputDescriptorFromInput creates the output descriptor based on input descriptor's file
func createOutputDescriptorFromInput(input proto.Message) protoreflect.MessageDescriptor {
	// Get the file descriptor from the input message
	inputDesc := input.ProtoReflect().Descriptor()
	fileDesc := inputDesc.ParentFile()

	// Find the HttpxResponse message in the same file
	messages := fileDesc.Messages()
	for i := 0; i < messages.Len(); i++ {
		msg := messages.Get(i)
		if msg.Name() == "HttpxResponse" {
			return msg
		}
	}

	panic("HttpxResponse not found in file descriptor")
}

// extractHostFromURL extracts hostname from URL
func extractHostFromURL(url string) string {
	// Simple extraction for testing
	if len(url) > 8 && url[:8] == "https://" {
		return url[8:]
	}
	if len(url) > 7 && url[:7] == "http://" {
		return url[7:]
	}
	return url
}

// createHarnessWithResolver creates a test harness with ProtoResolver configured
func createHarnessWithResolver(t *testing.T, mockRegistry component.ComponentDiscovery) AgentHarness {
	t.Helper()

	// Create ProtoResolver with default config
	resolver := protoresolver.NewDefaultProtoResolver(protoresolver.ProtoResolverConfig{
		CacheMaxEntries: 100,
		StrictMode:      false,
		LogFallbacks:    true,
	})

	// Create minimal harness with resolver
	harness := &DefaultAgentHarness{
		pluginRegistry:  plugin.NewPluginRegistry(nil), // nil event bus for testing
		registryAdapter: mockRegistry,
		resolver:        resolver,
		tracer:          noop.NewTracerProvider().Tracer("test"),
		logger:          slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug})),
		metrics:         &noopMetricsRecorder{},
		missionCtx: MissionContext{
			ID:   types.ID("test-mission"),
			Name: "test",
		},
	}

	return harness
}

// noopMetricsRecorder is a no-op metrics recorder for testing
type noopMetricsRecorder struct{}

func (n *noopMetricsRecorder) RecordCounter(name string, value int64, tags map[string]string)     {}
func (n *noopMetricsRecorder) RecordGauge(name string, value float64, tags map[string]string)     {}
func (n *noopMetricsRecorder) RecordHistogram(name string, value float64, tags map[string]string) {}
func (n *noopMetricsRecorder) RecordDuration(name string, value float64, tags map[string]string)  {}
func (n *noopMetricsRecorder) StartTimer(name string, tags map[string]string) func() {
	return func() {}
}
func (n *noopMetricsRecorder) RecordLLMCompletion(provider, model string, promptTokens, completionTokens int) {
}
func (n *noopMetricsRecorder) RecordToolExecution(toolName string, durationMs float64, success bool) {
}
func (n *noopMetricsRecorder) RecordFindingSubmitted(severity, category string) {}
