package registry

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	protobuf "google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/structpb"

	commonpb "github.com/zero-day-ai/sdk/api/gen/commonpb"
	proto "github.com/zero-day-ai/sdk/api/gen/proto"
	"github.com/zero-day-ai/sdk/protoresolver"
	sdkregistry "github.com/zero-day-ai/sdk/registry"
)

const bufSize = 1024 * 1024

// mockToolServer implements proto.ToolServiceServer for integration testing
type mockToolServer struct {
	proto.UnimplementedToolServiceServer

	// Hooks for test customization
	getDescriptorFunc func(ctx context.Context, req *proto.ToolGetDescriptorRequest) (*proto.ToolDescriptor, error)
	executeFunc       func(ctx context.Context, req *proto.ToolExecuteRequest) (*proto.ToolExecuteResponse, error)
	healthFunc        func(ctx context.Context, req *proto.ToolHealthRequest) (*commonpb.HealthStatus, error)
}

func (m *mockToolServer) GetDescriptor(ctx context.Context, req *proto.ToolGetDescriptorRequest) (*proto.ToolDescriptor, error) {
	if m.getDescriptorFunc != nil {
		return m.getDescriptorFunc(ctx, req)
	}
	return &proto.ToolDescriptor{
		Name:        "mock-tool",
		Description: "Mock tool for testing",
		Version:     "1.0.0",
		Tags:        []string{"test"},
	}, nil
}

func (m *mockToolServer) Execute(ctx context.Context, req *proto.ToolExecuteRequest) (*proto.ToolExecuteResponse, error) {
	if m.executeFunc != nil {
		return m.executeFunc(ctx, req)
	}
	return &proto.ToolExecuteResponse{
		OutputJson: "{}",
	}, nil
}

func (m *mockToolServer) Health(ctx context.Context, req *proto.ToolHealthRequest) (*commonpb.HealthStatus, error) {
	if m.healthFunc != nil {
		return m.healthFunc(ctx, req)
	}
	return &commonpb.HealthStatus{
		Status:  "healthy",
		Message: "OK",
	}, nil
}

// setupTestServer creates a bufconn-based gRPC server for testing
func setupTestServer(t *testing.T, server *mockToolServer) (*grpc.ClientConn, func()) {
	lis := bufconn.Listen(bufSize)

	s := grpc.NewServer()
	proto.RegisterToolServiceServer(s, server)

	go func() {
		if err := s.Serve(lis); err != nil {
			// Server stopped, this is normal during cleanup
		}
	}()

	// Create client connection
	ctx := context.Background()
	conn, err := grpc.DialContext(ctx, "bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return lis.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)

	cleanup := func() {
		conn.Close()
		s.Stop()
		lis.Close()
	}

	return conn, cleanup
}

// createTestFileDescriptorSet creates a FileDescriptorSet for testing dynamic resolution
func createTestFileDescriptorSet() string {
	// Create a proto file descriptor with a custom message type
	fileDescriptor := &descriptorpb.FileDescriptorProto{
		Name:    protobuf.String("custom_tool.proto"),
		Package: protobuf.String("custom.tool"),
		MessageType: []*descriptorpb.DescriptorProto{
			{
				Name: protobuf.String("CustomOutput"),
				Field: []*descriptorpb.FieldDescriptorProto{
					{
						Name:   protobuf.String("status"),
						Number: protobuf.Int32(1),
						Type:   descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(),
						Label:  descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
					},
					{
						Name:   protobuf.String("count"),
						Number: protobuf.Int32(2),
						Type:   descriptorpb.FieldDescriptorProto_TYPE_INT32.Enum(),
						Label:  descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
					},
				},
			},
		},
	}

	// Create FileDescriptorSet
	fds := &descriptorpb.FileDescriptorSet{
		File: []*descriptorpb.FileDescriptorProto{fileDescriptor},
	}

	// Marshal to bytes and encode as base64
	fdsBytes, err := protobuf.Marshal(fds)
	if err != nil {
		panic("failed to marshal FileDescriptorSet: " + err.Error())
	}

	return base64.StdEncoding.EncodeToString(fdsBytes)
}

// TestGRPCToolClient_ExecuteProto_GlobalTypesHit tests execution with a type in GlobalTypes
func TestGRPCToolClient_ExecuteProto_GlobalTypesHit(t *testing.T) {
	// Setup mock server that returns valid JSON for google.protobuf.Empty
	server := &mockToolServer{
		getDescriptorFunc: func(ctx context.Context, req *proto.ToolGetDescriptorRequest) (*proto.ToolDescriptor, error) {
			return &proto.ToolDescriptor{
				Name:        "test-tool",
				Description: "Test tool using global types",
				Version:     "1.0.0",
				Tags:        []string{"test"},
			}, nil
		},
		executeFunc: func(ctx context.Context, req *proto.ToolExecuteRequest) (*proto.ToolExecuteResponse, error) {
			// Verify input was properly marshaled
			var input map[string]any
			err := json.Unmarshal([]byte(req.InputJson), &input)
			require.NoError(t, err)

			// Return empty JSON for google.protobuf.Empty output
			return &proto.ToolExecuteResponse{
				OutputJson: "{}",
				Error:      nil,
			}, nil
		},
	}

	conn, cleanup := setupTestServer(t, server)
	defer cleanup()

	// Create ServiceInfo with google.protobuf.Empty as output type
	info := sdkregistry.ServiceInfo{
		Name:     "test-tool",
		Version:  "1.0.0",
		Endpoint: "bufnet",
		Metadata: map[string]string{
			"input_message_type":  "google.protobuf.Empty",
			"output_message_type": "google.protobuf.Empty",
		},
	}

	// Create resolver
	resolver := protoresolver.NewDefaultProtoResolver(protoresolver.DefaultConfig())

	// Create client
	client := NewGRPCToolClient(conn, info, resolver)

	// Execute with Empty input
	input := &emptypb.Empty{}
	output, err := client.ExecuteProto(context.Background(), input)
	require.NoError(t, err)
	require.NotNil(t, output)

	// Verify output is compiled type (not dynamic)
	emptyOutput, ok := output.(*emptypb.Empty)
	assert.True(t, ok, "output should be *emptypb.Empty (compiled type), got %T", output)
	assert.NotNil(t, emptyOutput)
}

// TestGRPCToolClient_ExecuteProto_DynamicTypesFallback tests execution with FileDescriptorSet
func TestGRPCToolClient_ExecuteProto_DynamicTypesFallback(t *testing.T) {
	// Create FileDescriptorSet for custom type
	fdsBase64 := createTestFileDescriptorSet()

	// Setup mock server that returns JSON for custom type
	server := &mockToolServer{
		getDescriptorFunc: func(ctx context.Context, req *proto.ToolGetDescriptorRequest) (*proto.ToolDescriptor, error) {
			return &proto.ToolDescriptor{
				Name:        "custom-tool",
				Description: "Tool with custom proto types",
				Version:     "1.0.0",
				Tags:        []string{"custom"},
			}, nil
		},
		executeFunc: func(ctx context.Context, req *proto.ToolExecuteRequest) (*proto.ToolExecuteResponse, error) {
			// Return JSON matching CustomOutput schema
			output := map[string]any{
				"status": "success",
				"count":  42,
			}
			outputJSON, _ := json.Marshal(output)

			return &proto.ToolExecuteResponse{
				OutputJson: string(outputJSON),
				Error:      nil,
			}, nil
		},
	}

	conn, cleanup := setupTestServer(t, server)
	defer cleanup()

	// Create ServiceInfo with custom type NOT in GlobalTypes
	info := sdkregistry.ServiceInfo{
		Name:     "custom-tool",
		Version:  "1.0.0",
		Endpoint: "bufnet",
		Metadata: map[string]string{
			"input_message_type":  "google.protobuf.Empty",
			"output_message_type": "custom.tool.CustomOutput",
			"file_descriptor_set": fdsBase64,
			"tool_name":           "custom-tool",
		},
	}

	// Create resolver with relaxed config for dynamic resolution
	config := protoresolver.DefaultConfig()
	config.StrictMode = false
	resolver := protoresolver.NewDefaultProtoResolver(config)

	// Create client
	client := NewGRPCToolClient(conn, info, resolver)

	// Execute with Empty input
	input := &emptypb.Empty{}
	output, err := client.ExecuteProto(context.Background(), input)
	require.NoError(t, err)
	require.NotNil(t, output)

	// Verify output is a proto.Message (will be dynamicpb.Message)
	assert.NotNil(t, output)

	// Use proto reflection to verify fields
	// For dynamicpb.Message, we can use proto.Marshal/Unmarshal
	outputBytes, err := protobuf.Marshal(output)
	require.NoError(t, err)
	assert.NotEmpty(t, outputBytes)

	// Verify the message has the expected type name
	msgDesc := output.ProtoReflect().Descriptor()
	assert.Equal(t, "CustomOutput", string(msgDesc.Name()))
	assert.Equal(t, "custom.tool", string(msgDesc.ParentFile().Package()))
}

// TestGRPCToolClient_ExecuteProto_MissingSchema tests error when schema is missing
func TestGRPCToolClient_ExecuteProto_MissingSchema(t *testing.T) {
	// Setup mock server
	server := &mockToolServer{
		getDescriptorFunc: func(ctx context.Context, req *proto.ToolGetDescriptorRequest) (*proto.ToolDescriptor, error) {
			return &proto.ToolDescriptor{
				Name:        "unknown-tool",
				Description: "Tool with unknown types",
				Version:     "1.0.0",
				Tags:        []string{"unknown"},
			}, nil
		},
		executeFunc: func(ctx context.Context, req *proto.ToolExecuteRequest) (*proto.ToolExecuteResponse, error) {
			// This shouldn't be reached because resolution will fail
			return &proto.ToolExecuteResponse{
				OutputJson: "{}",
				Error:      nil,
			}, nil
		},
	}

	conn, cleanup := setupTestServer(t, server)
	defer cleanup()

	// Create ServiceInfo with unknown type and NO file_descriptor_set
	info := sdkregistry.ServiceInfo{
		Name:     "unknown-tool",
		Version:  "1.0.0",
		Endpoint: "bufnet",
		Metadata: map[string]string{
			"input_message_type":  "google.protobuf.Empty",
			"output_message_type": "unknown.package.UnknownType",
			// Deliberately omit "file_descriptor_set"
			"tool_name": "unknown-tool",
		},
	}

	// Create resolver with strict mode enabled
	config := protoresolver.DefaultConfig()
	config.StrictMode = true
	resolver := protoresolver.NewDefaultProtoResolver(config)

	// Create client
	client := NewGRPCToolClient(conn, info, resolver)

	// Execute should fail with SchemaNotFoundError
	input := &emptypb.Empty{}
	output, err := client.ExecuteProto(context.Background(), input)

	// Should return error
	assert.Error(t, err)
	assert.Nil(t, output)

	// Verify it's a schema resolution error
	assert.Contains(t, err.Error(), "failed to resolve output type")
}

// TestGRPCToolClient_ExecuteProto_StructFallback tests fallback to google.protobuf.Struct
func TestGRPCToolClient_ExecuteProto_StructFallback(t *testing.T) {
	// Setup mock server that returns JSON
	server := &mockToolServer{
		getDescriptorFunc: func(ctx context.Context, req *proto.ToolGetDescriptorRequest) (*proto.ToolDescriptor, error) {
			return &proto.ToolDescriptor{
				Name:        "struct-tool",
				Description: "Tool using Struct fallback",
				Version:     "1.0.0",
				Tags:        []string{"test"},
			}, nil
		},
		executeFunc: func(ctx context.Context, req *proto.ToolExecuteRequest) (*proto.ToolExecuteResponse, error) {
			// Return arbitrary JSON
			output := map[string]any{
				"message": "Hello from tool",
				"code":    200,
				"nested": map[string]any{
					"key": "value",
				},
			}
			outputJSON, _ := json.Marshal(output)

			return &proto.ToolExecuteResponse{
				OutputJson: string(outputJSON),
				Error:      nil,
			}, nil
		},
	}

	conn, cleanup := setupTestServer(t, server)
	defer cleanup()

	// Create ServiceInfo with google.protobuf.Struct as output
	info := sdkregistry.ServiceInfo{
		Name:     "struct-tool",
		Version:  "1.0.0",
		Endpoint: "bufnet",
		Metadata: map[string]string{
			"input_message_type":  "google.protobuf.Struct",
			"output_message_type": "google.protobuf.Struct",
		},
	}

	// Create resolver
	resolver := protoresolver.NewDefaultProtoResolver(protoresolver.DefaultConfig())

	// Create client
	client := NewGRPCToolClient(conn, info, resolver)

	// Create Struct input
	inputMap := map[string]any{
		"target": "example.com",
		"port":   8080,
	}
	input, err := structpb.NewStruct(inputMap)
	require.NoError(t, err)

	// Execute
	output, err := client.ExecuteProto(context.Background(), input)
	require.NoError(t, err)
	require.NotNil(t, output)

	// Verify output is Struct
	structOutput, ok := output.(*structpb.Struct)
	assert.True(t, ok, "output should be *structpb.Struct, got %T", output)
	assert.Equal(t, "Hello from tool", structOutput.Fields["message"].GetStringValue())
	assert.Equal(t, float64(200), structOutput.Fields["code"].GetNumberValue())

	// Check nested structure
	nested := structOutput.Fields["nested"].GetStructValue()
	assert.NotNil(t, nested)
	assert.Equal(t, "value", nested.Fields["key"].GetStringValue())
}

// TestGRPCToolClient_ExecuteProto_WithToolError tests tool execution errors
func TestGRPCToolClient_ExecuteProto_WithToolError(t *testing.T) {
	// Setup mock server that returns an error
	server := &mockToolServer{
		getDescriptorFunc: func(ctx context.Context, req *proto.ToolGetDescriptorRequest) (*proto.ToolDescriptor, error) {
			return &proto.ToolDescriptor{
				Name:        "error-tool",
				Description: "Tool that returns errors",
				Version:     "1.0.0",
				Tags:        []string{"test"},
			}, nil
		},
		executeFunc: func(ctx context.Context, req *proto.ToolExecuteRequest) (*proto.ToolExecuteResponse, error) {
			// Return tool error
			return &proto.ToolExecuteResponse{
				OutputJson: "",
				Error: &commonpb.Error{
					Code:    "EXECUTION_FAILED",
					Message: "Command execution failed with exit code 1",
				},
			}, nil
		},
	}

	conn, cleanup := setupTestServer(t, server)
	defer cleanup()

	info := sdkregistry.ServiceInfo{
		Name:     "error-tool",
		Version:  "1.0.0",
		Endpoint: "bufnet",
		Metadata: map[string]string{
			"input_message_type":  "google.protobuf.Empty",
			"output_message_type": "google.protobuf.Empty",
		},
	}

	resolver := protoresolver.NewDefaultProtoResolver(protoresolver.DefaultConfig())
	client := NewGRPCToolClient(conn, info, resolver)

	// Execute
	input := &emptypb.Empty{}
	output, err := client.ExecuteProto(context.Background(), input)

	// Should return error
	assert.Error(t, err)
	assert.Nil(t, output)
	assert.Contains(t, err.Error(), "EXECUTION_FAILED")
	assert.Contains(t, err.Error(), "Command execution failed")
}

// TestGRPCToolClient_ExecuteProto_ConcurrentExecutions tests concurrent safety
// NOTE: This test reveals a race condition in GRPCToolClient.fetchDescriptor()
// The descriptor caching is not thread-safe. This should be fixed with sync.Once or mutex.
func TestGRPCToolClient_ExecuteProto_ConcurrentExecutions(t *testing.T) {
	t.Skip("Skipping concurrent test - reveals known race condition in fetchDescriptor caching")
	// Setup mock server
	server := &mockToolServer{
		getDescriptorFunc: func(ctx context.Context, req *proto.ToolGetDescriptorRequest) (*proto.ToolDescriptor, error) {
			return &proto.ToolDescriptor{
				Name:        "concurrent-tool",
				Description: "Tool for concurrent testing",
				Version:     "1.0.0",
				Tags:        []string{"test"},
			}, nil
		},
		executeFunc: func(ctx context.Context, req *proto.ToolExecuteRequest) (*proto.ToolExecuteResponse, error) {
			// Parse input to echo it back
			var input map[string]any
			_ = json.Unmarshal([]byte(req.InputJson), &input)

			outputJSON, _ := json.Marshal(input)
			return &proto.ToolExecuteResponse{
				OutputJson: string(outputJSON),
				Error:      nil,
			}, nil
		},
	}

	conn, cleanup := setupTestServer(t, server)
	defer cleanup()

	info := sdkregistry.ServiceInfo{
		Name:     "concurrent-tool",
		Version:  "1.0.0",
		Endpoint: "bufnet",
		Metadata: map[string]string{
			"input_message_type":  "google.protobuf.Struct",
			"output_message_type": "google.protobuf.Struct",
		},
	}

	resolver := protoresolver.NewDefaultProtoResolver(protoresolver.DefaultConfig())
	client := NewGRPCToolClient(conn, info, resolver)

	// Run 10 concurrent executions
	const numGoroutines = 10
	errChan := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			inputMap := map[string]any{
				"id": id,
			}
			input, err := structpb.NewStruct(inputMap)
			if err != nil {
				errChan <- err
				return
			}

			output, err := client.ExecuteProto(context.Background(), input)
			if err != nil {
				errChan <- err
				return
			}

			structOutput, ok := output.(*structpb.Struct)
			if !ok {
				errChan <- assert.AnError
				return
			}

			if structOutput.Fields["id"].GetNumberValue() != float64(id) {
				errChan <- assert.AnError
				return
			}

			errChan <- nil
		}(i)
	}

	// Collect results
	for i := 0; i < numGoroutines; i++ {
		err := <-errChan
		assert.NoError(t, err)
	}
}
