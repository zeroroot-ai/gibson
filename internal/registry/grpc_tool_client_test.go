package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/zero-day-ai/gibson/internal/schema"
	"github.com/zero-day-ai/gibson/internal/types"
	proto "github.com/zero-day-ai/sdk/api/gen/proto"
	commonpb "github.com/zero-day-ai/sdk/api/gen/commonpb"
	sdkregistry "github.com/zero-day-ai/sdk/registry"
)

// mockToolServiceClient implements proto.ToolServiceClient for testing
type mockToolServiceClient struct {
	proto.ToolServiceClient

	// Hooks for test customization
	getDescriptorFunc func(ctx context.Context, req *proto.ToolGetDescriptorRequest, opts ...grpc.CallOption) (*proto.ToolDescriptor, error)
	executeFunc       func(ctx context.Context, req *proto.ToolExecuteRequest, opts ...grpc.CallOption) (*proto.ToolExecuteResponse, error)
	healthFunc        func(ctx context.Context, req *proto.ToolHealthRequest, opts ...grpc.CallOption) (*proto.HealthStatus, error)
}

func (m *mockToolServiceClient) GetDescriptor(ctx context.Context, req *proto.ToolGetDescriptorRequest, opts ...grpc.CallOption) (*proto.ToolDescriptor, error) {
	if m.getDescriptorFunc != nil {
		return m.getDescriptorFunc(ctx, req, opts...)
	}
	return nil, fmt.Errorf("GetDescriptor not implemented in mock")
}

func (m *mockToolServiceClient) Execute(ctx context.Context, req *proto.ToolExecuteRequest, opts ...grpc.CallOption) (*proto.ToolExecuteResponse, error) {
	if m.executeFunc != nil {
		return m.executeFunc(ctx, req, opts...)
	}
	return nil, fmt.Errorf("Execute not implemented in mock")
}

func (m *mockToolServiceClient) Health(ctx context.Context, req *proto.ToolHealthRequest, opts ...grpc.CallOption) (*proto.HealthStatus, error) {
	if m.healthFunc != nil {
		return m.healthFunc(ctx, req, opts...)
	}
	return nil, fmt.Errorf("Health not implemented in mock")
}

// Helper function to create a test GRPCToolClient with mock client
func createTestToolClient(mockClient *mockToolServiceClient) *GRPCToolClient {
	info := sdkregistry.ServiceInfo{
		Name:     "test-tool",
		Version:  "1.0.0",
		Endpoint: "localhost:50051",
		Metadata: map[string]string{
			"description": "A test tool",
			"tags":        "network,scanner,test",
		},
	}

	client := &GRPCToolClient{
		conn:   nil, // Not needed for these tests
		client: mockClient,
		info:   info,
	}

	return client
}

func TestGRPCToolClient_Name(t *testing.T) {
	mockClient := &mockToolServiceClient{}
	client := createTestToolClient(mockClient)

	assert.Equal(t, "test-tool", client.Name())
}

func TestGRPCToolClient_Version(t *testing.T) {
	mockClient := &mockToolServiceClient{}
	client := createTestToolClient(mockClient)

	assert.Equal(t, "1.0.0", client.Version())
}

func TestGRPCToolClient_Description_FromMetadata(t *testing.T) {
	mockClient := &mockToolServiceClient{}
	client := createTestToolClient(mockClient)

	// Should get description from metadata when descriptor not loaded
	assert.Equal(t, "A test tool", client.Description())
}

func TestGRPCToolClient_Description_FromDescriptor(t *testing.T) {
	mockClient := &mockToolServiceClient{}
	client := createTestToolClient(mockClient)

	// Set descriptor directly
	client.descriptor = &toolDescriptor{
		Description: "Description from descriptor",
	}

	// Should use descriptor description when available
	assert.Equal(t, "Description from descriptor", client.Description())
}

func TestGRPCToolClient_Tags_FromMetadata(t *testing.T) {
	mockClient := &mockToolServiceClient{}
	client := createTestToolClient(mockClient)

	expected := []string{"network", "scanner", "test"}
	assert.Equal(t, expected, client.Tags())
}

func TestGRPCToolClient_Tags_FromDescriptor(t *testing.T) {
	mockClient := &mockToolServiceClient{}
	client := createTestToolClient(mockClient)

	// Set descriptor directly
	client.descriptor = &toolDescriptor{
		Tags: []string{"from", "descriptor"},
	}

	expected := []string{"from", "descriptor"}
	assert.Equal(t, expected, client.Tags())
}

func TestGRPCToolClient_InputSchema(t *testing.T) {
	inputSchemaJSON := `{
		"type": "object",
		"properties": {
			"target": {"type": "string"},
			"port": {"type": "integer"}
		},
		"required": ["target"]
	}`

	mockClient := &mockToolServiceClient{
		getDescriptorFunc: func(ctx context.Context, req *proto.ToolGetDescriptorRequest, opts ...grpc.CallOption) (*proto.ToolDescriptor, error) {
			return &proto.ToolDescriptor{
				Name:        "test-tool",
				Description: "Test tool",
				Version:     "1.0.0",
				Tags:        []string{"test"},
				InputSchema: &commonpb.JSONSchema{
					Json: inputSchemaJSON,
				},
				OutputSchema: &commonpb.JSONSchema{
					Json: `{"type": "object"}`,
				},
			}, nil
		},
	}

	client := createTestToolClient(mockClient)
	schema := client.InputSchema()

	assert.Equal(t, "object", schema.Type)
	assert.Contains(t, schema.Properties, "target")
	assert.Contains(t, schema.Properties, "port")
	assert.Equal(t, []string{"target"}, schema.Required)
}

func TestGRPCToolClient_OutputSchema(t *testing.T) {
	outputSchemaJSON := `{
		"type": "object",
		"properties": {
			"result": {"type": "string"},
			"exitCode": {"type": "integer"}
		},
		"required": ["result"]
	}`

	mockClient := &mockToolServiceClient{
		getDescriptorFunc: func(ctx context.Context, req *proto.ToolGetDescriptorRequest, opts ...grpc.CallOption) (*proto.ToolDescriptor, error) {
			return &proto.ToolDescriptor{
				Name:        "test-tool",
				Description: "Test tool",
				Version:     "1.0.0",
				Tags:        []string{"test"},
				InputSchema: &commonpb.JSONSchema{
					Json: `{"type": "object"}`,
				},
				OutputSchema: &commonpb.JSONSchema{
					Json: outputSchemaJSON,
				},
			}, nil
		},
	}

	client := createTestToolClient(mockClient)
	schema := client.OutputSchema()

	assert.Equal(t, "object", schema.Type)
	assert.Contains(t, schema.Properties, "result")
	assert.Contains(t, schema.Properties, "exitCode")
	assert.Equal(t, []string{"result"}, schema.Required)
}

func TestGRPCToolClient_Execute_Success(t *testing.T) {
	mockClient := &mockToolServiceClient{
		executeFunc: func(ctx context.Context, req *proto.ToolExecuteRequest, opts ...grpc.CallOption) (*proto.ToolExecuteResponse, error) {
			// Verify input was marshaled
			var input map[string]any
			err := json.Unmarshal([]byte(req.InputJson), &input)
			require.NoError(t, err)
			assert.Equal(t, "example.com", input["target"])

			// Return success response
			output := map[string]any{
				"result":   "success",
				"exitCode": 0,
			}
			outputJSON, _ := json.Marshal(output)

			return &proto.ToolExecuteResponse{
				OutputJson: string(outputJSON),
				Error:      nil,
			}, nil
		},
	}

	client := createTestToolClient(mockClient)
	ctx := context.Background()

	input := map[string]any{
		"target": "example.com",
		"port":   80,
	}

	output, err := client.Execute(ctx, input)
	require.NoError(t, err)
	assert.Equal(t, "success", output["result"])
	assert.Equal(t, float64(0), output["exitCode"]) // JSON numbers unmarshal as float64
}

func TestGRPCToolClient_Execute_WithError(t *testing.T) {
	mockClient := &mockToolServiceClient{
		executeFunc: func(ctx context.Context, req *proto.ToolExecuteRequest, opts ...grpc.CallOption) (*proto.ToolExecuteResponse, error) {
			// Return error response
			return &proto.ToolExecuteResponse{
				OutputJson: "",
				Error: &proto.Error{
					Code:    "EXECUTION_FAILED",
					Message: "Failed to scan target",
				},
			}, nil
		},
	}

	client := createTestToolClient(mockClient)
	ctx := context.Background()

	input := map[string]any{
		"target": "example.com",
	}

	output, err := client.Execute(ctx, input)
	assert.Error(t, err)
	assert.Nil(t, output)
	assert.Contains(t, err.Error(), "EXECUTION_FAILED")
	assert.Contains(t, err.Error(), "Failed to scan target")
}

func TestGRPCToolClient_Execute_RPCError(t *testing.T) {
	mockClient := &mockToolServiceClient{
		executeFunc: func(ctx context.Context, req *proto.ToolExecuteRequest, opts ...grpc.CallOption) (*proto.ToolExecuteResponse, error) {
			return nil, fmt.Errorf("connection refused")
		},
	}

	client := createTestToolClient(mockClient)
	ctx := context.Background()

	input := map[string]any{
		"target": "example.com",
	}

	output, err := client.Execute(ctx, input)
	assert.Error(t, err)
	assert.Nil(t, output)
	assert.Contains(t, err.Error(), "tool execution failed")
	assert.Contains(t, err.Error(), "connection refused")
}

func TestGRPCToolClient_Execute_MarshalError(t *testing.T) {
	mockClient := &mockToolServiceClient{}
	client := createTestToolClient(mockClient)
	ctx := context.Background()

	// Create input that can't be marshaled to JSON
	input := map[string]any{
		"invalid": make(chan int), // channels can't be marshaled to JSON
	}

	output, err := client.Execute(ctx, input)
	assert.Error(t, err)
	assert.Nil(t, output)
	assert.Contains(t, err.Error(), "failed to marshal input")
}

func TestGRPCToolClient_Execute_UnmarshalError(t *testing.T) {
	mockClient := &mockToolServiceClient{
		executeFunc: func(ctx context.Context, req *proto.ToolExecuteRequest, opts ...grpc.CallOption) (*proto.ToolExecuteResponse, error) {
			// Return invalid JSON
			return &proto.ToolExecuteResponse{
				OutputJson: "{invalid json}",
				Error:      nil,
			}, nil
		},
	}

	client := createTestToolClient(mockClient)
	ctx := context.Background()

	input := map[string]any{
		"target": "example.com",
	}

	output, err := client.Execute(ctx, input)
	assert.Error(t, err)
	assert.Nil(t, output)
	assert.Contains(t, err.Error(), "failed to unmarshal output")
}

func TestGRPCToolClient_Health_Healthy(t *testing.T) {
	mockClient := &mockToolServiceClient{
		healthFunc: func(ctx context.Context, req *proto.ToolHealthRequest, opts ...grpc.CallOption) (*proto.HealthStatus, error) {
			return &proto.HealthStatus{
				State:   "healthy",
				Message: "All systems operational",
			}, nil
		},
	}

	client := createTestToolClient(mockClient)
	ctx := context.Background()

	status := client.Health(ctx)
	assert.Equal(t, types.HealthStateHealthy, status.State)
	assert.Equal(t, "All systems operational", status.Message)
}

func TestGRPCToolClient_Health_Degraded(t *testing.T) {
	mockClient := &mockToolServiceClient{
		healthFunc: func(ctx context.Context, req *proto.ToolHealthRequest, opts ...grpc.CallOption) (*proto.HealthStatus, error) {
			return &proto.HealthStatus{
				State:   "degraded",
				Message: "Some features unavailable",
			}, nil
		},
	}

	client := createTestToolClient(mockClient)
	ctx := context.Background()

	status := client.Health(ctx)
	assert.Equal(t, types.HealthStateDegraded, status.State)
	assert.Equal(t, "Some features unavailable", status.Message)
}

func TestGRPCToolClient_Health_Unhealthy(t *testing.T) {
	mockClient := &mockToolServiceClient{
		healthFunc: func(ctx context.Context, req *proto.ToolHealthRequest, opts ...grpc.CallOption) (*proto.HealthStatus, error) {
			return &proto.HealthStatus{
				State:   "unhealthy",
				Message: "Service down",
			}, nil
		},
	}

	client := createTestToolClient(mockClient)
	ctx := context.Background()

	status := client.Health(ctx)
	assert.Equal(t, types.HealthStateUnhealthy, status.State)
	assert.Equal(t, "Service down", status.Message)
}

func TestGRPCToolClient_Health_RPCError(t *testing.T) {
	mockClient := &mockToolServiceClient{
		healthFunc: func(ctx context.Context, req *proto.ToolHealthRequest, opts ...grpc.CallOption) (*proto.HealthStatus, error) {
			return nil, fmt.Errorf("connection timeout")
		},
	}

	client := createTestToolClient(mockClient)
	ctx := context.Background()

	status := client.Health(ctx)
	assert.Equal(t, types.HealthStateUnhealthy, status.State)
	assert.Contains(t, status.Message, "health check failed")
	assert.Contains(t, status.Message, "connection timeout")
}

func TestGRPCToolClient_Health_UnknownState(t *testing.T) {
	mockClient := &mockToolServiceClient{
		healthFunc: func(ctx context.Context, req *proto.ToolHealthRequest, opts ...grpc.CallOption) (*proto.HealthStatus, error) {
			return &proto.HealthStatus{
				State:   "unknown",
				Message: "Unknown status",
			}, nil
		},
	}

	client := createTestToolClient(mockClient)
	ctx := context.Background()

	status := client.Health(ctx)
	assert.Equal(t, types.HealthStateUnhealthy, status.State)
	assert.Equal(t, "unknown health status", status.Message)
}

func TestGRPCToolClient_FetchDescriptor_Caching(t *testing.T) {
	callCount := 0

	mockClient := &mockToolServiceClient{
		getDescriptorFunc: func(ctx context.Context, req *proto.ToolGetDescriptorRequest, opts ...grpc.CallOption) (*proto.ToolDescriptor, error) {
			callCount++
			return &proto.ToolDescriptor{
				Name:        "test-tool",
				Description: "Test tool",
				Version:     "1.0.0",
				Tags:        []string{"test"},
				InputSchema: &commonpb.JSONSchema{
					Json: `{"type": "object"}`,
				},
				OutputSchema: &commonpb.JSONSchema{
					Json: `{"type": "object"}`,
				},
			}, nil
		},
	}

	client := createTestToolClient(mockClient)

	// First call should fetch descriptor
	_ = client.InputSchema()
	assert.Equal(t, 1, callCount)

	// Subsequent calls should use cached descriptor
	_ = client.InputSchema()
	assert.Equal(t, 1, callCount)

	_ = client.OutputSchema()
	assert.Equal(t, 1, callCount)

	_ = client.Tags()
	assert.Equal(t, 1, callCount)

	_ = client.Description()
	assert.Equal(t, 1, callCount)
}

func TestGRPCToolClient_FetchDescriptor_Error(t *testing.T) {
	mockClient := &mockToolServiceClient{
		getDescriptorFunc: func(ctx context.Context, req *proto.ToolGetDescriptorRequest, opts ...grpc.CallOption) (*proto.ToolDescriptor, error) {
			return nil, fmt.Errorf("descriptor fetch failed")
		},
	}

	client := createTestToolClient(mockClient)

	// Should return empty schema on error
	inputSchema := client.InputSchema()
	assert.Equal(t, schema.JSONSchema{}, inputSchema)

	// Should still be able to get metadata from ServiceInfo
	assert.Equal(t, "test-tool", client.Name())
	assert.Equal(t, "1.0.0", client.Version())
}

func TestProtoSchemaToInternal(t *testing.T) {
	tests := []struct {
		name        string
		protoSchema *commonpb.JSONSchema
		expectError bool
		validate    func(t *testing.T, schema schema.JSONSchema)
	}{
		{
			name:        "nil schema",
			protoSchema: nil,
			expectError: false,
			validate: func(t *testing.T, s schema.JSONSchema) {
				assert.Equal(t, schema.JSONSchema{}, s)
			},
		},
		{
			name:        "empty JSON",
			protoSchema: &commonpb.JSONSchema{Json: ""},
			expectError: false,
			validate: func(t *testing.T, s schema.JSONSchema) {
				assert.Equal(t, schema.JSONSchema{}, s)
			},
		},
		{
			name: "valid object schema",
			protoSchema: &commonpb.JSONSchema{
				Json: `{
					"type": "object",
					"properties": {
						"name": {"type": "string"},
						"age": {"type": "integer"}
					},
					"required": ["name"]
				}`,
			},
			expectError: false,
			validate: func(t *testing.T, s schema.JSONSchema) {
				assert.Equal(t, "object", s.Type)
				assert.Len(t, s.Properties, 2)
				assert.Contains(t, s.Properties, "name")
				assert.Contains(t, s.Properties, "age")
				assert.Equal(t, []string{"name"}, s.Required)
			},
		},
		{
			name: "invalid JSON",
			protoSchema: &commonpb.JSONSchema{
				Json: `{invalid`,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			schema, err := protoSchemaToInternal(tt.protoSchema)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				if tt.validate != nil {
					tt.validate(t, schema)
				}
			}
		})
	}
}

func TestNewGRPCToolClient(t *testing.T) {
	info := sdkregistry.ServiceInfo{
		Name:     "nmap",
		Version:  "2.0.0",
		Endpoint: "localhost:50052",
		Metadata: map[string]string{
			"description": "Network scanner",
			"tags":        "network,scanner",
		},
	}

	client := NewGRPCToolClient(nil, info)

	assert.NotNil(t, client)
	assert.Equal(t, "nmap", client.Name())
	assert.Equal(t, "2.0.0", client.Version())
	assert.Equal(t, "Network scanner", client.Description())
	assert.Equal(t, []string{"network", "scanner"}, client.Tags())
}
