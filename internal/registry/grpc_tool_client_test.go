package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/zero-day-ai/gibson/internal/types"
	commonpb "github.com/zero-day-ai/sdk/api/gen/commonpb"
	proto "github.com/zero-day-ai/sdk/api/gen/proto"
	sdkregistry "github.com/zero-day-ai/sdk/registry"
	"google.golang.org/protobuf/types/known/structpb"
)

// mockToolServiceClient implements proto.ToolServiceClient for testing
type mockToolServiceClient struct {
	proto.ToolServiceClient

	// Hooks for test customization
	getDescriptorFunc func(ctx context.Context, req *proto.ToolGetDescriptorRequest, opts ...grpc.CallOption) (*proto.ToolDescriptor, error)
	executeFunc       func(ctx context.Context, req *proto.ToolExecuteRequest, opts ...grpc.CallOption) (*proto.ToolExecuteResponse, error)
	healthFunc        func(ctx context.Context, req *proto.ToolHealthRequest, opts ...grpc.CallOption) (*commonpb.HealthStatus, error)
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

func (m *mockToolServiceClient) Health(ctx context.Context, req *proto.ToolHealthRequest, opts ...grpc.CallOption) (*commonpb.HealthStatus, error) {
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

func TestGRPCToolClient_InputMessageType(t *testing.T) {
	mockClient := &mockToolServiceClient{
		getDescriptorFunc: func(ctx context.Context, req *proto.ToolGetDescriptorRequest, opts ...grpc.CallOption) (*proto.ToolDescriptor, error) {
			return &proto.ToolDescriptor{
				Name:        "test-tool",
				Description: "Test tool",
				Version:     "1.0.0",
				Tags:        []string{"test"},
			}, nil
		},
	}

	info := sdkregistry.ServiceInfo{
		Name:     "test-tool",
		Version:  "1.0.0",
		Endpoint: "localhost:50051",
		Metadata: map[string]string{
			"description":         "A test tool",
			"tags":                "network,scanner,test",
			"input_message_type":  "zero_day.tools.TestInput",
			"output_message_type": "zero_day.tools.TestOutput",
		},
	}

	client := &GRPCToolClient{
		conn:   nil,
		client: mockClient,
		info:   info,
	}

	msgType := client.InputMessageType()
	assert.Equal(t, "zero_day.tools.TestInput", msgType)
}

func TestGRPCToolClient_OutputMessageType(t *testing.T) {
	mockClient := &mockToolServiceClient{
		getDescriptorFunc: func(ctx context.Context, req *proto.ToolGetDescriptorRequest, opts ...grpc.CallOption) (*proto.ToolDescriptor, error) {
			return &proto.ToolDescriptor{
				Name:        "test-tool",
				Description: "Test tool",
				Version:     "1.0.0",
				Tags:        []string{"test"},
			}, nil
		},
	}

	info := sdkregistry.ServiceInfo{
		Name:     "test-tool",
		Version:  "1.0.0",
		Endpoint: "localhost:50051",
		Metadata: map[string]string{
			"description":         "A test tool",
			"tags":                "network,scanner,test",
			"input_message_type":  "zero_day.tools.TestInput",
			"output_message_type": "zero_day.tools.TestOutput",
		},
	}

	client := &GRPCToolClient{
		conn:   nil,
		client: mockClient,
		info:   info,
	}

	msgType := client.OutputMessageType()
	assert.Equal(t, "zero_day.tools.TestOutput", msgType)
}

func TestGRPCToolClient_ExecuteProto_Success(t *testing.T) {
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
				"exitCode": float64(0),
			}
			outputJSON, _ := json.Marshal(output)

			return &proto.ToolExecuteResponse{
				OutputJson: string(outputJSON),
				Error:      nil,
			}, nil
		},
		getDescriptorFunc: func(ctx context.Context, req *proto.ToolGetDescriptorRequest, opts ...grpc.CallOption) (*proto.ToolDescriptor, error) {
			return &proto.ToolDescriptor{
				Name:        "test-tool",
				Description: "Test tool",
				Version:     "1.0.0",
				Tags:        []string{"test"},
			}, nil
		},
	}

	info := sdkregistry.ServiceInfo{
		Name:     "test-tool",
		Version:  "1.0.0",
		Endpoint: "localhost:50051",
		Metadata: map[string]string{
			"description":         "A test tool",
			"output_message_type": "google.protobuf.Struct",
		},
	}

	client := &GRPCToolClient{
		conn:   nil,
		client: mockClient,
		info:   info,
	}

	ctx := context.Background()

	// Create proto input (using google.protobuf.Struct as fallback)
	inputMap := map[string]any{
		"target": "example.com",
		"port":   float64(80),
	}
	inputProto, err := structpb.NewStruct(inputMap)
	require.NoError(t, err)

	output, err := client.ExecuteProto(ctx, inputProto)
	require.NoError(t, err)

	// Output should be a google.protobuf.Struct
	outputStruct, ok := output.(*structpb.Struct)
	require.True(t, ok, "output should be *structpb.Struct")
	assert.Equal(t, "success", outputStruct.Fields["result"].GetStringValue())
	assert.Equal(t, float64(0), outputStruct.Fields["exitCode"].GetNumberValue())
}

func TestGRPCToolClient_ExecuteProto_WithError(t *testing.T) {
	mockClient := &mockToolServiceClient{
		executeFunc: func(ctx context.Context, req *proto.ToolExecuteRequest, opts ...grpc.CallOption) (*proto.ToolExecuteResponse, error) {
			// Return error response
			return &proto.ToolExecuteResponse{
				OutputJson: "",
				Error: &commonpb.Error{
					Code:    "EXECUTION_FAILED",
					Message: "Failed to scan target",
				},
			}, nil
		},
	}

	info := sdkregistry.ServiceInfo{
		Name:     "test-tool",
		Version:  "1.0.0",
		Endpoint: "localhost:50051",
		Metadata: map[string]string{
			"output_message_type": "google.protobuf.Struct",
		},
	}

	client := &GRPCToolClient{
		conn:   nil,
		client: mockClient,
		info:   info,
	}

	ctx := context.Background()

	inputMap := map[string]any{
		"target": "example.com",
	}
	inputProto, err := structpb.NewStruct(inputMap)
	require.NoError(t, err)

	output, err := client.ExecuteProto(ctx, inputProto)
	assert.Error(t, err)
	assert.Nil(t, output)
	assert.Contains(t, err.Error(), "EXECUTION_FAILED")
	assert.Contains(t, err.Error(), "Failed to scan target")
}

func TestGRPCToolClient_ExecuteProto_RPCError(t *testing.T) {
	mockClient := &mockToolServiceClient{
		executeFunc: func(ctx context.Context, req *proto.ToolExecuteRequest, opts ...grpc.CallOption) (*proto.ToolExecuteResponse, error) {
			return nil, fmt.Errorf("connection refused")
		},
	}

	info := sdkregistry.ServiceInfo{
		Name:     "test-tool",
		Version:  "1.0.0",
		Endpoint: "localhost:50051",
		Metadata: map[string]string{
			"output_message_type": "google.protobuf.Struct",
		},
	}

	client := &GRPCToolClient{
		conn:   nil,
		client: mockClient,
		info:   info,
	}

	ctx := context.Background()

	inputMap := map[string]any{
		"target": "example.com",
	}
	inputProto, err := structpb.NewStruct(inputMap)
	require.NoError(t, err)

	output, err := client.ExecuteProto(ctx, inputProto)
	assert.Error(t, err)
	assert.Nil(t, output)
	assert.Contains(t, err.Error(), "tool execution failed")
	assert.Contains(t, err.Error(), "connection refused")
}

func TestGRPCToolClient_ExecuteProto_MarshalError(t *testing.T) {
	// Create input that can't be marshaled to proto (map with channel)
	input := map[string]any{
		"invalid": make(chan int), // channels can't be in proto Struct
	}

	// structpb.NewStruct will fail on this input
	inputProto, err := structpb.NewStruct(input)
	assert.Error(t, err) // Should fail before ExecuteProto
	assert.Nil(t, inputProto)

	// We don't need to actually call ExecuteProto since NewStruct already failed
	// This test verifies that invalid proto input is caught at the marshaling stage
}

func TestGRPCToolClient_ExecuteProto_UnmarshalError(t *testing.T) {
	mockClient := &mockToolServiceClient{
		executeFunc: func(ctx context.Context, req *proto.ToolExecuteRequest, opts ...grpc.CallOption) (*proto.ToolExecuteResponse, error) {
			// Return invalid JSON
			return &proto.ToolExecuteResponse{
				OutputJson: "{invalid json}",
				Error:      nil,
			}, nil
		},
		getDescriptorFunc: func(ctx context.Context, req *proto.ToolGetDescriptorRequest, opts ...grpc.CallOption) (*proto.ToolDescriptor, error) {
			return &proto.ToolDescriptor{
				Name:        "test-tool",
				Description: "Test tool",
				Version:     "1.0.0",
				Tags:        []string{"test"},
			}, nil
		},
	}

	info := sdkregistry.ServiceInfo{
		Name:     "test-tool",
		Version:  "1.0.0",
		Endpoint: "localhost:50051",
		Metadata: map[string]string{
			"output_message_type": "google.protobuf.Struct",
		},
	}

	client := &GRPCToolClient{
		conn:   nil,
		client: mockClient,
		info:   info,
	}

	ctx := context.Background()

	inputMap := map[string]any{
		"target": "example.com",
	}
	inputProto, err := structpb.NewStruct(inputMap)
	require.NoError(t, err)

	output, err := client.ExecuteProto(ctx, inputProto)
	assert.Error(t, err)
	assert.Nil(t, output)
	assert.Contains(t, err.Error(), "failed to unmarshal output")
}

func TestGRPCToolClient_Health_Healthy(t *testing.T) {
	mockClient := &mockToolServiceClient{
		healthFunc: func(ctx context.Context, req *proto.ToolHealthRequest, opts ...grpc.CallOption) (*commonpb.HealthStatus, error) {
			return &commonpb.HealthStatus{
				Status:  "healthy",
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
		healthFunc: func(ctx context.Context, req *proto.ToolHealthRequest, opts ...grpc.CallOption) (*commonpb.HealthStatus, error) {
			return &commonpb.HealthStatus{
				Status:  "degraded",
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
		healthFunc: func(ctx context.Context, req *proto.ToolHealthRequest, opts ...grpc.CallOption) (*commonpb.HealthStatus, error) {
			return &commonpb.HealthStatus{
				Status:  "unhealthy",
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
		healthFunc: func(ctx context.Context, req *proto.ToolHealthRequest, opts ...grpc.CallOption) (*commonpb.HealthStatus, error) {
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
		healthFunc: func(ctx context.Context, req *proto.ToolHealthRequest, opts ...grpc.CallOption) (*commonpb.HealthStatus, error) {
			return &commonpb.HealthStatus{
				Status:  "unknown",
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
			}, nil
		},
	}

	info := sdkregistry.ServiceInfo{
		Name:     "test-tool",
		Version:  "1.0.0",
		Endpoint: "localhost:50051",
		Metadata: map[string]string{
			"description":         "A test tool",
			"tags":                "network,scanner,test",
			"input_message_type":  "zero_day.tools.TestInput",
			"output_message_type": "zero_day.tools.TestOutput",
		},
	}

	client := &GRPCToolClient{
		conn:   nil,
		client: mockClient,
		info:   info,
	}

	// First call should fetch descriptor
	_ = client.InputMessageType()
	assert.Equal(t, 1, callCount)

	// Subsequent calls should use cached descriptor
	_ = client.InputMessageType()
	assert.Equal(t, 1, callCount)

	_ = client.OutputMessageType()
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

	info := sdkregistry.ServiceInfo{
		Name:     "test-tool",
		Version:  "1.0.0",
		Endpoint: "localhost:50051",
		Metadata: map[string]string{
			"description": "A test tool",
			"tags":        "network,scanner,test",
			// No input/output_message_type in metadata - will fallback to google.protobuf.Struct
		},
	}

	client := &GRPCToolClient{
		conn:   nil,
		client: mockClient,
		info:   info,
	}

	// Even though descriptor fetch will fail, the fetchDescriptor method
	// will return fallback type from metadata (or google.protobuf.Struct if missing)
	inputType := client.InputMessageType()
	// On error, fetchDescriptor returns fallback but descriptor is nil
	// So InputMessageType returns empty string when descriptor is nil and no metadata
	assert.Equal(t, "", inputType)

	// Should still be able to get metadata from ServiceInfo
	assert.Equal(t, "test-tool", client.Name())
	assert.Equal(t, "1.0.0", client.Version())
}

// TestProtoSchemaToInternal removed - tool interface no longer uses JSON schemas
// Tools now use proto message types (InputMessageType/OutputMessageType)

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

	client := NewGRPCToolClient(nil, info, nil)

	assert.NotNil(t, client)
	assert.Equal(t, "nmap", client.Name())
	assert.Equal(t, "2.0.0", client.Version())
	assert.Equal(t, "Network scanner", client.Description())
	assert.Equal(t, []string{"network", "scanner"}, client.Tags())
}
