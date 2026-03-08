package tool

import (
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/types"
	"github.com/zero-day-ai/sdk/api/gen/commonpb"
	"github.com/zero-day-ai/sdk/api/gen/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/structpb"
)

const bufSize = 1024 * 1024

// mockToolServiceServer implements proto.ToolServiceServer for testing
type mockToolServiceServer struct {
	proto.UnimplementedToolServiceServer

	// Configuration for mock behavior
	descriptor      *proto.ToolDescriptor
	executeResponse *proto.ToolExecuteResponse
	executeError    error
	healthResponse  *commonpb.HealthStatus
	healthError     error
}

func (m *mockToolServiceServer) GetDescriptor(ctx context.Context, req *proto.ToolGetDescriptorRequest) (*proto.ToolDescriptor, error) {
	if m.descriptor == nil {
		return nil, status.Error(codes.Internal, "descriptor not configured")
	}
	return m.descriptor, nil
}

func (m *mockToolServiceServer) Execute(ctx context.Context, req *proto.ToolExecuteRequest) (*proto.ToolExecuteResponse, error) {
	if m.executeError != nil {
		return nil, m.executeError
	}
	if m.executeResponse == nil {
		return nil, status.Error(codes.Internal, "execute response not configured")
	}
	return m.executeResponse, nil
}

func (m *mockToolServiceServer) Health(ctx context.Context, req *proto.ToolHealthRequest) (*commonpb.HealthStatus, error) {
	if m.healthError != nil {
		return nil, m.healthError
	}
	if m.healthResponse == nil {
		return &commonpb.HealthStatus{
			Status:    "healthy",
			Message:   "OK",
			CheckedAt: time.Now().UnixMilli(),
		}, nil
	}
	return m.healthResponse, nil
}

// setupTestServer creates an in-memory gRPC server with the mock tool service
func setupTestServer(t *testing.T, mock *mockToolServiceServer) (*grpc.Server, *bufconn.Listener, func()) {
	t.Helper()

	lis := bufconn.Listen(bufSize)
	srv := grpc.NewServer()
	proto.RegisterToolServiceServer(srv, mock)

	go func() {
		if err := srv.Serve(lis); err != nil && err != grpc.ErrServerStopped {
			t.Logf("Server error: %v", err)
		}
	}()

	// Give the server a moment to start
	time.Sleep(10 * time.Millisecond)

	cleanup := func() {
		srv.Stop()
		lis.Close()
	}

	return srv, lis, cleanup
}

// createTestClient creates a GRPCToolClient connected to the test server
func createTestClient(t *testing.T, lis *bufconn.Listener) *GRPCToolClient {
	t.Helper()

	// Create a dialer for bufconn
	bufDialer := func(ctx context.Context, s string) (net.Conn, error) {
		return lis.Dial()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	//nolint:staticcheck // Using DialContext for better bufconn compatibility
	conn, err := grpc.DialContext(
		ctx,
		"bufnet",
		grpc.WithContextDialer(bufDialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)

	client := proto.NewToolServiceClient(conn)

	// Fetch descriptor
	descCtx, descCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer descCancel()

	descriptor, err := client.GetDescriptor(descCtx, &proto.ToolGetDescriptorRequest{})
	require.NoError(t, err)

	// TODO: Once SDK task 1.3 is complete, use descriptor.GetInputMessageType() and descriptor.GetOutputMessageType()
	inputMsgType := "google.protobuf.Struct"
	outputMsgType := "google.protobuf.Struct"

	return &GRPCToolClient{
		name:              descriptor.GetName(),
		description:       descriptor.GetDescription(),
		version:           descriptor.GetVersion(),
		tags:              descriptor.GetTags(),
		conn:              conn,
		client:            client,
		inputMessageType:  inputMsgType,
		outputMessageType: outputMsgType,
	}
}

func TestNewGRPCToolClient(t *testing.T) {
	inputSchemaJSON := `{"type":"object","properties":{"target":{"type":"string"}},"required":["target"]}`
	outputSchemaJSON := `{"type":"object","properties":{"result":{"type":"string"}},"required":["result"]}`

	mock := &mockToolServiceServer{
		descriptor: &proto.ToolDescriptor{
			Name:        "test-tool",
			Description: "A test tool",
			Version:     "1.0.0",
			Tags:        []string{"test", "mock"},
			InputSchema: &commonpb.JSONSchema{
				Json: inputSchemaJSON,
			},
			OutputSchema: &commonpb.JSONSchema{
				Json: outputSchemaJSON,
			},
		},
	}

	_, lis, cleanup := setupTestServer(t, mock)
	defer cleanup()

	// Create dialer for bufconn
	bufDialer := func(ctx context.Context, s string) (net.Conn, error) {
		return lis.Dial()
	}

	// Test successful client creation
	client, err := NewGRPCToolClient(
		"bufnet",
		grpc.WithContextDialer(bufDialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(), // Block until connection is established
	)
	require.NoError(t, err)
	require.NotNil(t, client)
	defer client.Close()

	// Verify metadata
	assert.Equal(t, "test-tool", client.Name())
	assert.Equal(t, "A test tool", client.Description())
	assert.Equal(t, "1.0.0", client.Version())
	assert.Equal(t, []string{"test", "mock"}, client.Tags())

	// Verify message types are set
	assert.Equal(t, "google.protobuf.Struct", client.InputMessageType())
	assert.Equal(t, "google.protobuf.Struct", client.OutputMessageType())
}

func TestNewGRPCToolClient_ConnectionFailure(t *testing.T) {
	// Try to connect to a non-existent endpoint
	_, err := NewGRPCToolClient("localhost:99999")

	// Should fail during GetDescriptor, not during dial
	// (grpc.NewClient is lazy and doesn't actually connect)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get tool descriptor")
}

func TestNewGRPCToolClient_InvalidSchema(t *testing.T) {
	mock := &mockToolServiceServer{
		descriptor: &proto.ToolDescriptor{
			Name:        "bad-schema-tool",
			Description: "Tool with invalid schema",
			Version:     "1.0.0",
			InputSchema: &commonpb.JSONSchema{
				Json: `{invalid json}`,
			},
			OutputSchema: &commonpb.JSONSchema{
				Json: `{"type":"object"}`,
			},
		},
	}

	_, lis, cleanup := setupTestServer(t, mock)
	defer cleanup()

	bufDialer := func(ctx context.Context, s string) (net.Conn, error) {
		return lis.Dial()
	}

	_, err := NewGRPCToolClient(
		"bufnet",
		grpc.WithContextDialer(bufDialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse input schema")
}

func TestGRPCToolClient_Execute_Success(t *testing.T) {
	inputSchemaJSON := `{"type":"object","properties":{"target":{"type":"string"}},"required":["target"]}`
	outputSchemaJSON := `{"type":"object","properties":{"result":{"type":"string"}},"required":["result"]}`

	mock := &mockToolServiceServer{
		descriptor: &proto.ToolDescriptor{
			Name:         "test-tool",
			Description:  "A test tool",
			Version:      "1.0.0",
			InputSchema:  &commonpb.JSONSchema{Json: inputSchemaJSON},
			OutputSchema: &commonpb.JSONSchema{Json: outputSchemaJSON},
		},
		executeResponse: &proto.ToolExecuteResponse{
			OutputJson: `{"result":"success","data":"test data"}`,
		},
	}

	_, lis, cleanup := setupTestServer(t, mock)
	defer cleanup()

	client := createTestClient(t, lis)
	defer client.Close()

	// Execute with valid proto input
	ctx := context.Background()
	input, err := structpb.NewStruct(map[string]any{
		"target": "test-target",
	})
	require.NoError(t, err)

	outputProto, err := client.ExecuteProto(ctx, input)
	require.NoError(t, err)
	require.NotNil(t, outputProto)

	output := outputProto.(*structpb.Struct)
	assert.Equal(t, "success", output.Fields["result"].GetStringValue())
	assert.Equal(t, "test data", output.Fields["data"].GetStringValue())
}

func TestGRPCToolClient_Execute_WithError(t *testing.T) {
	inputSchemaJSON := `{"type":"object","properties":{"target":{"type":"string"}},"required":["target"]}`
	outputSchemaJSON := `{"type":"object","properties":{"result":{"type":"string"}},"required":["result"]}`

	mock := &mockToolServiceServer{
		descriptor: &proto.ToolDescriptor{
			Name:         "test-tool",
			Description:  "A test tool",
			Version:      "1.0.0",
			InputSchema:  &commonpb.JSONSchema{Json: inputSchemaJSON},
			OutputSchema: &commonpb.JSONSchema{Json: outputSchemaJSON},
		},
		executeResponse: &proto.ToolExecuteResponse{
			Error: &commonpb.Error{
				Code:      "tool_execution_failed",
				Message:   "tool failed to execute",
				Retryable: false,
			},
		},
	}

	_, lis, cleanup := setupTestServer(t, mock)
	defer cleanup()

	client := createTestClient(t, lis)
	defer client.Close()

	ctx := context.Background()
	input, err := structpb.NewStruct(map[string]any{
		"target": "test-target",
	})
	require.NoError(t, err)

	_, err = client.ExecuteProto(ctx, input)
	require.Error(t, err)

	gibsonErr, ok := err.(*types.GibsonError)
	require.True(t, ok, "expected GibsonError")
	assert.Equal(t, types.ErrorCode("tool_execution_failed"), gibsonErr.Code)
	assert.Equal(t, "tool failed to execute", gibsonErr.Message)
	assert.False(t, gibsonErr.Retryable)
}

func TestGRPCToolClient_Execute_GRPCError(t *testing.T) {
	inputSchemaJSON := `{"type":"object","properties":{"target":{"type":"string"}},"required":["target"]}`
	outputSchemaJSON := `{"type":"object","properties":{"result":{"type":"string"}},"required":["result"]}`

	mock := &mockToolServiceServer{
		descriptor: &proto.ToolDescriptor{
			Name:         "test-tool",
			Description:  "A test tool",
			Version:      "1.0.0",
			InputSchema:  &commonpb.JSONSchema{Json: inputSchemaJSON},
			OutputSchema: &commonpb.JSONSchema{Json: outputSchemaJSON},
		},
		executeError: status.Error(codes.Unavailable, "service unavailable"),
	}

	_, lis, cleanup := setupTestServer(t, mock)
	defer cleanup()

	client := createTestClient(t, lis)
	defer client.Close()

	ctx := context.Background()
	input, err := structpb.NewStruct(map[string]any{
		"target": "test-target",
	})
	require.NoError(t, err)

	_, err = client.ExecuteProto(ctx, input)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "gRPC tool \"test-tool\" execution failed")
}

func TestGRPCToolClient_Execute_InvalidInput(t *testing.T) {
	inputSchemaJSON := `{"type":"object","properties":{"target":{"type":"string"}},"required":["target"]}`
	outputSchemaJSON := `{"type":"object","properties":{"result":{"type":"string"}},"required":["result"]}`

	mock := &mockToolServiceServer{
		descriptor: &proto.ToolDescriptor{
			Name:         "test-tool",
			Description:  "A test tool",
			Version:      "1.0.0",
			InputSchema:  &commonpb.JSONSchema{Json: inputSchemaJSON},
			OutputSchema: &commonpb.JSONSchema{Json: outputSchemaJSON},
		},
	}

	_, lis, cleanup := setupTestServer(t, mock)
	defer cleanup()

	client := createTestClient(t, lis)
	defer client.Close()

	// Try to create input with un-marshallable value - structpb.NewStruct should fail
	_, err := structpb.NewStruct(map[string]any{
		"target": make(chan int), // channels can't be marshaled
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid type")
}

func TestGRPCToolClient_Execute_InvalidOutput(t *testing.T) {
	inputSchemaJSON := `{"type":"object","properties":{"target":{"type":"string"}},"required":["target"]}`
	outputSchemaJSON := `{"type":"object","properties":{"result":{"type":"string"}},"required":["result"]}`

	mock := &mockToolServiceServer{
		descriptor: &proto.ToolDescriptor{
			Name:         "test-tool",
			Description:  "A test tool",
			Version:      "1.0.0",
			InputSchema:  &commonpb.JSONSchema{Json: inputSchemaJSON},
			OutputSchema: &commonpb.JSONSchema{Json: outputSchemaJSON},
		},
		executeResponse: &proto.ToolExecuteResponse{
			OutputJson: `{invalid json}`,
		},
	}

	_, lis, cleanup := setupTestServer(t, mock)
	defer cleanup()

	client := createTestClient(t, lis)
	defer client.Close()

	ctx := context.Background()
	input, err := structpb.NewStruct(map[string]any{
		"target": "test-target",
	})
	require.NoError(t, err)

	_, err = client.ExecuteProto(ctx, input)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to unmarshal output")
}

func TestGRPCToolClient_Execute_ContextCancellation(t *testing.T) {
	inputSchemaJSON := `{"type":"object","properties":{"target":{"type":"string"}},"required":["target"]}`
	outputSchemaJSON := `{"type":"object","properties":{"result":{"type":"string"}},"required":["result"]}`

	mock := &mockToolServiceServer{
		descriptor: &proto.ToolDescriptor{
			Name:         "test-tool",
			Description:  "A test tool",
			Version:      "1.0.0",
			InputSchema:  &commonpb.JSONSchema{Json: inputSchemaJSON},
			OutputSchema: &commonpb.JSONSchema{Json: outputSchemaJSON},
		},
	}

	_, lis, cleanup := setupTestServer(t, mock)
	defer cleanup()

	client := createTestClient(t, lis)
	defer client.Close()

	// Create a context that's already cancelled
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	input, err := structpb.NewStruct(map[string]any{
		"target": "test-target",
	})
	require.NoError(t, err)

	_, err = client.ExecuteProto(ctx, input)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "context canceled")
}

func TestGRPCToolClient_Health_Healthy(t *testing.T) {
	inputSchemaJSON := `{"type":"object"}`
	outputSchemaJSON := `{"type":"object"}`

	now := time.Now()
	mock := &mockToolServiceServer{
		descriptor: &proto.ToolDescriptor{
			Name:         "test-tool",
			Description:  "A test tool",
			Version:      "1.0.0",
			InputSchema:  &commonpb.JSONSchema{Json: inputSchemaJSON},
			OutputSchema: &commonpb.JSONSchema{Json: outputSchemaJSON},
		},
		healthResponse: &commonpb.HealthStatus{
			Status:     "healthy",
			Message:   "All systems operational",
			CheckedAt: now.UnixMilli(),
		},
	}

	_, lis, cleanup := setupTestServer(t, mock)
	defer cleanup()

	client := createTestClient(t, lis)
	defer client.Close()

	ctx := context.Background()
	health := client.Health(ctx)

	assert.Equal(t, types.HealthState("healthy"), health.State)
	assert.Equal(t, "All systems operational", health.Message)
	assert.Equal(t, now.UnixMilli(), health.CheckedAt.UnixMilli())
}

func TestGRPCToolClient_Health_Unhealthy(t *testing.T) {
	inputSchemaJSON := `{"type":"object"}`
	outputSchemaJSON := `{"type":"object"}`

	now := time.Now()
	mock := &mockToolServiceServer{
		descriptor: &proto.ToolDescriptor{
			Name:         "test-tool",
			Description:  "A test tool",
			Version:      "1.0.0",
			InputSchema:  &commonpb.JSONSchema{Json: inputSchemaJSON},
			OutputSchema: &commonpb.JSONSchema{Json: outputSchemaJSON},
		},
		healthResponse: &commonpb.HealthStatus{
			Status:     "unhealthy",
			Message:   "Database connection failed",
			CheckedAt: now.UnixMilli(),
		},
	}

	_, lis, cleanup := setupTestServer(t, mock)
	defer cleanup()

	client := createTestClient(t, lis)
	defer client.Close()

	ctx := context.Background()
	health := client.Health(ctx)

	assert.Equal(t, types.HealthState("unhealthy"), health.State)
	assert.Equal(t, "Database connection failed", health.Message)
}

func TestGRPCToolClient_Health_Degraded(t *testing.T) {
	inputSchemaJSON := `{"type":"object"}`
	outputSchemaJSON := `{"type":"object"}`

	now := time.Now()
	mock := &mockToolServiceServer{
		descriptor: &proto.ToolDescriptor{
			Name:         "test-tool",
			Description:  "A test tool",
			Version:      "1.0.0",
			InputSchema:  &commonpb.JSONSchema{Json: inputSchemaJSON},
			OutputSchema: &commonpb.JSONSchema{Json: outputSchemaJSON},
		},
		healthResponse: &commonpb.HealthStatus{
			Status:     "degraded",
			Message:   "High latency detected",
			CheckedAt: now.UnixMilli(),
		},
	}

	_, lis, cleanup := setupTestServer(t, mock)
	defer cleanup()

	client := createTestClient(t, lis)
	defer client.Close()

	ctx := context.Background()
	health := client.Health(ctx)

	assert.Equal(t, types.HealthState("degraded"), health.State)
	assert.Equal(t, "High latency detected", health.Message)
}

func TestGRPCToolClient_Health_GRPCError(t *testing.T) {
	inputSchemaJSON := `{"type":"object"}`
	outputSchemaJSON := `{"type":"object"}`

	mock := &mockToolServiceServer{
		descriptor: &proto.ToolDescriptor{
			Name:         "test-tool",
			Description:  "A test tool",
			Version:      "1.0.0",
			InputSchema:  &commonpb.JSONSchema{Json: inputSchemaJSON},
			OutputSchema: &commonpb.JSONSchema{Json: outputSchemaJSON},
		},
		healthError: status.Error(codes.Unavailable, "health check failed"),
	}

	_, lis, cleanup := setupTestServer(t, mock)
	defer cleanup()

	client := createTestClient(t, lis)
	defer client.Close()

	ctx := context.Background()
	health := client.Health(ctx)

	assert.Equal(t, types.HealthStateUnhealthy, health.State)
	assert.Contains(t, health.Message, "gRPC health check failed")
}

func TestGRPCToolClient_Health_Timeout(t *testing.T) {
	inputSchemaJSON := `{"type":"object"}`
	outputSchemaJSON := `{"type":"object"}`

	// Test timeout by simulating a deadline exceeded error
	mock := &mockToolServiceServer{
		descriptor: &proto.ToolDescriptor{
			Name:         "test-tool",
			Description:  "A test tool",
			Version:      "1.0.0",
			InputSchema:  &commonpb.JSONSchema{Json: inputSchemaJSON},
			OutputSchema: &commonpb.JSONSchema{Json: outputSchemaJSON},
		},
		healthError: status.Error(codes.DeadlineExceeded, "context deadline exceeded"),
	}

	_, lis, cleanup := setupTestServer(t, mock)
	defer cleanup()

	client := createTestClient(t, lis)
	defer client.Close()

	// Create a context that's already past its deadline
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	// Wait for timeout to trigger
	time.Sleep(20 * time.Millisecond)

	health := client.Health(ctx)

	assert.Equal(t, types.HealthStateUnhealthy, health.State)
	assert.Contains(t, health.Message, "gRPC health check failed")
}

func TestGRPCToolClient_Close(t *testing.T) {
	inputSchemaJSON := `{"type":"object"}`
	outputSchemaJSON := `{"type":"object"}`

	mock := &mockToolServiceServer{
		descriptor: &proto.ToolDescriptor{
			Name:         "test-tool",
			Description:  "A test tool",
			Version:      "1.0.0",
			InputSchema:  &commonpb.JSONSchema{Json: inputSchemaJSON},
			OutputSchema: &commonpb.JSONSchema{Json: outputSchemaJSON},
		},
	}

	_, lis, cleanup := setupTestServer(t, mock)
	defer cleanup()

	client := createTestClient(t, lis)

	// Close should not return error
	err := client.Close()
	assert.NoError(t, err)

	// Subsequent operations should fail with connection closed error
	ctx := context.Background()
	health := client.Health(ctx)
	assert.Equal(t, types.HealthStateUnhealthy, health.State)
}

func TestGRPCToolClient_Close_NilConnection(t *testing.T) {
	client := &GRPCToolClient{
		name: "test-tool",
		conn: nil,
	}

	// Should not panic or error with nil connection
	err := client.Close()
	assert.NoError(t, err)
}

// Note: InputSchema and OutputSchema tests removed as tools now use proto-based message types
// instead of JSON schemas. Tools now expose InputMessageType() and OutputMessageType() which
// return fully-qualified proto message type names.

func TestGRPCToolClient_Metadata(t *testing.T) {
	inputSchemaJSON := `{"type":"object"}`
	outputSchemaJSON := `{"type":"object"}`

	mock := &mockToolServiceServer{
		descriptor: &proto.ToolDescriptor{
			Name:         "nmap-scanner",
			Description:  "Network port scanner using nmap",
			Version:      "2.3.1",
			Tags:         []string{"network", "scanner", "recon"},
			InputSchema:  &commonpb.JSONSchema{Json: inputSchemaJSON},
			OutputSchema: &commonpb.JSONSchema{Json: outputSchemaJSON},
		},
	}

	_, lis, cleanup := setupTestServer(t, mock)
	defer cleanup()

	client := createTestClient(t, lis)
	defer client.Close()

	assert.Equal(t, "nmap-scanner", client.Name())
	assert.Equal(t, "Network port scanner using nmap", client.Description())
	assert.Equal(t, "2.3.1", client.Version())
	assert.Equal(t, []string{"network", "scanner", "recon"}, client.Tags())
}

func TestGRPCToolClient_EmptyTags(t *testing.T) {
	inputSchemaJSON := `{"type":"object"}`
	outputSchemaJSON := `{"type":"object"}`

	mock := &mockToolServiceServer{
		descriptor: &proto.ToolDescriptor{
			Name:         "test-tool",
			Description:  "A test tool",
			Version:      "1.0.0",
			Tags:         []string{},
			InputSchema:  &commonpb.JSONSchema{Json: inputSchemaJSON},
			OutputSchema: &commonpb.JSONSchema{Json: outputSchemaJSON},
		},
	}

	_, lis, cleanup := setupTestServer(t, mock)
	defer cleanup()

	client := createTestClient(t, lis)
	defer client.Close()

	assert.Empty(t, client.Tags())
}

// TestGRPCToolClient_ComplexOutput tests execution with complex nested output
func TestGRPCToolClient_ComplexOutput(t *testing.T) {
	inputSchemaJSON := `{"type":"object"}`
	outputSchemaJSON := `{"type":"object"}`

	complexOutput := map[string]any{
		"hosts": []map[string]any{
			{
				"ip":    "192.168.1.1",
				"ports": []int{22, 80, 443},
				"services": map[string]string{
					"22":  "ssh",
					"80":  "http",
					"443": "https",
				},
			},
			{
				"ip":    "192.168.1.2",
				"ports": []int{3306},
				"services": map[string]string{
					"3306": "mysql",
				},
			},
		},
		"summary": map[string]any{
			"total_hosts":   2,
			"total_ports":   4,
			"scan_duration": 12.5,
		},
	}

	outputJSON, err := json.Marshal(complexOutput)
	require.NoError(t, err)

	mock := &mockToolServiceServer{
		descriptor: &proto.ToolDescriptor{
			Name:         "test-tool",
			Description:  "A test tool",
			Version:      "1.0.0",
			InputSchema:  &commonpb.JSONSchema{Json: inputSchemaJSON},
			OutputSchema: &commonpb.JSONSchema{Json: outputSchemaJSON},
		},
		executeResponse: &proto.ToolExecuteResponse{
			OutputJson: string(outputJSON),
		},
	}

	_, lis, cleanup := setupTestServer(t, mock)
	defer cleanup()

	client := createTestClient(t, lis)
	defer client.Close()

	ctx := context.Background()
	input, err := structpb.NewStruct(map[string]any{})
	require.NoError(t, err)

	outputProto, err := client.ExecuteProto(ctx, input)
	require.NoError(t, err)

	// Verify complex structure is preserved
	output := outputProto.(*structpb.Struct)
	hosts := output.Fields["hosts"].GetListValue()
	require.NotNil(t, hosts)
	assert.Len(t, hosts.Values, 2)

	summary := output.Fields["summary"].GetStructValue()
	require.NotNil(t, summary)
	assert.Equal(t, float64(2), summary.Fields["total_hosts"].GetNumberValue())
	assert.Equal(t, float64(4), summary.Fields["total_ports"].GetNumberValue())
}
