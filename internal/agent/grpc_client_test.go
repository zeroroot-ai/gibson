package agent

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/zero-day-ai/gibson/internal/types"
	agentpb "github.com/zero-day-ai/sdk/api/gen/gibson/agent/v1"
	commonpb "github.com/zero-day-ai/sdk/api/gen/gibson/common/v1"
)

const bufSize = 1024 * 1024

// mockAgentServiceServer implements agentpb.AgentServiceServer for testing
type mockAgentServiceServer struct {
	agentpb.UnimplementedAgentServiceServer

	// Configuration for mock behavior
	descriptor      *agentpb.GetDescriptorResponse
	slotSchema      *agentpb.GetSlotSchemaResponse
	executeResponse *agentpb.ExecuteResponse
	executeError    error
	healthResponse  *commonpb.HealthStatus
	healthError     error
	descriptorError error
	slotSchemaError error
}

func (m *mockAgentServiceServer) GetDescriptor(ctx context.Context, req *agentpb.GetDescriptorRequest) (*agentpb.GetDescriptorResponse, error) {
	if m.descriptorError != nil {
		return nil, m.descriptorError
	}
	if m.descriptor == nil {
		return nil, status.Error(codes.Internal, "descriptor not configured")
	}
	return m.descriptor, nil
}

func (m *mockAgentServiceServer) GetSlotSchema(ctx context.Context, req *agentpb.GetSlotSchemaRequest) (*agentpb.GetSlotSchemaResponse, error) {
	if m.slotSchemaError != nil {
		return nil, m.slotSchemaError
	}
	if m.slotSchema == nil {
		return &agentpb.GetSlotSchemaResponse{
			Slots: []*agentpb.AgentSlotDefinition{},
		}, nil
	}
	return m.slotSchema, nil
}

func (m *mockAgentServiceServer) Execute(ctx context.Context, req *agentpb.ExecuteRequest) (*agentpb.ExecuteResponse, error) {
	if m.executeError != nil {
		return nil, m.executeError
	}
	if m.executeResponse == nil {
		return nil, status.Error(codes.Internal, "execute response not configured")
	}
	return m.executeResponse, nil
}

func (m *mockAgentServiceServer) Health(ctx context.Context, req *agentpb.HealthRequest) (*commonpb.HealthStatus, error) {
	if m.healthError != nil {
		return nil, m.healthError
	}
	if m.healthResponse == nil {
		return &commonpb.HealthStatus{
			State:     "healthy",
			Message:   "OK",
			CheckedAt: time.Now().UnixMilli(),
		}, nil
	}
	return m.healthResponse, nil
}

// setupTestServer creates an in-memory gRPC server with the mock agent service
func setupTestServer(t *testing.T, mock *mockAgentServiceServer) (*grpc.Server, *bufconn.Listener, func()) {
	t.Helper()

	lis := bufconn.Listen(bufSize)
	srv := grpc.NewServer()
	agentpb.RegisterAgentServiceServer(srv, mock)

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

// createTestClient creates a GRPCAgentClient connected to the test server
func createTestClient(t *testing.T, lis *bufconn.Listener) *GRPCAgentClient {
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

	client := agentpb.NewAgentServiceClient(conn)

	// Fetch descriptor
	descCtx, descCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer descCancel()

	descriptor, err := client.GetDescriptor(descCtx, &agentpb.GetDescriptorRequest{})
	require.NoError(t, err)

	// Fetch slots
	slotCtx, slotCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer slotCancel()

	slotResp, err := client.GetSlotSchema(slotCtx, &agentpb.GetSlotSchemaRequest{})
	require.NoError(t, err)

	// Create agent descriptor
	agentDescriptor := &AgentDescriptor{
		Name:           descriptor.Name,
		Version:        descriptor.Version,
		Description:    descriptor.Description,
		Capabilities:   descriptor.Capabilities,
		TargetTypes:    convertTargetTypes(descriptor.TargetTypes),
		TechniqueTypes: convertTechniqueTypes(descriptor.TechniqueTypes),
		Slots:          convertSlots(slotResp.Slots),
		IsExternal:     true,
	}

	return &GRPCAgentClient{
		conn:       conn,
		client:     client,
		descriptor: agentDescriptor,
	}
}

func TestNewGRPCAgentClient(t *testing.T) {
	mock := &mockAgentServiceServer{
		descriptor: &agentpb.GetDescriptorResponse{
			Name:           "test-agent",
			Description:    "A test agent",
			Version:        "1.0.0",
			Capabilities:   []string{"prompt_injection", "jailbreak"},
			TargetTypes:    []string{"llm_chat", "llm_api"},
			TechniqueTypes: []string{"prompt_injection"},
		},
		slotSchema: &agentpb.GetSlotSchemaResponse{
			Slots: []*agentpb.AgentSlotDefinition{
				{
					Name:        "primary",
					Description: "Primary LLM for reasoning",
					Required:    true,
					DefaultConfig: &agentpb.AgentSlotConfig{
						Provider:    "anthropic",
						Model:       "claude-3-opus-20240229",
						Temperature: 0.7,
						MaxTokens:   4096,
					},
					Constraints: &agentpb.AgentSlotConstraints{
						MinContextWindow: 100000,
						RequiredFeatures: []string{"tool_use"},
					},
				},
			},
		},
	}

	_, lis, cleanup := setupTestServer(t, mock)
	defer cleanup()

	// Create dialer for bufconn
	bufDialer := func(ctx context.Context, s string) (net.Conn, error) {
		return lis.Dial()
	}

	// Test successful client creation (without WithBlock to avoid timeout issues)
	client, err := NewGRPCAgentClient(
		"bufnet",
		grpc.WithContextDialer(bufDialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	require.NotNil(t, client)
	defer client.Close()

	// Verify metadata
	assert.Equal(t, "test-agent", client.Name())
	assert.Equal(t, "A test agent", client.Description())
	assert.Equal(t, "1.0.0", client.Version())
	assert.Equal(t, []string{"prompt_injection", "jailbreak"}, client.Capabilities())
	assert.Equal(t, []types.TargetType{"llm_chat", "llm_api"}, client.TargetTypes())
	assert.Equal(t, []types.TechniqueType{"prompt_injection"}, client.TechniqueTypes())

	// Verify slots
	slots := client.LLMSlots()
	require.Len(t, slots, 1)
	assert.Equal(t, "primary", slots[0].Name)
	assert.Equal(t, "Primary LLM for reasoning", slots[0].Description)
	assert.True(t, slots[0].Required)
	assert.Equal(t, "anthropic", slots[0].Default.Provider)
	assert.Equal(t, "claude-3-opus-20240229", slots[0].Default.Model)
	assert.Equal(t, 100000, slots[0].Constraints.MinContextWindow)
	assert.Equal(t, []string{"tool_use"}, slots[0].Constraints.RequiredFeatures)
}

func TestNewGRPCAgentClient_ConnectionFailure(t *testing.T) {
	// Try to connect to a non-existent endpoint
	_, err := NewGRPCAgentClient("localhost:99999")

	// Should fail during GetDescriptor
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to fetch agent descriptor")
}

func TestNewGRPCAgentClient_DescriptorFailure(t *testing.T) {
	mock := &mockAgentServiceServer{
		descriptorError: status.Error(codes.Internal, "descriptor fetch failed"),
	}

	_, lis, cleanup := setupTestServer(t, mock)
	defer cleanup()

	bufDialer := func(ctx context.Context, s string) (net.Conn, error) {
		return lis.Dial()
	}

	_, err := NewGRPCAgentClient(
		"bufnet",
		grpc.WithContextDialer(bufDialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to fetch agent descriptor")
}

func TestNewGRPCAgentClient_SlotSchemaFailure(t *testing.T) {
	mock := &mockAgentServiceServer{
		descriptor: &agentpb.GetDescriptorResponse{
			Name:        "test-agent",
			Description: "A test agent",
			Version:     "1.0.0",
		},
		slotSchemaError: status.Error(codes.Internal, "slot schema fetch failed"),
	}

	_, lis, cleanup := setupTestServer(t, mock)
	defer cleanup()

	bufDialer := func(ctx context.Context, s string) (net.Conn, error) {
		return lis.Dial()
	}

	_, err := NewGRPCAgentClient(
		"bufnet",
		grpc.WithContextDialer(bufDialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to fetch agent slots")
}

func TestGRPCAgentClient_Execute_Success(t *testing.T) {
	result := Result{
		TaskID: types.NewID(),
		Status: ResultStatusCompleted,
		Output: map[string]any{
			"success": true,
			"data":    "test result",
		},
		Findings: []Finding{},
	}

	mock := &mockAgentServiceServer{
		descriptor: &agentpb.GetDescriptorResponse{
			Name:        "test-agent",
			Description: "A test agent",
			Version:     "1.0.0",
		},
		executeResponse: &agentpb.ExecuteResponse{
			Result: ResultToProto(result),
		},
	}

	_, lis, cleanup := setupTestServer(t, mock)
	defer cleanup()

	client := createTestClient(t, lis)
	defer client.Close()

	// Create test task
	task := NewTask("test-task", "Test task description", map[string]any{
		"target": "test-target",
	})

	// Execute
	ctx := context.Background()
	execResult, err := client.Execute(ctx, task, nil)
	require.NoError(t, err)
	require.NotNil(t, execResult)

	assert.Equal(t, ResultStatusCompleted, execResult.Status)
	assert.Equal(t, true, execResult.Output["success"])
	assert.Equal(t, "test result", execResult.Output["data"])
}

func TestGRPCAgentClient_Execute_WithError(t *testing.T) {
	mock := &mockAgentServiceServer{
		descriptor: &agentpb.GetDescriptorResponse{
			Name:        "test-agent",
			Description: "A test agent",
			Version:     "1.0.0",
		},
		executeResponse: &agentpb.ExecuteResponse{
			Error: &commonpb.Error{
				Code:      "agent_execution_failed",
				Message:   "agent failed to execute",
				Retryable: false,
			},
		},
	}

	_, lis, cleanup := setupTestServer(t, mock)
	defer cleanup()

	client := createTestClient(t, lis)
	defer client.Close()

	task := NewTask("test-task", "Test task description", map[string]any{})

	ctx := context.Background()
	result, err := client.Execute(ctx, task, nil)
	require.NoError(t, err) // Error is in result, not returned

	assert.Equal(t, ResultStatusFailed, result.Status)
	require.NotNil(t, result.Error)
	assert.Contains(t, result.Error.Message, "agent_execution_failed")
}

func TestGRPCAgentClient_Execute_GRPCError(t *testing.T) {
	mock := &mockAgentServiceServer{
		descriptor: &agentpb.GetDescriptorResponse{
			Name:        "test-agent",
			Description: "A test agent",
			Version:     "1.0.0",
		},
		executeError: status.Error(codes.Unavailable, "service unavailable"),
	}

	_, lis, cleanup := setupTestServer(t, mock)
	defer cleanup()

	client := createTestClient(t, lis)
	defer client.Close()

	task := NewTask("test-task", "Test task description", map[string]any{})

	ctx := context.Background()
	result, err := client.Execute(ctx, task, nil)
	require.NoError(t, err) // Error is in result, not returned

	assert.Equal(t, ResultStatusFailed, result.Status)
	require.NotNil(t, result.Error)
	assert.Contains(t, result.Error.Message, "gRPC agent execution failed")
}

func TestGRPCAgentClient_Execute_NilResult(t *testing.T) {
	mock := &mockAgentServiceServer{
		descriptor: &agentpb.GetDescriptorResponse{
			Name:        "test-agent",
			Description: "A test agent",
			Version:     "1.0.0",
		},
		executeResponse: &agentpb.ExecuteResponse{
			Result: nil, // No result provided
		},
	}

	_, lis, cleanup := setupTestServer(t, mock)
	defer cleanup()

	client := createTestClient(t, lis)
	defer client.Close()

	task := NewTask("test-task", "Test task description", map[string]any{})

	ctx := context.Background()
	result, err := client.Execute(ctx, task, nil)
	// With proto types, we should still get a valid result object, just empty
	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestGRPCAgentClient_Execute_ContextCancellation(t *testing.T) {
	mock := &mockAgentServiceServer{
		descriptor: &agentpb.GetDescriptorResponse{
			Name:        "test-agent",
			Description: "A test agent",
			Version:     "1.0.0",
		},
	}

	_, lis, cleanup := setupTestServer(t, mock)
	defer cleanup()

	client := createTestClient(t, lis)
	defer client.Close()

	// Create a context that's already cancelled
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	task := NewTask("test-task", "Test task description", map[string]any{})

	result, err := client.Execute(ctx, task, nil)
	require.NoError(t, err) // Error is in result

	assert.Equal(t, ResultStatusFailed, result.Status)
	require.NotNil(t, result.Error)
	assert.Contains(t, result.Error.Message, "context canceled")
}

func TestGRPCAgentClient_Health_Healthy(t *testing.T) {
	now := time.Now()
	mock := &mockAgentServiceServer{
		descriptor: &agentpb.GetDescriptorResponse{
			Name:        "test-agent",
			Description: "A test agent",
			Version:     "1.0.0",
		},
		healthResponse: &commonpb.HealthStatus{
			State:     "healthy",
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

	assert.Equal(t, types.HealthStateHealthy, health.State)
	assert.Equal(t, "All systems operational", health.Message)
}

func TestGRPCAgentClient_Health_Unhealthy(t *testing.T) {
	now := time.Now()
	mock := &mockAgentServiceServer{
		descriptor: &agentpb.GetDescriptorResponse{
			Name:        "test-agent",
			Description: "A test agent",
			Version:     "1.0.0",
		},
		healthResponse: &commonpb.HealthStatus{
			State:     "unhealthy",
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

	assert.Equal(t, types.HealthStateUnhealthy, health.State)
	assert.Equal(t, "Database connection failed", health.Message)
}

func TestGRPCAgentClient_Health_Degraded(t *testing.T) {
	now := time.Now()
	mock := &mockAgentServiceServer{
		descriptor: &agentpb.GetDescriptorResponse{
			Name:        "test-agent",
			Description: "A test agent",
			Version:     "1.0.0",
		},
		healthResponse: &commonpb.HealthStatus{
			State:     "degraded",
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

	assert.Equal(t, types.HealthStateDegraded, health.State)
	assert.Equal(t, "High latency detected", health.Message)
}

func TestGRPCAgentClient_Health_GRPCError(t *testing.T) {
	mock := &mockAgentServiceServer{
		descriptor: &agentpb.GetDescriptorResponse{
			Name:        "test-agent",
			Description: "A test agent",
			Version:     "1.0.0",
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

func TestGRPCAgentClient_Initialize(t *testing.T) {
	mock := &mockAgentServiceServer{
		descriptor: &agentpb.GetDescriptorResponse{
			Name:        "test-agent",
			Description: "A test agent",
			Version:     "1.0.0",
		},
	}

	_, lis, cleanup := setupTestServer(t, mock)
	defer cleanup()

	client := createTestClient(t, lis)
	defer client.Close()

	ctx := context.Background()
	cfg := NewAgentConfig("test-agent")

	// Initialize should not error (it's a no-op for gRPC agents)
	err := client.Initialize(ctx, cfg)
	assert.NoError(t, err)
}

func TestGRPCAgentClient_Shutdown(t *testing.T) {
	mock := &mockAgentServiceServer{
		descriptor: &agentpb.GetDescriptorResponse{
			Name:        "test-agent",
			Description: "A test agent",
			Version:     "1.0.0",
		},
	}

	_, lis, cleanup := setupTestServer(t, mock)
	defer cleanup()

	client := createTestClient(t, lis)

	ctx := context.Background()

	// Shutdown should not error
	err := client.Shutdown(ctx)
	assert.NoError(t, err)

	// Subsequent operations should fail with connection closed error
	health := client.Health(ctx)
	assert.Equal(t, types.HealthStateUnhealthy, health.State)
}

func TestGRPCAgentClient_Close(t *testing.T) {
	mock := &mockAgentServiceServer{
		descriptor: &agentpb.GetDescriptorResponse{
			Name:        "test-agent",
			Description: "A test agent",
			Version:     "1.0.0",
		},
	}

	_, lis, cleanup := setupTestServer(t, mock)
	defer cleanup()

	client := createTestClient(t, lis)

	// Close should not error
	err := client.Close()
	assert.NoError(t, err)
}

func TestGRPCAgentClient_Close_NilConnection(t *testing.T) {
	client := &GRPCAgentClient{
		conn: nil,
	}

	// Should not panic or error with nil connection
	err := client.Close()
	assert.NoError(t, err)
}

func TestGRPCAgentClient_SupportsStreaming(t *testing.T) {
	mock := &mockAgentServiceServer{
		descriptor: &agentpb.GetDescriptorResponse{
			Name:        "test-agent",
			Description: "A test agent",
			Version:     "1.0.0",
		},
	}

	_, lis, cleanup := setupTestServer(t, mock)
	defer cleanup()

	client := createTestClient(t, lis)
	defer client.Close()

	// Should support streaming (has valid connection)
	assert.True(t, client.SupportsStreaming())
}

func TestGRPCAgentClient_SupportsStreaming_NilConnection(t *testing.T) {
	client := &GRPCAgentClient{
		conn: nil,
	}

	// Should not support streaming (no connection)
	assert.False(t, client.SupportsStreaming())
}

func TestGRPCAgentClient_Metadata(t *testing.T) {
	mock := &mockAgentServiceServer{
		descriptor: &agentpb.GetDescriptorResponse{
			Name:           "advanced-jailbreak-agent",
			Description:    "Advanced jailbreak testing agent with multi-turn adversarial techniques",
			Version:        "2.1.3",
			Capabilities:   []string{"jailbreak", "adversarial", "multi_turn"},
			TargetTypes:    []string{"llm_chat", "llm_api", "rag_system"},
			TechniqueTypes: []string{"jailbreak", "prompt_injection", "context_manipulation"},
		},
	}

	_, lis, cleanup := setupTestServer(t, mock)
	defer cleanup()

	client := createTestClient(t, lis)
	defer client.Close()

	assert.Equal(t, "advanced-jailbreak-agent", client.Name())
	assert.Equal(t, "Advanced jailbreak testing agent with multi-turn adversarial techniques", client.Description())
	assert.Equal(t, "2.1.3", client.Version())
	assert.Equal(t, []string{"jailbreak", "adversarial", "multi_turn"}, client.Capabilities())
	assert.Equal(t, []types.TargetType{"llm_chat", "llm_api", "rag_system"}, client.TargetTypes())
	assert.Equal(t, []types.TechniqueType{"jailbreak", "prompt_injection", "context_manipulation"}, client.TechniqueTypes())
}

func TestConvertSlots_NilInput(t *testing.T) {
	result := convertSlots(nil)
	assert.Empty(t, result)
}

func TestConvertSlots_EmptyInput(t *testing.T) {
	result := convertSlots([]*agentpb.AgentSlotDefinition{})
	assert.Empty(t, result)
}

func TestConvertSlots_ValidInput(t *testing.T) {
	protoSlots := []*agentpb.AgentSlotDefinition{
		{
			Name:        "primary",
			Description: "Primary LLM",
			Required:    true,
			DefaultConfig: &agentpb.AgentSlotConfig{
				Provider:    "anthropic",
				Model:       "claude-3-opus-20240229",
				Temperature: 0.7,
				MaxTokens:   4096,
			},
			Constraints: &agentpb.AgentSlotConstraints{
				MinContextWindow: 100000,
				RequiredFeatures: []string{"tool_use", "vision"},
			},
		},
		{
			Name:        "secondary",
			Description: "Secondary LLM for validation",
			Required:    false,
			DefaultConfig: &agentpb.AgentSlotConfig{
				Provider:    "openai",
				Model:       "gpt-4-turbo",
				Temperature: 0.5,
				MaxTokens:   2048,
			},
			Constraints: &agentpb.AgentSlotConstraints{
				MinContextWindow: 50000,
				RequiredFeatures: []string{},
			},
		},
	}

	result := convertSlots(protoSlots)
	require.Len(t, result, 2)

	// Check first slot
	assert.Equal(t, "primary", result[0].Name)
	assert.Equal(t, "Primary LLM", result[0].Description)
	assert.True(t, result[0].Required)
	assert.Equal(t, "anthropic", result[0].Default.Provider)
	assert.Equal(t, "claude-3-opus-20240229", result[0].Default.Model)
	assert.Equal(t, 0.7, result[0].Default.Temperature)
	assert.Equal(t, 4096, result[0].Default.MaxTokens)
	assert.Equal(t, 100000, result[0].Constraints.MinContextWindow)
	assert.Equal(t, []string{"tool_use", "vision"}, result[0].Constraints.RequiredFeatures)

	// Check second slot
	assert.Equal(t, "secondary", result[1].Name)
	assert.False(t, result[1].Required)
	assert.Equal(t, "openai", result[1].Default.Provider)
	assert.Equal(t, 50000, result[1].Constraints.MinContextWindow)
}
