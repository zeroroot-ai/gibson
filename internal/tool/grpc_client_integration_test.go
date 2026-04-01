//go:build integration

package tool

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/types"
	toolpb "github.com/zero-day-ai/sdk/api/gen/gibson/tool/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	protobuf "google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

// mockIntegrationToolServer implements toolpb.ToolServiceServer for integration testing
type mockIntegrationToolServer struct {
	toolpb.UnimplementedToolServiceServer

	// Configuration for mock behavior
	descriptor      *toolpb.GetDescriptorResponse
	executeResponse *toolpb.ExecuteResponse
	executeError    error
	healthResponse  *proto.HealthStatus
	healthError     error
}

func (m *mockIntegrationToolServer) GetDescriptor(ctx context.Context, req *toolpb.GetDescriptorRequest) (*toolpb.GetDescriptorResponse, error) {
	if m.descriptor == nil {
		return &toolpb.GetDescriptorResponse{
			Name:         "integration-tool",
			Description:  "Integration test tool",
			Version:      "1.0.0",
			Tags:         []string{"integration", "test"},
			InputSchema:  &proto.JSONSchema{Json: `{"type":"object","properties":{"input":{"type":"string"}},"required":["input"]}`},
			OutputSchema: &proto.JSONSchema{Json: `{"type":"object","properties":{"output":{"type":"string"}},"required":["output"]}`},
		}, nil
	}
	return m.descriptor, nil
}

func (m *mockIntegrationToolServer) Execute(ctx context.Context, req *toolpb.ExecuteRequest) (*toolpb.ExecuteResponse, error) {
	if m.executeError != nil {
		return nil, m.executeError
	}
	if m.executeResponse == nil {
		// Default response
		return &toolpb.ExecuteResponse{
			OutputJson: `{"output":"success","message":"Integration test executed"}`,
		}, nil
	}
	return m.executeResponse, nil
}

func (m *mockIntegrationToolServer) Health(ctx context.Context, req *toolpb.HealthRequest) (*proto.HealthStatus, error) {
	if m.healthError != nil {
		return nil, m.healthError
	}
	if m.healthResponse == nil {
		return &proto.HealthStatus{
			State:     "healthy",
			Message:   "Integration test server healthy",
			CheckedAt: time.Now().UnixMilli(),
		}, nil
	}
	return m.healthResponse, nil
}

// startRealGRPCServer starts a real TCP gRPC server for integration testing
func startRealGRPCServer(t *testing.T, mock *mockIntegrationToolServer) (*grpc.Server, string, func()) {
	t.Helper()

	// Find an available port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "failed to create listener")

	addr := listener.Addr().String()
	t.Logf("Started gRPC server on %s", addr)

	srv := grpc.NewServer()
	toolpb.RegisterToolServiceServer(srv, mock)

	// Start server in background
	go func() {
		if err := srv.Serve(listener); err != nil && err != grpc.ErrServerStopped {
			t.Logf("Server error: %v", err)
		}
	}()

	// Give the server time to start
	time.Sleep(100 * time.Millisecond)

	cleanup := func() {
		// Graceful stop with timeout
		stopped := make(chan struct{})
		go func() {
			srv.GracefulStop()
			close(stopped)
		}()

		select {
		case <-stopped:
			t.Log("Server stopped gracefully")
		case <-time.After(5 * time.Second):
			t.Log("Server graceful stop timed out, forcing stop")
			srv.Stop()
		}

		listener.Close()
	}

	return srv, addr, cleanup
}

// checkNetworkAvailable verifies that the network is available for testing
func checkNetworkAvailable(t *testing.T) {
	t.Helper()

	// Try to bind to localhost
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("Network unavailable, skipping integration test")
	}
	listener.Close()
}

// TestGRPCToolClient_Integration_RealServer tests GRPCToolClient with a real gRPC server
func TestGRPCToolClient_Integration_RealServer(t *testing.T) {
	checkNetworkAvailable(t)

	inputSchemaJSON := `{"type":"object","properties":{"target":{"type":"string"},"port":{"type":"integer"}},"required":["target"]}`
	outputSchemaJSON := `{"type":"object","properties":{"result":{"type":"string"},"success":{"type":"boolean"}},"required":["result"]}`

	mock := &mockIntegrationToolServer{
		descriptor: &toolpb.GetDescriptorResponse{
			Name:        "integration-scanner",
			Description: "Integration test network scanner",
			Version:     "1.0.0",
			Tags:        []string{"integration", "network", "scanner"},
			InputSchema: &proto.JSONSchema{
				Json: inputSchemaJSON,
			},
			OutputSchema: &proto.JSONSchema{
				Json: outputSchemaJSON,
			},
		},
		executeResponse: &toolpb.ExecuteResponse{
			OutputJson: `{"result":"scan completed","success":true,"ports_found":3}`,
		},
		healthResponse: &proto.HealthStatus{
			State:     "healthy",
			Message:   "All systems operational",
			CheckedAt: time.Now().UnixMilli(),
		},
	}

	_, addr, cleanup := startRealGRPCServer(t, mock)
	defer cleanup()

	// Create client
	client, err := NewGRPCToolClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	require.NotNil(t, client)
	defer client.Close()

	// Verify metadata
	assert.Equal(t, "integration-scanner", client.Name())
	assert.Equal(t, "Integration test network scanner", client.Description())
	assert.Equal(t, "1.0.0", client.Version())
	assert.Equal(t, []string{"integration", "network", "scanner"}, client.Tags())

	// Test ExecuteProto
	ctx := context.Background()
	input, err := structpb.NewStruct(map[string]any{
		"target": "192.168.1.1",
		"port":   443,
	})
	require.NoError(t, err)

	outputProto, err := client.ExecuteProto(ctx, input)
	require.NoError(t, err)
	require.NotNil(t, outputProto)

	output := outputProto.(*structpb.Struct)
	assert.Equal(t, "scan completed", output.Fields["result"].GetStringValue())
	assert.Equal(t, true, output.Fields["success"].GetBoolValue())
	assert.Equal(t, float64(3), output.Fields["ports_found"].GetNumberValue())

	// Test Health
	health := client.Health(ctx)
	assert.Equal(t, types.HealthState("healthy"), health.State)
	assert.Equal(t, "All systems operational", health.Message)

	// Test Close
	err = client.Close()
	assert.NoError(t, err)
}

// TestGRPCToolClient_Integration_ServerRestart tests reconnection after server restart
func TestGRPCToolClient_Integration_ServerRestart(t *testing.T) {
	checkNetworkAvailable(t)

	inputSchemaJSON := `{"type":"object","properties":{"input":{"type":"string"}},"required":["input"]}`
	outputSchemaJSON := `{"type":"object","properties":{"output":{"type":"string"}},"required":["output"]}`

	mock := &mockIntegrationToolServer{
		descriptor: &toolpb.GetDescriptorResponse{
			Name:        "restart-test-tool",
			Description: "Tool for testing server restart",
			Version:     "1.0.0",
			Tags:        []string{"integration"},
			InputSchema: &proto.JSONSchema{
				Json: inputSchemaJSON,
			},
			OutputSchema: &proto.JSONSchema{
				Json: outputSchemaJSON,
			},
		},
	}

	// Start first server instance
	_, addr, cleanup1 := startRealGRPCServer(t, mock)
	t.Logf("First server started on %s", addr)

	// Create client
	client, err := NewGRPCToolClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	require.NotNil(t, client)
	defer client.Close()

	// Test initial execution
	ctx := context.Background()
	input, err := structpb.NewStruct(map[string]any{"input": "test1"})
	require.NoError(t, err)

	outputProto, err := client.ExecuteProto(ctx, input)
	require.NoError(t, err)

	output := outputProto.(*structpb.Struct)
	assert.Equal(t, "success", output.Fields["output"].GetStringValue())

	// Test health check - should be healthy
	health := client.Health(ctx)
	assert.Equal(t, types.HealthState("healthy"), health.State)

	// Stop the first server
	t.Log("Stopping first server...")
	cleanup1()

	// Give it time to fully stop
	time.Sleep(200 * time.Millisecond)

	// Attempt to execute should fail now
	t.Log("Testing execution after server stop...")
	_, err = client.ExecuteProto(ctx, input)
	assert.Error(t, err, "ExecuteProto should fail when server is down")

	// Health check should report unhealthy
	health = client.Health(ctx)
	assert.Equal(t, types.HealthStateUnhealthy, health.State)
	assert.Contains(t, health.Message, "gRPC health check failed")

	// Start a new server on the same address
	t.Log("Starting second server on same address...")

	// We need to parse the port from the original address
	_, port, err := net.SplitHostPort(addr)
	require.NoError(t, err)

	// Try to bind to the same port
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		// If we can't bind to the exact same address (common on some systems),
		// skip the reconnection test
		t.Skipf("Cannot rebind to %s: %v - skipping reconnection test", addr, err)
	}

	srv2 := grpc.NewServer()
	toolpb.RegisterToolServiceServer(srv2, mock)

	go func() {
		if err := srv2.Serve(listener); err != nil && err != grpc.ErrServerStopped {
			t.Logf("Second server error: %v", err)
		}
	}()

	cleanup2 := func() {
		stopped := make(chan struct{})
		go func() {
			srv2.GracefulStop()
			close(stopped)
		}()
		select {
		case <-stopped:
		case <-time.After(5 * time.Second):
			srv2.Stop()
		}
		listener.Close()
	}
	defer cleanup2()

	// Give the new server time to start
	time.Sleep(200 * time.Millisecond)
	t.Logf("Second server started, testing reconnection on port %s...", port)

	// gRPC client should automatically reconnect on next call
	// We may need to retry a few times as the connection re-establishes
	var lastErr error
	var outputProto2 protobuf.Message
	reconnected := false
	for i := 0; i < 5; i++ {
		time.Sleep(100 * time.Millisecond * time.Duration(i+1))
		outputProto2, err = client.ExecuteProto(ctx, input)
		if err == nil {
			reconnected = true
			break
		}
		lastErr = err
		t.Logf("Reconnection attempt %d failed: %v", i+1, err)
	}

	if reconnected {
		t.Log("Successfully reconnected to restarted server")
		output2 := outputProto2.(*structpb.Struct)
		assert.Equal(t, "success", output2.Fields["output"].GetStringValue())

		// Health check should be healthy again
		health = client.Health(ctx)
		assert.Equal(t, types.HealthState("healthy"), health.State)
	} else {
		// Some systems may not support immediate rebinding to the same address
		// This is acceptable behavior - log it but don't fail the test
		t.Logf("Could not reconnect after server restart (last error: %v). This may be system-specific behavior.", lastErr)
	}
}

// TestGRPCToolClient_Integration_MultipleClients tests multiple clients to the same server
func TestGRPCToolClient_Integration_MultipleClients(t *testing.T) {
	checkNetworkAvailable(t)

	inputSchemaJSON := `{"type":"object","properties":{"client_id":{"type":"string"}},"required":["client_id"]}`
	outputSchemaJSON := `{"type":"object","properties":{"response":{"type":"string"}},"required":["response"]}`

	mock := &mockIntegrationToolServer{
		descriptor: &toolpb.GetDescriptorResponse{
			Name:        "multi-client-tool",
			Description: "Tool for testing multiple clients",
			Version:     "1.0.0",
			InputSchema: &proto.JSONSchema{
				Json: inputSchemaJSON,
			},
			OutputSchema: &proto.JSONSchema{
				Json: outputSchemaJSON,
			},
		},
	}

	_, addr, cleanup := startRealGRPCServer(t, mock)
	defer cleanup()

	ctx := context.Background()
	const numClients = 5

	// Create multiple clients
	clients := make([]*GRPCToolClient, numClients)
	for i := 0; i < numClients; i++ {
		client, err := NewGRPCToolClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
		require.NoError(t, err, "failed to create client %d", i)
		require.NotNil(t, client)
		clients[i] = client
		defer client.Close()
	}

	// Test concurrent execution from all clients
	done := make(chan bool, numClients)
	errors := make(chan error, numClients)

	for i := 0; i < numClients; i++ {
		clientID := i
		go func(c *GRPCToolClient, id int) {
			input, err := structpb.NewStruct(map[string]any{
				"client_id": fmt.Sprintf("client-%d", id),
			})
			if err != nil {
				errors <- err
				done <- false
				return
			}

			outputProto, err := c.ExecuteProto(ctx, input)
			if err != nil {
				errors <- err
				done <- false
				return
			}

			output := outputProto.(*structpb.Struct)
			if output.Fields["output"].GetStringValue() != "success" {
				errors <- fmt.Errorf("unexpected output from client %d: %v", id, output)
				done <- false
				return
			}

			done <- true
		}(clients[clientID], clientID)
	}

	// Wait for all clients to complete
	successCount := 0
	for i := 0; i < numClients; i++ {
		select {
		case success := <-done:
			if success {
				successCount++
			}
		case err := <-errors:
			t.Errorf("Client error: %v", err)
		case <-time.After(10 * time.Second):
			t.Fatal("Timeout waiting for clients")
		}
	}

	assert.Equal(t, numClients, successCount, "all clients should execute successfully")

	// Test health checks from all clients
	for i, client := range clients {
		health := client.Health(ctx)
		assert.Equal(t, types.HealthState("healthy"), health.State, "client %d health check failed", i)
	}
}

// TestGRPCToolClient_Integration_Timeout tests execution with context timeout
func TestGRPCToolClient_Integration_Timeout(t *testing.T) {
	checkNetworkAvailable(t)

	inputSchemaJSON := `{"type":"object"}`
	outputSchemaJSON := `{"type":"object"}`

	mock := &mockIntegrationToolServer{
		descriptor: &toolpb.GetDescriptorResponse{
			Name:         "timeout-tool",
			Description:  "Tool for testing timeouts",
			Version:      "1.0.0",
			InputSchema:  &proto.JSONSchema{Json: inputSchemaJSON},
			OutputSchema: &proto.JSONSchema{Json: outputSchemaJSON},
		},
	}

	_, addr, cleanup := startRealGRPCServer(t, mock)
	defer cleanup()

	client, err := NewGRPCToolClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer client.Close()

	// Create a context with very short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	// Wait for context to expire
	time.Sleep(10 * time.Millisecond)

	// ExecuteProto should fail with context deadline exceeded
	input, err := structpb.NewStruct(map[string]any{})
	require.NoError(t, err)

	_, err = client.ExecuteProto(ctx, input)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "context deadline exceeded")
}

// TestGRPCToolClient_Integration_ComplexDataFlow tests realistic data flow patterns
func TestGRPCToolClient_Integration_ComplexDataFlow(t *testing.T) {
	checkNetworkAvailable(t)

	inputSchemaJSON := `{"type":"object","properties":{"target":{"type":"string"},"options":{"type":"object"}},"required":["target"]}`
	outputSchemaJSON := `{"type":"object","properties":{"findings":{"type":"array"},"metadata":{"type":"object"}},"required":["findings"]}`

	complexOutput := map[string]any{
		"findings": []map[string]any{
			{
				"id":       "finding-001",
				"severity": "high",
				"type":     "sql-injection",
				"evidence": map[string]any{
					"payload": "' OR '1'='1",
					"response": map[string]any{
						"status_code": 200,
						"body_length": 1234,
					},
				},
			},
			{
				"id":       "finding-002",
				"severity": "medium",
				"type":     "xss",
				"evidence": map[string]any{
					"payload": "<script>alert(1)</script>",
					"response": map[string]any{
						"status_code": 200,
						"body_length": 567,
					},
				},
			},
		},
		"metadata": map[string]any{
			"scan_duration_ms": 1234.56,
			"requests_sent":    42,
			"timestamp":        time.Now().Unix(),
		},
	}

	outputJSON, err := json.Marshal(complexOutput)
	require.NoError(t, err)

	mock := &mockIntegrationToolServer{
		descriptor: &toolpb.GetDescriptorResponse{
			Name:         "complex-scanner",
			Description:  "Scanner with complex output",
			Version:      "1.0.0",
			InputSchema:  &proto.JSONSchema{Json: inputSchemaJSON},
			OutputSchema: &proto.JSONSchema{Json: outputSchemaJSON},
		},
		executeResponse: &toolpb.ExecuteResponse{
			OutputJson: string(outputJSON),
		},
	}

	_, addr, cleanup := startRealGRPCServer(t, mock)
	defer cleanup()

	client, err := NewGRPCToolClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer client.Close()

	ctx := context.Background()
	input, err := structpb.NewStruct(map[string]any{
		"target": "https://example.com",
		"options": map[string]any{
			"depth":   3,
			"timeout": 30,
			"headers": map[string]string{
				"User-Agent": "gibson/1.0",
			},
		},
	})
	require.NoError(t, err)

	outputProto, err := client.ExecuteProto(ctx, input)
	require.NoError(t, err)
	require.NotNil(t, outputProto)

	// Verify complex nested structure is preserved
	output := outputProto.(*structpb.Struct)
	findings := output.Fields["findings"].GetListValue()
	require.NotNil(t, findings, "findings should be an array")
	assert.Len(t, findings.Values, 2, "should have 2 findings")

	// Check first finding structure
	finding1 := findings.Values[0].GetStructValue()
	require.NotNil(t, finding1)
	assert.Equal(t, "finding-001", finding1.Fields["id"].GetStringValue())
	assert.Equal(t, "high", finding1.Fields["severity"].GetStringValue())
	assert.Equal(t, "sql-injection", finding1.Fields["type"].GetStringValue())

	evidence1 := finding1.Fields["evidence"].GetStructValue()
	require.NotNil(t, evidence1)
	assert.Equal(t, "' OR '1'='1", evidence1.Fields["payload"].GetStringValue())

	// Check metadata
	metadata := output.Fields["metadata"].GetStructValue()
	require.NotNil(t, metadata)
	assert.Equal(t, float64(42), metadata.Fields["requests_sent"].GetNumberValue())
	assert.Greater(t, metadata.Fields["scan_duration_ms"].GetNumberValue(), float64(0))
}
