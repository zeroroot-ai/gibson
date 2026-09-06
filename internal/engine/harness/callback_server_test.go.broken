package harness

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewCallbackServer tests the callback server constructor.
func TestNewCallbackServer(t *testing.T) {
	t.Run("with default logger", func(t *testing.T) {
		server := NewCallbackServer(nil, 50051)
		require.NotNil(t, server)
		assert.NotNil(t, server.logger)
		assert.NotNil(t, server.service)
		assert.Equal(t, 50051, server.port)
	})

	t.Run("with custom logger", func(t *testing.T) {
		logger := slog.Default()
		server := NewCallbackServer(logger, 50052)
		require.NotNil(t, server)
		assert.NotNil(t, server.logger)
		assert.NotNil(t, server.service)
		assert.Equal(t, 50052, server.port)
	})
}

// TestNewCallbackServerWithRegistry tests the callback server constructor with registry.
func TestNewCallbackServerWithRegistry(t *testing.T) {
	logger := slog.Default()
	registry := NewCallbackHarnessRegistry()

	server := NewCallbackServerWithRegistry(logger, 50053, registry)
	require.NotNil(t, server)
	assert.NotNil(t, server.logger)
	assert.NotNil(t, server.service)
	assert.Equal(t, 50053, server.port)
	assert.NotNil(t, server.service.registry)
}

// TestCallbackServerService tests the Service method.
func TestCallbackServerService(t *testing.T) {
	server := NewCallbackServer(nil, 50054)
	service := server.Service()
	assert.NotNil(t, service)
	assert.Equal(t, server.service, service)
}

// TestCallbackServer_StartWithKeepalive tests that the server starts with keepalive options.
func TestCallbackServer_StartWithKeepalive(t *testing.T) {
	logger := slog.Default()
	server := NewCallbackServer(logger, 0) // Use port 0 for random available port

	// Create a context with timeout for the server
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Start the server in a goroutine
	serverErr := make(chan error, 1)
	go func() {
		err := server.Start(ctx)
		serverErr <- err
	}()

	// Give the server time to start
	time.Sleep(500 * time.Millisecond)

	// Verify the server is running by checking if it was created
	assert.NotNil(t, server.server, "gRPC server should be initialized")

	// Stop the server gracefully
	server.Stop()

	// Wait for server to finish
	err := <-serverErr
	// Context cancellation is expected
	if err != nil {
		assert.Equal(t, context.DeadlineExceeded, err, "expected context deadline exceeded")
	}
}

// TestCallbackServerRegisterHarness tests harness registration.
func TestCallbackServerRegisterHarness(t *testing.T) {
	server := NewCallbackServer(nil, 50055)

	// Create a mock harness using the existing mock from planning_harness_test.go
	mockHarness := new(mockAgentHarness)

	// Register the harness
	taskID := "task-123"
	server.RegisterHarness(taskID, mockHarness)

	// Verify the harness was registered in the service
	h, ok := server.service.activeHarnesses.Load(taskID)
	assert.True(t, ok, "harness should be registered")
	assert.Equal(t, mockHarness, h)
}

// TestCallbackServerUnregisterHarness tests harness unregistration.
func TestCallbackServerUnregisterHarness(t *testing.T) {
	server := NewCallbackServer(nil, 50056)

	// Create a mock harness using the existing mock from planning_harness_test.go
	mockHarness := new(mockAgentHarness)

	// Register the harness
	taskID := "task-456"
	server.RegisterHarness(taskID, mockHarness)

	// Verify it's registered
	_, ok := server.service.activeHarnesses.Load(taskID)
	assert.True(t, ok, "harness should be registered")

	// Unregister the harness
	server.UnregisterHarness(taskID)

	// Verify it's no longer registered
	_, ok = server.service.activeHarnesses.Load(taskID)
	assert.False(t, ok, "harness should be unregistered")
}

// TestCallbackServerStopWithoutStart tests that Stop can be called safely without Start.
func TestCallbackServerStopWithoutStart(t *testing.T) {
	server := NewCallbackServer(nil, 50057)

	// Stop should not panic even if server was never started
	assert.NotPanics(t, func() {
		server.Stop()
	})
}
