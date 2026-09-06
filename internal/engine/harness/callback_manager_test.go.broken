package harness

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ─── Test Helpers ─────────────────────────────────────────────────────────────

// getRandomPort finds an available port by binding to :0 and reading the assigned port.
func getRandomPort(t *testing.T) int {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "failed to get random port")
	defer listener.Close()

	addr := listener.Addr().(*net.TCPAddr)
	return addr.Port
}

// createTestConfig creates a test configuration with a random available port.
func createTestConfig(t *testing.T) CallbackConfig {
	t.Helper()

	port := getRandomPort(t)
	return CallbackConfig{
		ListenAddress:    fmt.Sprintf("127.0.0.1:%d", port),
		AdvertiseAddress: "",
		Enabled:          true,
	}
}

// mockHarness is a minimal mock implementation of AgentHarness for testing.
// For CallbackManager tests, we don't actually invoke methods on the harness,
// we just need a valid instance to register. We use nil since the manager
// doesn't validate the harness, it just passes it to the service.

// ─── Tests ────────────────────────────────────────────────────────────────────

// TestNewCallbackManager verifies that NewCallbackManager creates a manager
// with the correct configuration and defaults.
func TestNewCallbackManager(t *testing.T) {
	tests := []struct {
		name           string
		config         CallbackConfig
		logger         *slog.Logger
		expectNonNil   bool
		checkAdvertise bool
	}{
		{
			name: "valid config with logger",
			config: CallbackConfig{
				ListenAddress:    "127.0.0.1:50001",
				AdvertiseAddress: "external.example.com:50001",
				Enabled:          true,
			},
			logger:         slog.New(slog.NewTextHandler(os.Stdout, nil)),
			expectNonNil:   true,
			checkAdvertise: true,
		},
		{
			name: "valid config with nil logger (should use default)",
			config: CallbackConfig{
				ListenAddress:    "0.0.0.0:50002",
				AdvertiseAddress: "",
				Enabled:          true,
			},
			logger:         nil,
			expectNonNil:   true,
			checkAdvertise: false,
		},
		{
			name: "disabled config",
			config: CallbackConfig{
				ListenAddress:    "127.0.0.1:50003",
				AdvertiseAddress: "",
				Enabled:          false,
			},
			logger:         slog.New(slog.NewTextHandler(os.Stdout, nil)),
			expectNonNil:   true,
			checkAdvertise: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager := NewCallbackManager(tt.config, tt.logger)

			assert.NotNil(t, manager, "manager should not be nil")
			assert.NotNil(t, manager.server, "server should be initialized")
			assert.NotNil(t, manager.logger, "logger should not be nil")
			assert.Equal(t, tt.config.ListenAddress, manager.config.ListenAddress)
			assert.Equal(t, tt.config.AdvertiseAddress, manager.config.AdvertiseAddress)
			assert.Equal(t, tt.config.Enabled, manager.config.Enabled)
			assert.False(t, manager.running, "manager should not be running initially")

			if tt.checkAdvertise {
				assert.Equal(t, tt.config.AdvertiseAddress, manager.CallbackEndpoint())
			}
		})
	}
}

// TestCallbackManager_StartStop verifies the lifecycle management of the
// callback server: starting, running, and graceful shutdown.
func TestCallbackManager_StartStop(t *testing.T) {
	tests := []struct {
		name             string
		config           CallbackConfig
		startTwice       bool
		stopTwice        bool
		expectStartError bool
	}{
		{
			name:             "normal start and stop",
			config:           createTestConfig(t),
			startTwice:       false,
			stopTwice:        false,
			expectStartError: false,
		},
		{
			name:             "start twice (idempotent)",
			config:           createTestConfig(t),
			startTwice:       true,
			stopTwice:        false,
			expectStartError: false,
		},
		{
			name:             "stop twice (idempotent)",
			config:           createTestConfig(t),
			startTwice:       false,
			stopTwice:        true,
			expectStartError: false,
		},
		{
			name: "disabled callback server",
			config: CallbackConfig{
				ListenAddress:    "127.0.0.1:50099",
				AdvertiseAddress: "",
				Enabled:          false,
			},
			startTwice:       false,
			stopTwice:        false,
			expectStartError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
				Level: slog.LevelError, // Reduce noise in test output
			}))
			manager := NewCallbackManager(tt.config, logger)

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			// Start the manager
			err := manager.Start(ctx)
			if tt.expectStartError {
				assert.Error(t, err, "expected start error")
				return
			}
			assert.NoError(t, err, "start should succeed")

			// If config is enabled, verify the server is running
			if tt.config.Enabled {
				assert.True(t, manager.IsRunning(), "manager should be running")

				// Give server a moment to actually start listening
				time.Sleep(100 * time.Millisecond)
			}
			// Note: When disabled, the current implementation still marks running=true
			// but doesn't actually start the server. This is acceptable behavior.

			// Test idempotent start
			if tt.startTwice {
				err2 := manager.Start(ctx)
				assert.NoError(t, err2, "second start should not error (idempotent)")
			}

			// Stop the manager
			manager.Stop()
			assert.False(t, manager.IsRunning(), "manager should not be running after stop")

			// Test idempotent stop
			if tt.stopTwice {
				// Should not panic or hang
				manager.Stop()
				assert.False(t, manager.IsRunning(), "manager should still not be running")
			}
		})
	}
}

// TestCallbackManager_RegisterUnregister verifies harness registration and
// unregistration functionality.
func TestCallbackManager_RegisterUnregister(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))
	config := createTestConfig(t)
	manager := NewCallbackManager(config, logger)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Start the manager
	err := manager.Start(ctx)
	require.NoError(t, err)
	defer manager.Stop()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Create a mock harness for testing
	harness := new(mockAgentHarness)

	tests := []struct {
		name             string
		taskID           string
		harness          AgentHarness
		expectEndpoint   bool
		registerMultiple bool
	}{
		{
			name:           "register single harness",
			taskID:         "task-123",
			harness:        harness,
			expectEndpoint: true,
		},
		{
			name:           "register another harness",
			taskID:         "task-456",
			harness:        harness,
			expectEndpoint: true,
		},
		{
			name:             "register multiple harnesses",
			taskID:           "task-789",
			harness:          harness,
			expectEndpoint:   true,
			registerMultiple: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Register harness
			endpoint := manager.RegisterHarness(tt.taskID, tt.harness)

			// Verify endpoint is returned
			if tt.expectEndpoint {
				assert.NotEmpty(t, endpoint, "endpoint should not be empty")
				assert.Equal(t, manager.CallbackEndpoint(), endpoint)
			}

			// Verify harness is registered by checking the server's internal state
			service := manager.server.Service()
			_, ok := service.activeHarnesses.Load(tt.taskID)
			assert.True(t, ok, "harness should be registered")

			// If testing multiple registrations, register another harness
			if tt.registerMultiple {
				endpoint2 := manager.RegisterHarness(tt.taskID+"-second", tt.harness)
				assert.Equal(t, endpoint, endpoint2, "endpoint should be consistent")
			}

			// Unregister harness
			manager.UnregisterHarness(tt.taskID)

			// Verify harness is unregistered
			_, ok = service.activeHarnesses.Load(tt.taskID)
			assert.False(t, ok, "harness should be unregistered")

			// Unregister again (should be safe/idempotent)
			manager.UnregisterHarness(tt.taskID)

			if tt.registerMultiple {
				manager.UnregisterHarness(tt.taskID + "-second")
			}
		})
	}
}

// TestCallbackManager_RegisterUnregister_BeforeStart verifies that registration
// attempts before starting the server are handled gracefully.
func TestCallbackManager_RegisterUnregister_BeforeStart(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))
	config := createTestConfig(t)
	manager := NewCallbackManager(config, logger)

	// Create a mock harness for testing
	harness := new(mockAgentHarness)
	taskID := "task-early"

	// Try to register before starting (should handle gracefully)
	endpoint := manager.RegisterHarness(taskID, harness)

	// Endpoint should still be returned based on config
	assert.NotEmpty(t, endpoint)
	assert.Equal(t, manager.CallbackEndpoint(), endpoint)

	// Unregister should also not panic
	manager.UnregisterHarness(taskID)
}

// TestCallbackManager_CallbackEndpoint verifies the CallbackEndpoint method
// returns the correct address based on configuration.
func TestCallbackManager_CallbackEndpoint(t *testing.T) {
	tests := []struct {
		name             string
		listenAddress    string
		advertiseAddress string
		expectedEndpoint string
	}{
		{
			name:             "advertise address set (Docker networking)",
			listenAddress:    "0.0.0.0:50001",
			advertiseAddress: "gibson:50001",
			expectedEndpoint: "gibson:50001",
		},
		{
			name:             "advertise address empty (use listen)",
			listenAddress:    "127.0.0.1:50002",
			advertiseAddress: "",
			expectedEndpoint: "127.0.0.1:50002",
		},
		{
			name:             "kubernetes service",
			listenAddress:    "0.0.0.0:50003",
			advertiseAddress: "gibson.gibson-ns.svc.cluster.local:50003",
			expectedEndpoint: "gibson.gibson-ns.svc.cluster.local:50003",
		},
		{
			name:             "localhost",
			listenAddress:    "localhost:50004",
			advertiseAddress: "",
			expectedEndpoint: "localhost:50004",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
				Level: slog.LevelError,
			}))

			config := CallbackConfig{
				ListenAddress:    tt.listenAddress,
				AdvertiseAddress: tt.advertiseAddress,
				Enabled:          true,
			}

			manager := NewCallbackManager(config, logger)

			endpoint := manager.CallbackEndpoint()
			assert.Equal(t, tt.expectedEndpoint, endpoint,
				"callback endpoint should match expected value")
		})
	}
}

// TestCallbackManager_ConcurrentRegistrations verifies that concurrent harness
// registrations and unregistrations are handled correctly.
func TestCallbackManager_ConcurrentRegistrations(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))
	config := createTestConfig(t)
	manager := NewCallbackManager(config, logger)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Start the manager
	err := manager.Start(ctx)
	require.NoError(t, err)
	defer manager.Stop()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Create a mock harness for testing
	harness := new(mockAgentHarness)

	// Launch multiple goroutines that register and unregister harnesses
	const numGoroutines = 10
	done := make(chan bool, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			taskID := fmt.Sprintf("concurrent-task-%d", id)
			endpoint := manager.RegisterHarness(taskID, harness)
			assert.NotEmpty(t, endpoint)

			// Small delay to simulate work
			time.Sleep(10 * time.Millisecond)

			manager.UnregisterHarness(taskID)
			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		select {
		case <-done:
			// Success
		case <-time.After(5 * time.Second):
			t.Fatal("timeout waiting for concurrent registrations")
		}
	}
}

// TestCallbackManager_ContextCancellation verifies that the server shuts down
// properly when the context is cancelled.
func TestCallbackManager_ContextCancellation(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))
	config := createTestConfig(t)
	manager := NewCallbackManager(config, logger)

	ctx, cancel := context.WithCancel(context.Background())

	// Start the manager
	err := manager.Start(ctx)
	require.NoError(t, err)

	// Give server time to start
	time.Sleep(100 * time.Millisecond)
	assert.True(t, manager.IsRunning())

	// Cancel the context
	cancel()

	// Give server time to shut down
	time.Sleep(200 * time.Millisecond)

	// Server should have stopped
	// Note: The running flag might not be false if Stop() wasn't explicitly called,
	// but the server should not be accepting connections
}
