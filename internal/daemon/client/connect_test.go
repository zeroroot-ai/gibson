package client

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zero-day-ai/gibson/internal/daemon"
)

// TestConnectOrFail_RemoteAddress tests ConnectOrFail when GIBSON_DAEMON_ADDRESS is set.
// It verifies that the function uses the remote connection path and doesn't look for daemon.json.
func TestConnectOrFail_RemoteAddress(t *testing.T) {
	tests := []struct {
		name           string
		remoteAddress  string
		expectError    bool
		errorContains  []string
		setupGibsonDir bool // Whether to create daemon.json (should be ignored)
	}{
		{
			name:          "remote TCP address - connection fails",
			remoteAddress: "remote-host:50002",
			expectError:   true,
			errorContains: []string{
				"failed to connect to remote daemon",
				"remote-host:50002",
				EnvDaemonAddress,
				"Troubleshooting steps",
			},
			setupGibsonDir: false,
		},
		{
			name:          "remote TCP address with daemon.json present - ignores local file",
			remoteAddress: "192.168.1.100:50002",
			expectError:   true,
			errorContains: []string{
				"failed to connect to remote daemon",
				"192.168.1.100:50002",
				EnvDaemonAddress,
			},
			setupGibsonDir: true, // daemon.json exists but should be ignored
		},
		{
			name:          "remote Unix socket with unix:// prefix",
			remoteAddress: "unix:///tmp/remote-gibson.sock",
			expectError:   true,
			errorContains: []string{
				"failed to connect to remote daemon",
				"unix:///tmp/remote-gibson.sock",
				EnvDaemonAddress,
			},
			setupGibsonDir: false,
		},
		{
			name:          "remote Unix socket without prefix",
			remoteAddress: "/tmp/remote-gibson.sock",
			expectError:   true,
			errorContains: []string{
				"failed to connect to remote daemon",
				"/tmp/remote-gibson.sock",
				EnvDaemonAddress,
			},
			setupGibsonDir: false,
		},
		{
			name:          "localhost address - connection fails",
			remoteAddress: "localhost:59999",
			expectError:   true,
			errorContains: []string{
				"failed to connect to remote daemon",
				"localhost:59999",
				EnvDaemonAddress,
			},
			setupGibsonDir: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup temp directory for GIBSON_HOME
			tempDir := t.TempDir()
			t.Setenv("GIBSON_HOME", tempDir)

			// Set remote daemon address
			t.Setenv(EnvDaemonAddress, tt.remoteAddress)

			// Optionally create daemon.json to verify it's ignored
			if tt.setupGibsonDir {
				infoPath := filepath.Join(tempDir, "daemon.json")
				info := &daemon.DaemonInfo{
					PID:         12345,
					StartTime:   time.Now(),
					GRPCAddress: "localhost:50002",
					Version:     "1.0.0",
				}
				err := daemon.WriteDaemonInfo(infoPath, info)
				require.NoError(t, err)
			}

			// Create context with timeout to avoid hanging
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()

			// Attempt connection
			client, err := ConnectOrFail(ctx)

			// Verify expectations
			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, client)

				// Check that all expected error message fragments are present
				for _, fragment := range tt.errorContains {
					assert.Contains(t, err.Error(), fragment,
						"Error should contain '%s'", fragment)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, client)
				if client != nil {
					client.Close()
				}
			}
		})
	}
}

// TestConnectOrFail_RemoteFallback tests that ConnectOrFail falls back to
// daemon.json behavior when GIBSON_DAEMON_ADDRESS is empty or unset.
func TestConnectOrFail_RemoteFallback(t *testing.T) {
	tests := []struct {
		name              string
		envValue          string // Value of GIBSON_DAEMON_ADDRESS (empty string = unset)
		setupDaemonJSON   bool   // Whether to create daemon.json
		expectError       bool
		errorContains     []string
		shouldUseDaemonJS bool // Whether daemon.json path should be used
	}{
		{
			name:              "env unset - daemon.json missing",
			envValue:          "",
			setupDaemonJSON:   false,
			expectError:       true,
			shouldUseDaemonJS: true,
			errorContains: []string{
				"Gibson daemon not running",
				"gibson daemon start",
				"daemon.json",
			},
		},
		{
			name:              "env empty string - daemon.json missing",
			envValue:          "",
			setupDaemonJSON:   false,
			expectError:       true,
			shouldUseDaemonJS: true,
			errorContains: []string{
				"Gibson daemon not running",
				"gibson daemon start",
			},
		},
		{
			name:              "env unset - daemon.json exists but daemon not running",
			envValue:          "",
			setupDaemonJSON:   true,
			expectError:       true,
			shouldUseDaemonJS: true,
			errorContains: []string{
				"failed to connect to daemon",
				"may have crashed",
				"gibson daemon status",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup temp directory
			tempDir := t.TempDir()
			t.Setenv("GIBSON_HOME", tempDir)

			// Set or unset environment variable
			if tt.envValue == "" {
				// Explicitly unset to test fallback behavior
				os.Unsetenv(EnvDaemonAddress)
			} else {
				t.Setenv(EnvDaemonAddress, tt.envValue)
			}

			// Setup daemon.json if requested
			if tt.setupDaemonJSON {
				infoPath := filepath.Join(tempDir, "daemon.json")
				info := &daemon.DaemonInfo{
					PID:         99990,
					StartTime:   time.Now(),
					GRPCAddress: "localhost:59990",
					Version:     "1.0.0",
				}
				err := daemon.WriteDaemonInfo(infoPath, info)
				require.NoError(t, err)
			}

			// Create context with timeout
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()

			// Attempt connection
			client, err := ConnectOrFail(ctx)

			// Verify expectations
			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, client)

				// Verify error messages
				for _, fragment := range tt.errorContains {
					assert.Contains(t, err.Error(), fragment,
						"Error should contain '%s'", fragment)
				}

				// If should use daemon.json path, error should NOT mention remote connection
				if tt.shouldUseDaemonJS {
					assert.NotContains(t, err.Error(), "remote daemon",
						"Error should not mention remote daemon when using local fallback")
					assert.NotContains(t, err.Error(), EnvDaemonAddress,
						"Error should not mention %s when using local fallback", EnvDaemonAddress)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, client)
				if client != nil {
					client.Close()
				}
			}
		})
	}
}

// TestConnectToRemote_ErrorMessages tests that connectToRemote produces
// helpful error messages with the target address and environment variable name.
func TestConnectToRemote_ErrorMessages(t *testing.T) {
	tests := []struct {
		name               string
		address            string
		expectedInError    []string
		notExpectedInError []string
	}{
		{
			name:    "TCP address error message",
			address: "unreachable-host:50002",
			expectedInError: []string{
				"failed to connect to remote daemon",
				"unreachable-host:50002",
				EnvDaemonAddress,
				"Troubleshooting steps",
				"Verify the daemon is running",
				"Check network connectivity",
				"firewall",
				"TCP: host:port",
				"Unix socket: unix:///path",
				"unset " + EnvDaemonAddress,
			},
		},
		{
			name:    "Unix socket error message",
			address: "unix:///nonexistent/socket.sock",
			expectedInError: []string{
				"failed to connect to remote daemon",
				"unix:///nonexistent/socket.sock",
				EnvDaemonAddress,
				"Troubleshooting steps",
			},
		},
		{
			name:    "localhost connection error",
			address: "localhost:12345",
			expectedInError: []string{
				"failed to connect to remote daemon",
				"localhost:12345",
				EnvDaemonAddress,
			},
		},
		{
			name:    "IPv4 address error",
			address: "10.0.0.1:50002",
			expectedInError: []string{
				"failed to connect to remote daemon",
				"10.0.0.1:50002",
				EnvDaemonAddress,
			},
		},
		{
			name:    "hostname with port error",
			address: "gibson-daemon.example.com:50002",
			expectedInError: []string{
				"failed to connect to remote daemon",
				"gibson-daemon.example.com:50002",
				EnvDaemonAddress,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create context with short timeout
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			// Attempt connection to non-existent daemon
			client, err := connectToRemote(ctx, tt.address)

			// Should always fail (we're not running a real daemon)
			assert.Error(t, err)
			assert.Nil(t, client)

			// Verify error message contains all expected fragments
			errMsg := err.Error()
			for _, expected := range tt.expectedInError {
				assert.Contains(t, errMsg, expected,
					"Error message should contain '%s'", expected)
			}

			// Verify error message doesn't contain unwanted fragments
			for _, notExpected := range tt.notExpectedInError {
				assert.NotContains(t, errMsg, notExpected,
					"Error message should not contain '%s'", notExpected)
			}
		})
	}
}

// TestConnectToRemote_Timeout tests that connectToRemote respects timeout.
func TestConnectToRemote_Timeout(t *testing.T) {
	// Use an address that will hang (non-routable IP)
	address := "192.0.2.1:50002" // TEST-NET-1 - should not route

	// Create context with short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	start := time.Now()
	client, err := connectToRemote(ctx, address)
	elapsed := time.Since(start)

	// Should fail with timeout
	assert.Error(t, err)
	assert.Nil(t, client)
	assert.Contains(t, err.Error(), "failed to connect to remote daemon")
	assert.Contains(t, err.Error(), address)

	// Should complete within reasonable time (timeout + some overhead)
	assert.Less(t, elapsed, 7*time.Second,
		"connectToRemote should respect timeout context")
}

// TestConnectToRemote_ContextCanceled tests behavior when context is already canceled.
func TestConnectToRemote_ContextCanceled(t *testing.T) {
	// Create already-canceled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	address := "localhost:50002"
	client, err := connectToRemote(ctx, address)

	// Should fail immediately
	assert.Error(t, err)
	assert.Nil(t, client)
	assert.Contains(t, err.Error(), "failed to connect to remote daemon")
	assert.Contains(t, err.Error(), address)
}

// TestConnectOrFail_EnvVarPriority tests that GIBSON_DAEMON_ADDRESS
// takes priority over daemon.json when both are available.
func TestConnectOrFail_EnvVarPriority(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("GIBSON_HOME", tempDir)

	// Create daemon.json for local daemon
	infoPath := filepath.Join(tempDir, "daemon.json")
	localInfo := &daemon.DaemonInfo{
		PID:         11111,
		StartTime:   time.Now(),
		GRPCAddress: "localhost:50002",
		Version:     "1.0.0",
	}
	err := daemon.WriteDaemonInfo(infoPath, localInfo)
	require.NoError(t, err)

	// Set remote daemon address (different from local)
	remoteAddr := "remote-host:50002"
	t.Setenv(EnvDaemonAddress, remoteAddr)

	// Create context
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Attempt connection
	client, err := ConnectOrFail(ctx)

	// Should fail trying to connect to remote (not local)
	assert.Error(t, err)
	assert.Nil(t, client)

	// Error should mention remote address, not local
	assert.Contains(t, err.Error(), remoteAddr,
		"Error should mention remote address from env var")
	assert.NotContains(t, err.Error(), "localhost:50002",
		"Error should not mention local daemon.json address")
	assert.Contains(t, err.Error(), "remote daemon",
		"Error should indicate remote connection attempt")
}

// TestConnectOrFail_EmptyEnvVarUsesLocal tests that an empty
// GIBSON_DAEMON_ADDRESS env var properly falls back to local behavior.
func TestConnectOrFail_EmptyEnvVarUsesLocal(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("GIBSON_HOME", tempDir)

	// Explicitly set env var to empty string
	t.Setenv(EnvDaemonAddress, "")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	client, err := ConnectOrFail(ctx)

	// Should fail with local daemon error (not remote)
	assert.Error(t, err)
	assert.Nil(t, client)
	assert.Contains(t, err.Error(), "Gibson daemon not running",
		"Error should indicate local daemon check")
	assert.NotContains(t, err.Error(), "remote daemon",
		"Error should not mention remote daemon")
}

// TestConnectToRemote_AddressInclusion verifies that error messages
// always include the target address for debugging.
func TestConnectToRemote_AddressInclusion(t *testing.T) {
	addresses := []string{
		"example.com:50002",
		"192.168.1.100:50002",
		"localhost:9999",
		"unix:///tmp/test.sock",
		"/var/run/gibson.sock",
	}

	for _, addr := range addresses {
		t.Run(addr, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()

			client, err := connectToRemote(ctx, addr)

			assert.Error(t, err)
			assert.Nil(t, client)

			// Extract the actual address that would be used
			// (Connect may modify Unix socket paths)
			expectedAddr := addr
			if strings.HasPrefix(addr, "/") && !strings.HasPrefix(addr, "unix://") {
				expectedAddr = addr // Original path should still appear in error
			}

			assert.Contains(t, err.Error(), expectedAddr,
				"Error must include the target address for debugging")
			assert.Contains(t, err.Error(), EnvDaemonAddress,
				"Error must mention the environment variable name")
		})
	}
}
