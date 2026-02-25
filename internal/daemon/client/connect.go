package client

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/zero-day-ai/gibson/internal/config"
)

// EnvDaemonAddress is the environment variable for specifying a remote daemon address.
// When set, the client will connect to the specified address instead of using daemon.json.
// Supports both TCP (host:port) and Unix socket (unix:///path or /path) formats.
const EnvDaemonAddress = "GIBSON_DAEMON_ADDRESS"

// connectToRemote connects to a daemon at the specified remote address.
//
// This function is used when the GIBSON_DAEMON_ADDRESS environment variable is set,
// allowing the client to connect to remote daemons instead of only local ones.
// It creates a context with a 5-second timeout and provides clear error messages
// that include the address and environment variable name for easier debugging.
//
// Parameters:
//   - ctx: Base context for the connection attempt
//   - address: Daemon address (TCP host:port or Unix socket path)
//
// Returns:
//   - *Client: Connected client ready for use
//   - error: User-friendly error with troubleshooting hints
//
// Example:
//
//	client, err := connectToRemote(ctx, "remote-host:50002")
//	if err != nil {
//	    // Error includes helpful message like:
//	    // "Failed to connect to remote daemon at remote-host:50002 (from GIBSON_DAEMON_ADDRESS): ..."
//	    return err
//	}
//	defer client.Close()
func connectToRemote(ctx context.Context, address string) (*Client, error) {
	// Create context with connection timeout
	connectCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// Attempt connection using the existing Connect function
	client, err := Connect(connectCtx, address)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to remote daemon at %s (from %s): %w\n\n"+
			"Troubleshooting steps:\n"+
			"  1. Verify the daemon is running at the specified address\n"+
			"  2. Check network connectivity: ping/telnet to the host and port\n"+
			"  3. Ensure no firewall is blocking the connection\n"+
			"  4. Verify the address format is correct:\n"+
			"     - TCP: host:port (e.g., 192.168.1.100:50002)\n"+
			"     - Unix socket: unix:///path or /path\n"+
			"  5. Check daemon logs on the remote host for connection errors\n\n"+
			"To connect to a local daemon instead, unset %s",
			address, EnvDaemonAddress, err, EnvDaemonAddress)
	}

	return client, nil
}

// ConnectOrFail attempts to connect to the Gibson daemon with user-friendly error messages.
//
// This is the recommended function for CLI commands to connect to the daemon. It:
//  1. Checks for GIBSON_DAEMON_ADDRESS environment variable (remote daemon connection)
//  2. If not set, discovers Gibson home directory from environment or defaults
//  3. Checks for daemon.json file existence
//  4. Attempts connection with a reasonable timeout
//  5. Returns clear, actionable error messages if connection fails
//
// The function handles common error scenarios:
//   - Remote daemon connection (GIBSON_DAEMON_ADDRESS set)
//   - Daemon not running (daemon.json missing)
//   - Daemon crashed (daemon.json exists but connection fails)
//   - Connection timeout (daemon hung or network issues)
//
// Parameters:
//   - ctx: Base context for the connection attempt
//
// Returns:
//   - *Client: Connected client ready for use
//   - error: User-friendly error with troubleshooting hints
//
// Example:
//
//	client, err := ConnectOrFail(ctx)
//	if err != nil {
//	    // Error already includes helpful message like:
//	    // "Gibson daemon not running. Start with: gibson daemon start"
//	    return err
//	}
//	defer client.Close()
//
//	// Use client for daemon operations
//	status, err := client.Status(ctx)
func ConnectOrFail(ctx context.Context) (*Client, error) {
	// Check for remote daemon address environment variable first
	if address := os.Getenv(EnvDaemonAddress); address != "" {
		return connectToRemote(ctx, address)
	}

	// Get Gibson home directory
	homeDir, err := getGibsonHome()
	if err != nil {
		return nil, fmt.Errorf("failed to determine Gibson home directory: %w\n\n"+
			"Try setting GIBSON_HOME environment variable", err)
	}

	// Build path to daemon.json
	daemonInfoPath := filepath.Join(homeDir, "daemon.json")

	// Check if daemon.json exists
	if _, err := os.Stat(daemonInfoPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("Gibson daemon not running\n\n"+
			"Start the daemon with:\n"+
			"  gibson daemon start\n\n"+
			"For background operation, use shell job control:\n"+
			"  gibson daemon start &\n\n"+
			"Expected daemon info at: %s", daemonInfoPath)
	}

	// Create context with connection timeout
	connectCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// Attempt connection
	client, err := ConnectFromInfo(connectCtx, daemonInfoPath)
	if err != nil {
		// Check if daemon.json exists but process is dead
		return nil, fmt.Errorf("failed to connect to daemon: %w\n\n"+
			"The daemon may have crashed or is not responding.\n\n"+
			"Troubleshooting steps:\n"+
			"  1. Check daemon status: gibson daemon status\n"+
			"  2. Check daemon logs: tail -f %s/daemon.log\n"+
			"  3. Stop stale daemon: gibson daemon stop\n"+
			"  4. Start fresh daemon: gibson daemon start\n\n"+
			"If the problem persists, check for port conflicts:\n"+
			"  - etcd ports: 2379, 2380\n"+
			"  - callback server: 50001\n"+
			"  - daemon gRPC: 50002",
			err, homeDir)
	}

	return client, nil
}

// getGibsonHome returns the Gibson home directory.
//
// It checks in order:
//  1. GIBSON_HOME environment variable
//  2. $HOME/.gibson (default)
//  3. Falls back to config.DefaultHomeDir() which handles edge cases
//
// Returns:
//   - string: Gibson home directory path
//   - error: Non-nil if home directory cannot be determined
func getGibsonHome() (string, error) {
	// Check environment variable first
	if homeDir := os.Getenv("GIBSON_HOME"); homeDir != "" {
		return homeDir, nil
	}

	// Use default from config package
	return config.DefaultHomeDir(), nil
}
