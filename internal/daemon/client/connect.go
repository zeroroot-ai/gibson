package client

import (
	"context"
	"fmt"
	"os"
	"time"
)

// EnvDaemonAddress is the environment variable for specifying the daemon address.
// When set, the client will connect to the specified address.
// Supports both TCP (host:port) and Unix socket (unix:///path or /path) formats.
// If not set, defaults to localhost:50002.
const EnvDaemonAddress = "GIBSON_DAEMON_ADDRESS"

// DefaultDaemonAddress is the default address used when GIBSON_DAEMON_ADDRESS is not set.
const DefaultDaemonAddress = "localhost:50002"

// GetDaemonAddress returns the daemon address to use for connections.
//
// It checks the GIBSON_DAEMON_ADDRESS environment variable first.
// If not set, returns the default address (localhost:50002).
//
// Returns:
//   - string: The daemon address (TCP host:port or Unix socket path)
//
// Example:
//
//	addr := GetDaemonAddress()
//	fmt.Printf("Connecting to daemon at: %s\n", addr)
func GetDaemonAddress() string {
	if addr := os.Getenv(EnvDaemonAddress); addr != "" {
		return addr
	}
	return DefaultDaemonAddress
}

// ConnectOrFail attempts to connect to the Gibson daemon with user-friendly error messages.
//
// This is the recommended function for CLI commands to connect to the daemon. It:
//  1. Checks for GIBSON_DAEMON_ADDRESS environment variable
//  2. If not set, defaults to localhost:50002
//  3. Attempts connection with a 5 second timeout
//  4. Returns clear, actionable error messages if connection fails
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
//	    // "Failed to connect to daemon at localhost:50002"
//	    return err
//	}
//	defer client.Close()
//
//	// Use client for daemon operations
//	status, err := client.Status(ctx)
func ConnectOrFail(ctx context.Context) (*Client, error) {
	address := GetDaemonAddress()

	// Create context with connection timeout
	connectCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// Attempt connection
	client, err := Connect(connectCtx, address)
	if err != nil {
		// Check if this was a remote address (env var set)
		if os.Getenv(EnvDaemonAddress) != "" {
			return nil, fmt.Errorf("failed to connect to daemon at %s (from %s): %w\n\n"+
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

		// Local daemon connection failed
		return nil, fmt.Errorf("failed to connect to daemon at %s: %w\n\n"+
			"The daemon may not be running.\n\n"+
			"Start the daemon with:\n"+
			"  gibson daemon start\n\n"+
			"For background operation, use shell job control:\n"+
			"  gibson daemon start &\n\n"+
			"Or set %s to connect to a remote daemon.",
			address, err, EnvDaemonAddress)
	}

	return client, nil
}
