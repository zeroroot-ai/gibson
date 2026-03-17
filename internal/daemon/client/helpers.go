package client

import (
	"context"
	"fmt"
	"time"
)

// RequireDaemon returns a connected daemon client or an error if the daemon is not running.
//
// This function should be used for operations that cannot function without a running daemon,
// such as mission execution, attack runs, or component lifecycle operations.
//
// The function provides clear, actionable error messages to help users start the daemon
// if it's not running.
//
// Parameters:
//   - ctx: Context for the connection attempt
//
// Returns:
//   - *Client: Connected client ready for use
//   - error: Non-nil if daemon is not running or connection fails
//
// Example:
//
//	client, err := RequireDaemon(ctx)
//	if err != nil {
//	    // User-friendly error like:
//	    // "Error: daemon not running. Start with: gibson daemon start"
//	    return err
//	}
//	defer client.Close()
//
//	// Use client for operations that require daemon
//	err = client.RunMission(ctx, missionID)
func RequireDaemon(ctx context.Context) (*Client, error) {
	// Use ConnectOrFail which provides user-friendly error messages
	client, err := ConnectOrFail(ctx)
	if err != nil {
		return nil, fmt.Errorf("daemon required for this operation: %w", err)
	}
	return client, nil
}

// OptionalDaemon returns a connected daemon client, or nil if the daemon is not running.
//
// This function should be used for operations that can fall back to local data sources
// when the daemon is unavailable, such as reading mission history or listing components
// from the SQLite database.
//
// Unlike RequireDaemon, this function does NOT return an error if the daemon is not running.
// Callers should check for nil and implement their fallback strategy.
//
// Parameters:
//   - ctx: Context for the connection attempt
//
// Returns:
//   - *Client: Connected client if daemon is running, nil otherwise
//
// Example:
//
//	client := OptionalDaemon(ctx)
//	if client != nil {
//	    defer client.Close()
//	    // Use daemon for live data
//	    missions, err := client.ListMissions(ctx, false, "", 0, 0)
//	    if err == nil {
//	        displayMissions(missions)
//	        return nil
//	    }
//	}
//
//	// Fall back to local data
//	log.Warn("Daemon not running, showing local data only")
//	missions, err := core.MissionList(ctx)
//	if err != nil {
//	    return err
//	}
//	displayMissions(missions)
func OptionalDaemon(ctx context.Context) *Client {
	// Try to connect with a short timeout
	connectCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	client, err := ConnectOrFail(connectCtx)
	if err != nil {
		// Connection failed, return nil (no error)
		return nil
	}

	return client
}

// IsDaemonRunning checks if the Gibson daemon is currently running and responsive.
//
// This is a lightweight check that only tests daemon availability by attempting
// a connection and ping. It's useful for status checks, UI indicators, or conditional
// logic that needs to determine daemon availability.
//
// Returns:
//   - bool: true if daemon is running and responsive, false otherwise
//
// Example:
//
//	if IsDaemonRunning() {
//	    fmt.Println("✓ Daemon is running")
//	} else {
//	    fmt.Println("✗ Daemon is not running")
//	    fmt.Println("  Start with: gibson daemon start")
//	}
func IsDaemonRunning() bool {
	// Try to connect with short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	client, err := Connect(ctx, GetDaemonAddress())
	if err != nil {
		return false
	}
	defer client.Close()

	// Ping to verify daemon is responsive
	_, err = client.Status(ctx)
	return err == nil
}
