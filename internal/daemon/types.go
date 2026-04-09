// Package daemon provides daemon lifecycle management for Gibson.
//
// The daemon package implements the daemon-client architecture for Gibson,
// separating long-running services (etcd registry, callback server, gRPC endpoints)
// from CLI command execution. The daemon runs as a background process that CLI
// commands connect to, eliminating port conflicts and enabling multiple concurrent
// operations.
package daemon

import (
	"context"
	"time"
)

// DaemonStatus represents the current state and health information of the daemon.
//
// This struct is returned by the Status() method and includes both runtime state
// (PID, running status, uptime) and service information (registry, callback server,
// component counts). It provides a complete view of daemon health for status
// commands and monitoring.
type DaemonStatus struct {
	// Running indicates whether the daemon process is currently active
	Running bool `json:"running"`

	// PID is the process ID of the daemon
	PID int `json:"pid"`

	// StartTime is when the daemon was started
	StartTime time.Time `json:"start_time"`

	// Uptime is a human-readable duration since daemon start (e.g., "2h 15m")
	Uptime string `json:"uptime"`

	// SocketPath is the Unix socket path for daemon IPC (if using Unix sockets)
	SocketPath string `json:"socket_path,omitempty"`

	// GRPCAddress is the TCP address for daemon gRPC API (e.g., "localhost:50002")
	GRPCAddress string `json:"grpc_address"`

	// RegistryType is the registry mode: "embedded" or "etcd"
	RegistryType string `json:"registry_type"`

	// RegistryAddr is the registry endpoint address
	RegistryAddr string `json:"registry_address"`

	// CallbackAddr is the callback server endpoint address
	CallbackAddr string `json:"callback_address"`

	// AgentCount is the number of registered agents
	AgentCount int `json:"agent_count"`

	// MissionCount is the total number of missions (historical)
	MissionCount int `json:"mission_count"`

	// ActiveCount is the number of currently running missions
	ActiveCount int `json:"active_mission_count"`
}

// DaemonInfo contains daemon connection information stored in etcd.
//
// This struct is registered in etcd when the daemon starts and is used
// for service discovery. Clients can query etcd to find daemon endpoints.
//
// Note: This struct is NOT written to filesystem files (daemon.json was removed).
// Discovery is done via etcd or GIBSON_DAEMON_ADDRESS environment variable.
type DaemonInfo struct {
	// PID is the process ID of the daemon
	PID int `json:"pid"`

	// StartTime is when the daemon was started
	StartTime time.Time `json:"start_time"`

	// SocketPath is the Unix socket path for daemon IPC (if using Unix sockets)
	SocketPath string `json:"socket_path,omitempty"`

	// GRPCAddress is the TCP address for daemon gRPC API (e.g., "localhost:50002")
	GRPCAddress string `json:"grpc_address"`

	// Version is the Gibson version that started the daemon
	Version string `json:"version"`
}

// Daemon represents the Gibson daemon process and its lifecycle operations.
//
// The daemon manages long-running services including:
//   - etcd registry (embedded or external)
//   - Callback server for agent harnesses
//   - gRPC API server for client connections
//   - Mission orchestration
//
// Example usage:
//
//	cfg, err := config.Load()
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	daemon, err := New(cfg, homeDir)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Start daemon (blocks until context cancelled or SIGTERM)
//	if err := daemon.Start(ctx); err != nil {
//	    log.Fatal(err)
//	}
//
//	// Check status
//	status, err := daemon.Status()
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Daemon running: %v, PID: %d\n", status.Running, status.PID)
//
//	// Graceful shutdown
//	if err := daemon.Stop(ctx); err != nil {
//	    log.Error("shutdown error", "error", err)
//	}
type Daemon interface {
	// Start begins the daemon process and blocks until shutdown.
	//
	// This method initializes and starts all daemon services including the
	// registry, callback server, and gRPC API server.
	//
	// The daemon always runs in foreground mode, blocking until the context
	// is cancelled or a shutdown signal (SIGTERM/SIGINT) is received. This
	// makes it ideal for Docker containers and systemd services.
	//
	// Parameters:
	//   - ctx: Context for daemon lifetime (cancellation triggers shutdown)
	//
	// Returns:
	//   - error: Non-nil if startup fails or if another daemon is already running
	//
	// The method performs these steps:
	// 1. Start registry manager
	// 2. Start callback server
	// 3. Start gRPC API server
	// 4. Block until shutdown signal
	//
	// Common errors:
	//   - ErrAlreadyRunning: Another daemon is already running on the same port
	//   - Port binding errors: Required ports are in use
	Start(ctx context.Context) error

	// Stop gracefully shuts down the daemon.
	//
	// This method performs a graceful shutdown of all daemon services:
	// 1. Stop accepting new client connections (gRPC)
	// 2. Stop callback server (agents can't make new callbacks)
	// 3. Stop registry (embedded etcd shutdown)
	//
	// Parameters:
	//   - ctx: Context with timeout for shutdown operations
	//
	// Returns:
	//   - error: Non-nil if shutdown encounters errors
	//
	// The method is idempotent - calling Stop() on a stopped daemon is a no-op.
	// In-flight operations are given time to complete based on context timeout.
	Stop(ctx context.Context) error

	// SetOnRegistryReady sets a callback that will be called after the registry
	// is started but before other services. This is used by the CLI to set up
	// verbose logging after etcd is initialized, avoiding conflicts with etcd's
	// internal logging during startup.
	SetOnRegistryReady(fn func())

	// Note: Status() method moved to api.DaemonInterface for gRPC integration.
	// The daemon implements api.DaemonInterface.Status() which returns api.DaemonStatus.
	// For internal status queries, use the daemon's status() private method.
}
