// Package client provides the internal admin client for the Gibson daemon.
//
// This package contains only what is needed for daemon lifecycle commands
// (daemon stop, daemon restart) — specifically the DaemonOperatorService
// Shutdown RPC. Operational RPCs (Status, ListMissions, etc.)
// are available via github.com/zero-day-ai/sdk/daemonclient.
package client

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	daemonoperatorv1 "github.com/zero-day-ai/platform-sdk/gen/gibson/daemon/operator/v1"
)

// AdminClient is a minimal gRPC client for the DaemonOperatorService.
//
// It provides only the operations needed by daemon lifecycle CLI commands:
// Shutdown (used by daemon stop/restart) and Ping (liveness check).
// For operational RPCs use github.com/zero-day-ai/sdk/daemonclient.
type AdminClient struct {
	conn     *grpc.ClientConn
	operator daemonoperatorv1.DaemonOperatorServiceClient
}

// ConnectAdmin establishes a gRPC connection to the daemon at the given address.
//
// Parameters:
//   - ctx: Context with timeout for connection establishment
//   - address: Daemon address (TCP host:port or unix:///path)
//
// Returns:
//   - *AdminClient: Connected admin client ready for use
//   - error: Non-nil if connection fails
func ConnectAdmin(ctx context.Context, address string) (*AdminClient, error) {
	if address == "" {
		return nil, fmt.Errorf("daemon address cannot be empty")
	}

	// Ensure a connection timeout is set
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
	}

	target := address

	conn, err := grpc.DialContext( //nolint:staticcheck // DialContext is fine here; NewClient requires the address at dial time
		ctx,
		target,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to daemon at %s: %w", address, err)
	}

	return &AdminClient{
		conn:     conn,
		operator: daemonoperatorv1.NewDaemonOperatorServiceClient(conn),
	}, nil
}

// Shutdown requests a graceful shutdown of the daemon via the DaemonOperatorService RPC.
//
// This is the primary method used by 'gibson daemon stop'.
func (c *AdminClient) Shutdown(ctx context.Context) error {
	_, err := c.operator.Shutdown(ctx, &daemonoperatorv1.ShutdownRequest{})
	if err != nil {
		return fmt.Errorf("shutdown RPC failed: %w", err)
	}
	return nil
}

// Close closes the underlying gRPC connection.
func (c *AdminClient) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}
