//go:build e2e
// +build e2e

// Package helpers — grpc_clients.go
//
// Builds the gRPC client connections needed by the mission e2e test suite:
//   - DaemonServiceClient (public mission + component control plane)
//   - TenantServiceClient (tenant RPCs: CreateProvider, etc.)
//   - DaemonOperatorServiceClient (operator RPCs: Shutdown, etc.)
//
// Reads DAEMON_GRPC_ADDR env var for the daemon's gRPC endpoint.
// Default: "localhost:50002" (Kind NodePort convention).
//
// Authentication is handled by the caller via metadata.NewOutgoingContext.
// The daemon's identity interceptor requires x-tenant-id and authorization
// headers injected by Envoy; in the test environment (no Envoy), the daemon
// runs with authz.enabled=false so unauthenticated calls work.
//
// Requirements: R1.1–R1.10, R3, R4.
package helpers

import (
	"fmt"
	"os"
	"testing"

	daemonoperatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
	daemonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/daemon/v1"
	sdktenantv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/tenant/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// GRPCClientSet holds all gRPC clients needed by the mission e2e test.
// Use NewGRPCClients to construct it; call Close when done.
type GRPCClientSet struct {
	conn           *grpc.ClientConn
	Daemon         daemonpb.DaemonServiceClient
	Tenant         sdktenantv1.TenantServiceClient
	DaemonOperator daemonoperatorv1.DaemonOperatorServiceClient
}

// Close releases the underlying gRPC connection.
func (c *GRPCClientSet) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// DaemonGRPCAddr returns the daemon gRPC address from DAEMON_GRPC_ADDR env var
// or the Kind NodePort default.
func DaemonGRPCAddr() string {
	if addr := os.Getenv("DAEMON_GRPC_ADDR"); addr != "" {
		return addr
	}
	return "localhost:50002"
}

// NewGRPCClients creates a GRPCClientSet connected to the daemon.
// Uses insecure credentials (Kind dev cluster — no mTLS in test environment).
//
// The caller injects tenant/auth context via metadata.NewOutgoingContext when
// making RPC calls.
func NewGRPCClients() (*GRPCClientSet, error) {
	addr := DaemonGRPCAddr()

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("grpc_clients: NewGRPCClients: dial %s: %w", addr, err)
	}

	return &GRPCClientSet{
		conn:           conn,
		Daemon:         daemonpb.NewDaemonServiceClient(conn),
		Tenant:         sdktenantv1.NewTenantServiceClient(conn),
		DaemonOperator: daemonoperatorv1.NewDaemonOperatorServiceClient(conn),
	}, nil
}

// MustNewGRPCClients is like NewGRPCClients but calls t.Fatal on error.
// Registers t.Cleanup to close the connection automatically.
func MustNewGRPCClients(t *testing.T) *GRPCClientSet {
	t.Helper()
	clients, err := NewGRPCClients()
	if err != nil {
		t.Fatalf("grpc_clients: MustNewGRPCClients: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := clients.Close(); closeErr != nil {
			t.Logf("grpc_clients: Close: %v", closeErr)
		}
	})
	return clients
}
