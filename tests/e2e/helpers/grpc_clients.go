// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build e2e
// +build e2e

// Package helpers — grpc_clients.go
//
// Builds the gRPC client connections needed by the mission e2e test suite:
//   - DaemonServiceClient (public mission + component control plane)
//   - ProviderServiceClient (provider RPCs: CreateProvider, etc.)
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
// Transport: the daemon's gRPC listener speaks SPIFFE mTLS and refuses
// plaintext (zero-trust-hardening Req 1.2). When the suite runs in the mesh
// (the exit-test Jobs mount the SPIRE agent socket) it presents the runner's
// SVID, spiffe://<td>/platform/e2e-runner, which the e2eRunner values
// allow-list on the daemon. Without a socket (a workstation against a
// loopback port-forward) it dials plaintext, the only option there.
//
// Requirements: R1.1–R1.10, R3, R4.
package helpers

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	daemonoperatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
	sdktenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	daemonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/daemon/v1"
)

// GRPCClientSet holds all gRPC clients needed by the mission e2e test.
// Use NewGRPCClients to construct it; call Close when done.
type GRPCClientSet struct {
	conn           *grpc.ClientConn
	source         *workloadapi.X509Source // nil on the plaintext path
	Daemon         daemonpb.DaemonServiceClient
	Provider       sdktenantv1.ProviderServiceClient
	DaemonOperator daemonoperatorv1.DaemonOperatorServiceClient
}

// Close releases the underlying gRPC connection and, on the mTLS path, the
// SPIRE agent stream behind the SVID.
func (c *GRPCClientSet) Close() error {
	var err error
	if c.conn != nil {
		err = c.conn.Close()
	}
	if c.source != nil {
		if cerr := c.source.Close(); err == nil {
			err = cerr
		}
	}
	return err
}

// defaultSPIREAgentSocket is where the exit-test Jobs mount the SPIRE agent
// socket (csi.spiffe.io at /run/spire/sockets), the same path the platform
// workloads use (internal/infra/config/authconfig.go).
const defaultSPIREAgentSocket = "/run/spire/sockets/agent.sock"

// transportCredentials picks how to reach the daemon. SPIFFE_ENDPOINT_SOCKET
// wins when set (the go-spiffe convention); otherwise the mounted socket, if
// present, selects mTLS; otherwise plaintext. The server must be a member of
// the runner's own trust domain: the test-mode daemon has no fixed SPIFFE ID
// worth pinning, and a foreign trust domain is the thing to refuse.
func transportCredentials(ctx context.Context) (credentials.TransportCredentials, *workloadapi.X509Source, error) {
	sock := strings.TrimSpace(os.Getenv("SPIFFE_ENDPOINT_SOCKET"))
	if sock == "" {
		if _, err := os.Stat(defaultSPIREAgentSocket); err == nil {
			sock = "unix://" + defaultSPIREAgentSocket
		}
	}
	if sock == "" {
		return insecure.NewCredentials(), nil, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(sock)))
	if err != nil {
		return nil, nil, fmt.Errorf("grpc_clients: X509Source from %s: %w", sock, err)
	}
	svid, err := source.GetX509SVID()
	if err != nil {
		_ = source.Close()
		return nil, nil, fmt.Errorf("grpc_clients: no SVID from %s: %w", sock, err)
	}
	tlsCfg := tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeMemberOf(svid.ID.TrustDomain()))
	return credentials.NewTLS(tlsCfg), source, nil
}

// Conn returns the shared client connection, so a caller can construct
// additional daemon-local service clients (e.g. MembershipService,
// AgentConsoleService) over the same dial.
func (c *GRPCClientSet) Conn() *grpc.ClientConn {
	return c.conn
}

// DaemonGRPCAddr returns the daemon gRPC address from DAEMON_GRPC_ADDR env var
// or the Kind NodePort default.
func DaemonGRPCAddr() string {
	if addr := os.Getenv("DAEMON_GRPC_ADDR"); addr != "" {
		return addr
	}
	return "localhost:50002"
}

// NewGRPCClients creates a GRPCClientSet connected to the daemon, over mTLS
// with the runner's SVID in the mesh and plaintext on a workstation (see
// transportCredentials).
//
// The caller injects tenant/auth context via metadata.NewOutgoingContext when
// making RPC calls.
func NewGRPCClients() (*GRPCClientSet, error) {
	addr := DaemonGRPCAddr()

	creds, source, err := transportCredentials(context.Background())
	if err != nil {
		return nil, err
	}
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(creds))
	if err != nil {
		if source != nil {
			_ = source.Close()
		}
		return nil, fmt.Errorf("grpc_clients: NewGRPCClients: dial %s: %w", addr, err)
	}

	return &GRPCClientSet{
		conn:           conn,
		source:         source,
		Daemon:         daemonpb.NewDaemonServiceClient(conn),
		Provider:       sdktenantv1.NewProviderServiceClient(conn),
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
