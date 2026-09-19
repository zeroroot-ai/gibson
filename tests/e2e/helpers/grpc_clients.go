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
	"github.com/zeroroot-ai/sdk/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

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

// spireSocketDir is where the exit-test Jobs mount the SPIRE agent socket
// (csi.spiffe.io at /run/spire/sockets). The csi driver names the socket
// api.sock in this chart (gibson-workloads gibson.auth.spiffe.workloadAPISocket),
// the same file the daemon reads. agent.sock is the go-spiffe default name and
// is tried second. A var so the test can point it at a temp dir.
var spireSocketDir = "/run/spire/sockets"

var spireSocketNames = []string{"api.sock", "agent.sock"}

// resolveSPIFFESocket picks the Workload API socket. SPIFFE_ENDPOINT_SOCKET
// wins when set (the go-spiffe convention). Otherwise, a mounted socket
// directory must hold one of the known socket names: the mount says the
// runner is in the mesh, and a runner in the mesh that dials plaintext gets
// "error reading server preface: EOF" from the mTLS listener with no hint
// why (gibson#14: every run since 2026-09-09 failed that way because the
// helper looked for agent.sock while the mount carries api.sock). No mount
// at all means a workstation against a port-forward, the one plaintext case.
func resolveSPIFFESocket(envValue, dir string) (string, error) {
	if sock := strings.TrimSpace(envValue); sock != "" {
		return sock, nil
	}
	if _, err := os.Stat(dir); err != nil {
		return "", nil
	}
	for _, name := range spireSocketNames {
		p := dir + "/" + name
		if _, err := os.Stat(p); err == nil {
			return "unix://" + p, nil
		}
	}
	return "", fmt.Errorf("grpc_clients: %s is mounted but holds none of %v; the runner is in the mesh and will not dial plaintext (set SPIFFE_ENDPOINT_SOCKET)", dir, spireSocketNames)
}

// transportCredentials picks how to reach the daemon: mTLS with the runner's
// SVID when a Workload API socket resolves, plaintext only when nothing is
// mounted. The server must be a member of the runner's own trust domain: the
// test-mode daemon has no fixed SPIFFE ID worth pinning, and a foreign trust
// domain is the thing to refuse.
func transportCredentials(ctx context.Context) (credentials.TransportCredentials, *workloadapi.X509Source, error) {
	sock, err := resolveSPIFFESocket(os.Getenv("SPIFFE_ENDPOINT_SOCKET"), spireSocketDir)
	if err != nil {
		return nil, nil, err
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
// A tenant placed on the context with auth.ContextWithTenant travels to the
// daemon as x-gibson-identity-tenant (see tenantHeaderUnary), which is how
// every tenant-scoped assertion in the suite names its tenant.
func NewGRPCClients() (*GRPCClientSet, error) {
	addr := DaemonGRPCAddr()

	creds, source, err := transportCredentials(context.Background())
	if err != nil {
		return nil, err
	}
	conn, err := grpc.NewClient(addr,
		grpc.WithTransportCredentials(creds),
		grpc.WithUnaryInterceptor(tenantHeaderUnary),
		grpc.WithStreamInterceptor(tenantHeaderStream),
	)
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

// withTenantHeader copies the tenant a test put on ctx with
// auth.ContextWithTenant into the outgoing gRPC metadata as
// x-gibson-identity-tenant. A Go context value never leaves the process;
// before this, every tenant-scoped RPC in the suite reached the daemon with
// no tenant and failed with FailedPrecondition (gibson#14, run 35413689180).
// The daemon's fixture build reads the header for the runner's SVID only.
func withTenantHeader(ctx context.Context) context.Context {
	t, ok := auth.TenantFromContext(ctx)
	if !ok || t == (auth.TenantID{}) {
		return ctx
	}
	return metadata.AppendToOutgoingContext(ctx, auth.HeaderTenant, t.String())
}

func tenantHeaderUnary(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
	return invoker(withTenantHeader(ctx), method, req, reply, cc, opts...)
}

func tenantHeaderStream(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	return streamer(withTenantHeader(ctx), desc, cc, method, opts...)
}
