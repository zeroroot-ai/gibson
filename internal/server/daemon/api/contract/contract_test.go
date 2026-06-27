// Copyright 2026 Hack the Planet LLC
//
// Platform wire-contract test — in-module home after the platform-sdk
// retirement (gibson#909, decision A).
//
// HISTORY
// -------
// This suite used to live in zeroroot-ai/.github -> contract-tests/ and
// imported the platform-sdk module's generated bindings. #781 dissolved
// platform-sdk and moved the platform protos into the gibson daemon-local tree
// (internal/server/daemon/api/...), which is NOT importable from outside this
// module. So the wire-contract test moves in-tree and imports the in-module
// bindings directly. .github/contract-tests is deleted; platform-sdk is retired.
//
// SCOPE
// -----
// The platform services that still live in gibson are DaemonOperatorService and
// DiscoveryService — covered here, one happy-path + one forced-failure RPC each,
// against in-process stub servers (wire-shape parity, no external deps).
//
//   - BillingService was ripped out of gibson into the closed `billing` repo
//     (gibson#915); its wire contract belongs there, not here.
//   - gibson.common.errors.v1 (the old ErrorDetail failure shape) and
//     gibson.common.pagination.v1 were platform-sdk-only and consumed by nobody
//     after the dashboard/daemon rewire; they are retired with platform-sdk.
//     The failure path is asserted on the gRPC status code, which is the wire
//     contract these services actually carry.
package contract

import (
	"context"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	discoveryv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/discovery/v1"
	operatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
)

// assertGRPCCode verifies err carries the expected gRPC status code.
func assertGRPCCode(t *testing.T, err error, want codes.Code) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected an error with code %v, got nil", want)
	}
	if got := status.Code(err); got != want {
		t.Errorf("gRPC code: got %v, want %v", got, want)
	}
}

// --- Stub servers --- //

// DaemonOperatorService: Shutdown(force=false) → ok, Shutdown(force=true) →
// PermissionDenied. RefreshToolCatalog(force=false) → ok, force=true → NotFound.
type stubDaemonOperator struct {
	operatorv1.UnimplementedDaemonOperatorServiceServer
}

func (s *stubDaemonOperator) Shutdown(_ context.Context, req *operatorv1.ShutdownRequest) (*operatorv1.ShutdownResponse, error) {
	if req.GetForce() {
		return nil, status.Error(codes.PermissionDenied, "forced shutdown denied")
	}
	return &operatorv1.ShutdownResponse{}, nil
}

func (s *stubDaemonOperator) RefreshToolCatalog(_ context.Context, req *operatorv1.RefreshToolCatalogRequest) (*operatorv1.RefreshToolCatalogResponse, error) {
	if req.GetForce() {
		return nil, status.Error(codes.NotFound, "catalog refresh target not found")
	}
	return &operatorv1.RefreshToolCatalogResponse{}, nil
}

// DiscoveryService: ListAgents(query=nil) → ok, ListAgents(query.PageSize=999) →
// NotFound.
type stubDiscovery struct {
	discoveryv1.UnimplementedDiscoveryServiceServer
}

func (s *stubDiscovery) ListAgents(_ context.Context, req *discoveryv1.ListAgentsRequest) (*discoveryv1.ListAgentsResponse, error) {
	if req.GetQuery() != nil && req.GetQuery().GetPageSize() == 999 {
		return nil, status.Error(codes.NotFound, "tenant not found")
	}
	return &discoveryv1.ListAgentsResponse{}, nil
}

// --- Test harness --- //

func startStubServer(t *testing.T) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer()
	operatorv1.RegisterDaemonOperatorServiceServer(srv, &stubDaemonOperator{})
	discoveryv1.RegisterDiscoveryServiceServer(srv, &stubDiscovery{})
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.GracefulStop)
	return lis.Addr().String()
}

// --- Tests --- //

func TestPlatformContractSuite(t *testing.T) {
	addr := startStubServer(t)
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("grpc dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	t.Run("DaemonOperatorService/Shutdown", func(t *testing.T) {
		c := operatorv1.NewDaemonOperatorServiceClient(conn)
		if _, err := c.Shutdown(context.Background(), &operatorv1.ShutdownRequest{Force: false}); err != nil {
			t.Errorf("happy path: %v", err)
		}
		_, err := c.Shutdown(context.Background(), &operatorv1.ShutdownRequest{Force: true})
		assertGRPCCode(t, err, codes.PermissionDenied)
	})

	t.Run("DaemonOperatorService/RefreshToolCatalog", func(t *testing.T) {
		c := operatorv1.NewDaemonOperatorServiceClient(conn)
		if _, err := c.RefreshToolCatalog(context.Background(), &operatorv1.RefreshToolCatalogRequest{Force: false}); err != nil {
			t.Errorf("happy path: %v", err)
		}
		_, err := c.RefreshToolCatalog(context.Background(), &operatorv1.RefreshToolCatalogRequest{Force: true})
		assertGRPCCode(t, err, codes.NotFound)
	})

	t.Run("DiscoveryService/ListAgents", func(t *testing.T) {
		c := discoveryv1.NewDiscoveryServiceClient(conn)
		if _, err := c.ListAgents(context.Background(), &discoveryv1.ListAgentsRequest{}); err != nil {
			t.Errorf("happy path: %v", err)
		}
		_, err := c.ListAgents(context.Background(), &discoveryv1.ListAgentsRequest{
			Query: &discoveryv1.ListQuery{PageSize: 999},
		})
		assertGRPCCode(t, err, codes.NotFound)
	})
}
