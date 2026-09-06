// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemonclient

import (
	"context"
	"errors"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	daemonoperatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
)

// fakeOperatorService records the revoke it receives and answers as told.
type fakeOperatorService struct {
	daemonoperatorv1.UnimplementedDaemonOperatorServiceServer
	got *daemonoperatorv1.RevokeConnectorGrantRequest
	err error
}

func (f *fakeOperatorService) RevokeConnectorGrant(_ context.Context, req *daemonoperatorv1.RevokeConnectorGrantRequest) (*daemonoperatorv1.RevokeConnectorGrantResponse, error) {
	f.got = req
	if f.err != nil {
		return nil, f.err
	}
	return &daemonoperatorv1.RevokeConnectorGrantResponse{HadGrant: true}, nil
}

// dialFake serves the fake over bufconn and returns a Client on it.
func dialFake(t *testing.T, svc *fakeOperatorService) *Client {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	daemonoperatorv1.RegisterDaemonOperatorServiceServer(srv, svc)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
	)
	if err != nil {
		t.Fatalf("dial bufconn: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return NewWithConn(conn)
}

func TestRevoke_CarriesTenantAndConnector(t *testing.T) {
	svc := &fakeOperatorService{}
	c := dialFake(t, svc)

	if err := c.Revoke(context.Background(), "acme", "github"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if svc.got.GetTenantId() != "acme" || svc.got.GetConnector() != "github" {
		t.Errorf("daemon received (%q, %q), want (acme, github)", svc.got.GetTenantId(), svc.got.GetConnector())
	}
}

func TestRevoke_SurfacesTheDaemonError(t *testing.T) {
	svc := &fakeOperatorService{err: status.Error(codes.Unavailable, "no secrets stack")}
	c := dialFake(t, svc)

	err := c.Revoke(context.Background(), "acme", "github")
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("code = %v, want Unavailable (err=%v)", status.Code(err), err)
	}
}

func TestNew_RequiresAddrAndSVID(t *testing.T) {
	if _, err := New(context.Background(), "", "spiffe://zeroroot.ai/platform/daemon"); err == nil {
		t.Error("an empty address must be refused")
	}
	if _, err := New(context.Background(), "gibson-workloads:50051", ""); err == nil {
		t.Error("an empty daemon SVID must be refused")
	}
}

func TestClose_IsSafeWithoutTransport(t *testing.T) {
	var nilClient *Client
	if err := errors.Join(nilClient.Close(), NewWithConn(nil).Close()); err != nil {
		t.Fatalf("Close without a transport must be a no-op: %v", err)
	}
}
