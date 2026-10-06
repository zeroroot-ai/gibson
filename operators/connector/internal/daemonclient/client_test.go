// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemonclient

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	daemonoperatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

// fakeOperatorService records the calls it receives and answers as told.
type fakeOperatorService struct {
	daemonoperatorv1.UnimplementedDaemonOperatorServiceServer
	got        *daemonoperatorv1.RevokeConnectorGrantRequest
	gotStatus  *daemonoperatorv1.GetConnectorAuthStatusRequest
	statusResp *tenantv1.GetConnectorAuthStatusResponse
	err        error
}

func (f *fakeOperatorService) GetConnectorAuthStatus(_ context.Context, req *daemonoperatorv1.GetConnectorAuthStatusRequest) (*daemonoperatorv1.GetConnectorAuthStatusResponse, error) {
	f.gotStatus = req
	if f.err != nil {
		return nil, f.err
	}
	return &daemonoperatorv1.GetConnectorAuthStatusResponse{Status: f.statusResp}, nil
}

func (f *fakeOperatorService) RevokeConnectorGrant(_ context.Context, req *daemonoperatorv1.RevokeConnectorGrantRequest) (*tenantv1.RevokeConnectorGrantResponse, error) {
	f.got = req
	if f.err != nil {
		return nil, f.err
	}
	return &tenantv1.RevokeConnectorGrantResponse{}, nil
}

func (f *fakeOperatorService) ListDesiredConnectors(context.Context, *daemonoperatorv1.ListDesiredConnectorsRequest) (*daemonoperatorv1.ListDesiredConnectorsResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &daemonoperatorv1.ListDesiredConnectorsResponse{Connectors: []*daemonoperatorv1.DesiredConnector{{TenantId: "acme", ConnectorId: "gitlab"}}}, nil
}

func (f *fakeOperatorService) ReportConnectorStatus(_ context.Context, req *daemonoperatorv1.ReportConnectorStatusRequest) (*daemonoperatorv1.ReportConnectorStatusResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &daemonoperatorv1.ReportConnectorStatusResponse{Updated: req.GetTenantId() == "acme"}, nil
}

func (f *fakeOperatorService) AdoptConnector(context.Context, *daemonoperatorv1.AdoptConnectorRequest) (*daemonoperatorv1.AdoptConnectorResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &daemonoperatorv1.AdoptConnectorResponse{}, nil
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

// AuthStatus carries the tenant and connector to the daemon and returns the
// credential state the controller records as the Degraded condition
// (ADR-0061).
func TestAuthStatus_CarriesTenantAndConnector(t *testing.T) {
	svc := &fakeOperatorService{statusResp: &tenantv1.GetConnectorAuthStatusResponse{
		State:            tenantv1.ConnectorAuthState_CONNECTOR_AUTH_STATE_REFRESH_FAILING,
		LastRefreshError: "invalid_grant",
	}}
	c := dialFake(t, svc)

	got, err := c.AuthStatus(context.Background(), "acme", "github")
	if err != nil {
		t.Fatalf("AuthStatus: %v", err)
	}
	if svc.gotStatus.GetTenantId() != "acme" || svc.gotStatus.GetConnector() != "github" {
		t.Errorf("request = %+v, want tenant acme connector github", svc.gotStatus)
	}
	if got.GetState() != tenantv1.ConnectorAuthState_CONNECTOR_AUTH_STATE_REFRESH_FAILING {
		t.Errorf("state = %v, want REFRESH_FAILING", got.GetState())
	}
	if got.GetLastRefreshError() != "invalid_grant" {
		t.Errorf("last_refresh_error = %q, want the vendor error code", got.GetLastRefreshError())
	}
}

// A daemon that cannot answer is an error the controller degrades on, and the
// message names the tenant and connector it asked about.
func TestAuthStatus_WrapsTheDaemonError(t *testing.T) {
	svc := &fakeOperatorService{err: status.Error(codes.Unavailable, "secrets stack down")}
	c := dialFake(t, svc)

	_, err := c.AuthStatus(context.Background(), "acme", "github")
	if err == nil {
		t.Fatal("an unavailable daemon must surface as an error")
	}
	if status.Code(err) != codes.Unavailable {
		t.Errorf("code = %v, want Unavailable", status.Code(err))
	}
	if !strings.Contains(err.Error(), "acme/github") {
		t.Errorf("error = %q, want the tenant and connector named", err.Error())
	}
}

// The three connector RPCs pass the request and surface the daemon error.
func TestConnectorRPCs(t *testing.T) {
	ctx := context.Background()
	c := dialFake(t, &fakeOperatorService{})
	got, err := c.ListDesiredConnectors(ctx)
	if err != nil || len(got) != 1 || got[0].GetConnectorId() != "gitlab" {
		t.Fatalf("ListDesiredConnectors = %v, %v", got, err)
	}
	if err := c.ReportConnectorStatus(ctx, &daemonoperatorv1.ReportConnectorStatusRequest{TenantId: "acme", ConnectorId: "gitlab", Phase: "Ready"}); err != nil {
		t.Fatalf("ReportConnectorStatus: %v", err)
	}
	if err := c.AdoptConnector(ctx, "acme", "gitlab"); err != nil {
		t.Fatalf("AdoptConnector: %v", err)
	}

	down := dialFake(t, &fakeOperatorService{err: status.Error(codes.Unavailable, "down")})
	if _, err := down.ListDesiredConnectors(ctx); status.Code(err) != codes.Unavailable {
		t.Errorf("ListDesiredConnectors: code %v", status.Code(err))
	}
	if err := down.ReportConnectorStatus(ctx, &daemonoperatorv1.ReportConnectorStatusRequest{TenantId: "acme"}); status.Code(err) != codes.Unavailable {
		t.Errorf("ReportConnectorStatus: code %v", status.Code(err))
	}
	if err := down.AdoptConnector(ctx, "acme", "gitlab"); status.Code(err) != codes.Unavailable {
		t.Errorf("AdoptConnector: code %v", status.Code(err))
	}
}
