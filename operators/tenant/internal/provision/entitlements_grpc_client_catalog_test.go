// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package provision

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

	operatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
)

// catalogPluginServer answers the two catalog plugin RPCs.
type catalogPluginServer struct {
	operatorv1.UnimplementedDaemonOperatorServiceServer
	plugins []*operatorv1.DesiredCatalogPlugin
	err     error
	report  *operatorv1.ReportCatalogPluginStatusRequest
}

func (s *catalogPluginServer) ListDesiredCatalogPlugins(context.Context, *operatorv1.ListDesiredCatalogPluginsRequest) (*operatorv1.ListDesiredCatalogPluginsResponse, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &operatorv1.ListDesiredCatalogPluginsResponse{Plugins: s.plugins}, nil
}

func (s *catalogPluginServer) ReportCatalogPluginStatus(_ context.Context, req *operatorv1.ReportCatalogPluginStatusRequest) (*operatorv1.ReportCatalogPluginStatusResponse, error) {
	if s.err != nil {
		return nil, s.err
	}
	s.report = req
	return &operatorv1.ReportCatalogPluginStatusResponse{}, nil
}

// bufconnClient serves srv over an in-memory connection and returns a client
// over it.
func bufconnClient(t *testing.T, srv operatorv1.DaemonOperatorServiceServer) *EntitlementsGRPCClient {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	operatorv1.RegisterDaemonOperatorServiceServer(gs, srv)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial bufconn: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return &EntitlementsGRPCClient{client: operatorv1.NewDaemonOperatorServiceClient(conn), audience: "gibson-daemon"}
}

// The client maps each desired plugin of the daemon, and reports the phase
// of an instance with the fields the daemon reads.
func TestCatalogPlugins_ListAndReport(t *testing.T) {
	srv := &catalogPluginServer{plugins: []*operatorv1.DesiredCatalogPlugin{
		{TenantId: "acme", PluginId: "github", Image: "ghcr.io/x/github@sha256:aa", EgressAllow: []string{"api.github.com:443"}},
	}}
	c := bufconnClient(t, srv)
	got, err := c.ListDesiredCatalogPlugins(context.Background())
	if err != nil {
		t.Fatalf("ListDesiredCatalogPlugins: %v", err)
	}
	want := DesiredCatalogPlugin{TenantID: "acme", PluginID: "github", Image: "ghcr.io/x/github@sha256:aa", EgressAllow: []string{"api.github.com:443"}}
	if len(got) != 1 || got[0].TenantID != want.TenantID || got[0].PluginID != want.PluginID || got[0].Image != want.Image || len(got[0].EgressAllow) != 1 {
		t.Fatalf("plugins = %+v, want %+v", got, want)
	}
	if err := c.ReportCatalogPluginStatus(context.Background(), "acme", "github", "Running", ""); err != nil {
		t.Fatalf("ReportCatalogPluginStatus: %v", err)
	}
	if srv.report.GetTenantId() != "acme" || srv.report.GetPluginId() != "github" || srv.report.GetPhase() != "Running" {
		t.Fatalf("report = %+v", srv.report)
	}

	srv.err = status.Error(codes.Unavailable, "daemon down")
	if _, err := c.ListDesiredCatalogPlugins(context.Background()); err == nil {
		t.Fatal("a refused list must return the error")
	}
	if err := c.ReportCatalogPluginStatus(context.Background(), "acme", "github", "Failed", "x"); err == nil {
		t.Fatal("a refused report must return the error")
	}

	c.tokens = failingTokens{}
	if _, err := c.ListDesiredCatalogPlugins(context.Background()); !errors.Is(err, errNoToken) {
		t.Fatalf("list with no token: %v", err)
	}
	if err := c.ReportCatalogPluginStatus(context.Background(), "acme", "github", "Running", ""); !errors.Is(err, errNoToken) {
		t.Fatalf("report with no token: %v", err)
	}
}

var errNoToken = errors.New("no token")

type failingTokens struct{}

func (failingTokens) FetchToken(context.Context, string) (string, error) { return "", errNoToken }
