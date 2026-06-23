/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package provision

import (
	"context"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	operatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
)

// TestUpsertTenantQuota_SendsConcurrentMissions guards tenant-operator#287:
// the gRPC client previously dropped ConcurrentMissions, sending Go's zero
// value (0 == unlimited) for every tenant regardless of plan.
// captureZitadelOrgServer records the SetTenantZitadelOrgRequest it received.
type captureZitadelOrgServer struct {
	operatorv1.UnimplementedDaemonOperatorServiceServer
	got *operatorv1.SetTenantZitadelOrgRequest
}

func (s *captureZitadelOrgServer) SetTenantZitadelOrg(_ context.Context, req *operatorv1.SetTenantZitadelOrgRequest) (*operatorv1.SetTenantZitadelOrgResponse, error) {
	s.got = req
	return &operatorv1.SetTenantZitadelOrgResponse{}, nil
}

// TestSetTenantZitadelOrg_SendsMapping guards gibson#621: the operator seeds
// the daemon's tenant -> Zitadel-org mapping with the right wire fields.
func TestSetTenantZitadelOrg_SendsMapping(t *testing.T) {
	srv := &captureZitadelOrgServer{}

	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	operatorv1.RegisterDaemonOperatorServiceServer(gs, srv)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial bufconn: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	c := &EntitlementsGRPCClient{
		client:   operatorv1.NewDaemonOperatorServiceClient(conn),
		audience: "gibson-daemon",
	}

	if err := c.SetTenantZitadelOrg(context.Background(), "tenant-team", "org-12345"); err != nil {
		t.Fatalf("SetTenantZitadelOrg: %v", err)
	}
	if srv.got == nil {
		t.Fatal("server received no SetTenantZitadelOrg request")
	}
	if got, want := srv.got.GetTenantId(), "tenant-team"; got != want {
		t.Errorf("tenant_id: got %q, want %q", got, want)
	}
	if got, want := srv.got.GetZitadelOrgId(), "org-12345"; got != want {
		t.Errorf("zitadel_org_id: got %q, want %q", got, want)
	}
}

// captureTenantStatusServer records the ReportTenantStatusRequest it received.
type captureTenantStatusServer struct {
	operatorv1.UnimplementedDaemonOperatorServiceServer
	got *operatorv1.ReportTenantStatusRequest
}

func (s *captureTenantStatusServer) ReportTenantStatus(_ context.Context, req *operatorv1.ReportTenantStatusRequest) (*operatorv1.ReportTenantStatusResponse, error) {
	s.got = req
	return &operatorv1.ReportTenantStatusResponse{}, nil
}

// TestReportTenantStatus_SendsAllFields guards dashboard#855: the operator
// mirrors the Tenant CR's aggregate status to the daemon with the right wire
// fields so the dashboard can read it without a K8s channel.
func TestReportTenantStatus_SendsAllFields(t *testing.T) {
	srv := &captureTenantStatusServer{}

	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	operatorv1.RegisterDaemonOperatorServiceServer(gs, srv)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial bufconn: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	c := &EntitlementsGRPCClient{
		client:   operatorv1.NewDaemonOperatorServiceClient(conn),
		audience: "gibson-daemon",
	}

	err = c.ReportTenantStatus(context.Background(), TenantStatusReport{
		TenantID:         "acme",
		Phase:            "Ready",
		Ready:            true,
		ZitadelOrgID:     "org-123",
		DataPlaneReady:   true,
		OwnerMemberReady: true,
	})
	if err != nil {
		t.Fatalf("ReportTenantStatus: %v", err)
	}
	if srv.got == nil {
		t.Fatal("server received no ReportTenantStatus request")
	}
	if srv.got.GetTenantId() != "acme" || srv.got.GetPhase() != "Ready" || !srv.got.GetReady() ||
		srv.got.GetZitadelOrgId() != "org-123" || !srv.got.GetDataPlaneReady() || !srv.got.GetOwnerMemberReady() {
		t.Errorf("unexpected ReportTenantStatus request: %+v", srv.got)
	}
}
