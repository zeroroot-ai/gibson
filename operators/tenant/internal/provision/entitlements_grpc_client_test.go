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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
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

// captureReportStatusServer records the ReportTenantStatusRequest it received
// and echoes a fixed billing_active flag back.
type captureReportStatusServer struct {
	operatorv1.UnimplementedDaemonOperatorServiceServer
	got           *operatorv1.ReportTenantStatusRequest
	billingActive bool
}

func (s *captureReportStatusServer) ReportTenantStatus(_ context.Context, req *operatorv1.ReportTenantStatusRequest) (*operatorv1.ReportTenantStatusResponse, error) {
	s.got = req
	return &operatorv1.ReportTenantStatusResponse{Updated: true, BillingActive: s.billingActive}, nil
}

// TestReportTenantStatus_SendsFieldsAndEchoesBilling guards the operator → daemon
// status report (gibson#948, dashboard#813): the client maps every status field
// onto the wire request and returns the daemon-echoed billing-active flag.
func TestReportTenantStatus_SendsFieldsAndEchoesBilling(t *testing.T) {
	srv := &captureReportStatusServer{billingActive: true}

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

	billingActive, err := c.ReportTenantStatus(context.Background(), TenantStatusReport{
		TenantID:         "tenant-team",
		Phase:            "Ready",
		DataPlaneReady:   true,
		StorePostgres:    "ready",
		StoreRedis:       "ready",
		StoreNeo4j:       "provisioning",
		ZitadelOrgSlug:   "team-org",
		StripeCustomerID: "cus_42",
	})
	if err != nil {
		t.Fatalf("ReportTenantStatus: %v", err)
	}
	if !billingActive {
		t.Errorf("expected echoed billing_active=true")
	}
	if srv.got == nil {
		t.Fatal("server received no ReportTenantStatus request")
	}
	if srv.got.GetTenantId() != "tenant-team" || srv.got.GetPhase() != "Ready" || !srv.got.GetDataPlaneReady() {
		t.Errorf("unexpected core fields: %+v", srv.got)
	}
	if srv.got.GetStorePostgres() != "ready" || srv.got.GetStoreNeo4J() != "provisioning" {
		t.Errorf("unexpected store fields: %+v", srv.got)
	}
	if srv.got.GetZitadelOrgSlug() != "team-org" || srv.got.GetStripeCustomerId() != "cus_42" {
		t.Errorf("unexpected org/stripe fields: %+v", srv.got)
	}
}

// errorReportStatusServer always fails ReportTenantStatus, exercising the
// client's gRPC error-translation branch.
type errorReportStatusServer struct {
	operatorv1.UnimplementedDaemonOperatorServiceServer
}

func (errorReportStatusServer) ReportTenantStatus(context.Context, *operatorv1.ReportTenantStatusRequest) (*operatorv1.ReportTenantStatusResponse, error) {
	return nil, status.Errorf(codes.Unavailable, "daemon down")
}

// TestReportTenantStatus_RPCError_Translated covers the client error path: a
// daemon-side failure is surfaced (not swallowed) so the caller logs it.
func TestReportTenantStatus_RPCError_Translated(t *testing.T) {
	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	operatorv1.RegisterDaemonOperatorServiceServer(gs, errorReportStatusServer{})
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
	if _, err := c.ReportTenantStatus(context.Background(), TenantStatusReport{TenantID: "acme"}); err == nil {
		t.Fatal("expected error to be surfaced from a failing daemon")
	}
}
