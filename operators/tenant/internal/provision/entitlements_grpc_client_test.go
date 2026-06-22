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

	"github.com/zeroroot-ai/gibson/operators/tenant/plans"
	operatorv1 "github.com/zeroroot-ai/gibson/internal/daemon/api/gibson/daemon/operator/v1"
)

// captureQuotaServer records the last UpsertTenantQuotaRequest it received so
// the test can assert the wire-level mapping performed by EntitlementsGRPCClient.
type captureQuotaServer struct {
	operatorv1.UnimplementedDaemonOperatorServiceServer
	got *operatorv1.UpsertTenantQuotaRequest
}

func (s *captureQuotaServer) UpsertTenantQuota(_ context.Context, req *operatorv1.UpsertTenantQuotaRequest) (*operatorv1.UpsertTenantQuotaResponse, error) {
	s.got = req
	return &operatorv1.UpsertTenantQuotaResponse{}, nil
}

// TestUpsertTenantQuota_SendsConcurrentMissions guards tenant-operator#287:
// the gRPC client previously dropped ConcurrentMissions, sending Go's zero
// value (0 == unlimited) for every tenant regardless of plan.
func TestUpsertTenantQuota_SendsConcurrentMissions(t *testing.T) {
	srv := &captureQuotaServer{}

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

	// Construct the client against the in-memory connection, bypassing the
	// SPIFFE transport (unexported fields are reachable from the same package).
	c := &EntitlementsGRPCClient{
		client:   operatorv1.NewDaemonOperatorServiceClient(conn),
		audience: "gibson-daemon",
	}

	q := plans.Quotas{PlanID: "team", ConcurrentAgents: 5, ConcurrentMissions: 10}
	if err := c.UpsertTenantQuota(context.Background(), "tenant-team", q); err != nil {
		t.Fatalf("UpsertTenantQuota: %v", err)
	}

	if srv.got == nil {
		t.Fatal("server received no UpsertTenantQuota request")
	}
	if got, want := srv.got.GetTenantId(), "tenant-team"; got != want {
		t.Errorf("tenant_id: got %q, want %q", got, want)
	}
	if got, want := srv.got.GetConcurrentAgents(), int32(5); got != want {
		t.Errorf("concurrent_agents: got %d, want %d", got, want)
	}
	if got, want := srv.got.GetConcurrentMissions(), int32(10); got != want {
		t.Errorf("concurrent_missions: got %d, want %d", got, want)
	}
	if got, want := srv.got.GetPlanId(), "team"; got != want {
		t.Errorf("plan_id: got %q, want %q", got, want)
	}
}

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
