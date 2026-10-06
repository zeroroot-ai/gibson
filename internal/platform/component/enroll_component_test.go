// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

type recordingEnroller struct {
	tenant, producer string
	spec             ProducedComponentSpec
	err              error
}

func (r *recordingEnroller) EnrollProduced(_ context.Context, tenantID, producer string, c ProducedComponentSpec) (EnrolledProducedComponent, error) {
	r.tenant, r.producer, r.spec = tenantID, producer, c
	if r.err != nil {
		return EnrolledProducedComponent{}, r.err
	}
	return EnrolledProducedComponent{PrincipalID: "tool_principal:new", BootstrapToken: "one-time", ExpiresAt: time.Unix(1800000000, 0)}, nil
}

func componentCaller(tenant, subject string) context.Context {
	return auth.WithIdentity(context.Background(), auth.Identity{Subject: subject, Tenant: auth.MustNewTenantID(tenant)})
}

func TestEnrollComponent_TakesTheTenantAndTheProducerFromTheIdentity(t *testing.T) {
	svc := NewComponentServiceServer(&countingRegistry{}, &noopWorkQueue{}, testLogger(), nil, nil, nil, nil)
	enr := &recordingEnroller{}
	svc.WithProducedComponentEnroller(enr)

	resp, err := svc.EnrollComponent(componentCaller("acme", "agent_principal:p-1"), &componentpb.EnrollComponentRequest{
		Kind: "tool", Name: "port-sniffer", Version: "0.1.0", Image: "img@sha256:abc", Description: "scans",
	})
	if err != nil {
		t.Fatalf("EnrollComponent: %v", err)
	}
	if enr.tenant != "acme" || enr.producer != "agent_principal:p-1" {
		t.Errorf("tenant=%q producer=%q, want acme and the caller", enr.tenant, enr.producer)
	}
	if enr.spec != (ProducedComponentSpec{Kind: "tool", Name: "port-sniffer", Version: "0.1.0", Image: "img@sha256:abc", Description: "scans"}) {
		t.Errorf("spec = %+v", enr.spec)
	}
	if resp.GetPrincipalId() != "tool_principal:new" || resp.GetBootstrapToken() != "one-time" || resp.GetExpiresAt().AsTime().Unix() != 1800000000 {
		t.Errorf("response = %+v", resp)
	}
}

func TestEnrollComponent_Refusals(t *testing.T) {
	svc := NewComponentServiceServer(&countingRegistry{}, &noopWorkQueue{}, testLogger(), nil, nil, nil, nil)
	req := &componentpb.EnrollComponentRequest{Kind: "tool", Name: "a-tool", Version: "1", Image: "img@sha256:abc"}

	if _, err := svc.EnrollComponent(componentCaller("acme", "agent_principal:p-1"), req); status.Code(err) != codes.Unavailable {
		t.Fatalf("no enroller: want Unavailable, got %v", err)
	}

	enr := &recordingEnroller{}
	svc.WithProducedComponentEnroller(enr)
	if _, err := svc.EnrollComponent(context.Background(), req); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("no identity: want Unauthenticated, got %v", err)
	}

	enr.err = status.Error(codes.ResourceExhausted, "quota")
	if _, err := svc.EnrollComponent(componentCaller("acme", "agent_principal:p-1"), req); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("enroller error: want it unchanged, got %v", err)
	}
}
