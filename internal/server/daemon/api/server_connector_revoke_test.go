// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// server_connector_revoke_test.go — the operator-scoped RevokeConnectorGrant
// (ADR-0015 §5): it delegates to the shared revoker with the tenant carried
// explicitly, and answers Unavailable when no revoker is wired.
package api

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	daemonoperatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

type fakeGrantRevoker struct {
	tenant    string
	connector string
	hadGrant  bool
	err       error
	calls     int
}

func (f *fakeGrantRevoker) Revoke(_ context.Context, tenant auth.TenantID, connector string) (hadGrant, vendorRevoked bool, err error) {
	f.calls++
	f.tenant, f.connector = tenant.String(), connector
	return f.hadGrant, false, f.err
}

func TestRevokeConnectorGrant_DelegatesWithTheRequestTenant(t *testing.T) {
	rev := &fakeGrantRevoker{hadGrant: true}
	srv := NewDaemonServer(&mockDaemon{}, nil, nil).WithConnectorGrantRevoker(rev)

	resp, err := srv.RevokeConnectorGrant(context.Background(), &daemonoperatorv1.RevokeConnectorGrantRequest{
		TenantId: "acme", Connector: "github",
	})
	if err != nil {
		t.Fatalf("RevokeConnectorGrant: %v", err)
	}
	if !resp.GetHadGrant() || rev.tenant != "acme" || rev.connector != "github" {
		t.Errorf("delegated (%q, %q) had_grant=%v; want (acme, github) true", rev.tenant, rev.connector, resp.GetHadGrant())
	}
}

func TestRevokeConnectorGrant_UnwiredIsUnavailable(t *testing.T) {
	srv := NewDaemonServer(&mockDaemon{}, nil, nil)
	_, err := srv.RevokeConnectorGrant(context.Background(), &daemonoperatorv1.RevokeConnectorGrantRequest{
		TenantId: "acme", Connector: "github",
	})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("code = %v, want Unavailable", status.Code(err))
	}
}

func TestRevokeConnectorGrant_ValidatesInputAndPropagatesRevokeErrors(t *testing.T) {
	rev := &fakeGrantRevoker{err: status.Error(codes.Internal, "broker down")}
	srv := NewDaemonServer(&mockDaemon{}, nil, nil).WithConnectorGrantRevoker(rev)
	ctx := context.Background()

	if _, err := srv.RevokeConnectorGrant(ctx, &daemonoperatorv1.RevokeConnectorGrantRequest{Connector: "github"}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("missing tenant: code = %v, want InvalidArgument", status.Code(err))
	}
	if _, err := srv.RevokeConnectorGrant(ctx, &daemonoperatorv1.RevokeConnectorGrantRequest{TenantId: "acme"}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("missing connector: code = %v, want InvalidArgument", status.Code(err))
	}
	if rev.calls != 0 {
		t.Errorf("invalid input must not reach the revoker; calls = %d", rev.calls)
	}
	_, err := srv.RevokeConnectorGrant(ctx, &daemonoperatorv1.RevokeConnectorGrantRequest{TenantId: "acme", Connector: "github"})
	if status.Code(err) != codes.Internal || !errors.Is(err, err) {
		t.Errorf("revoke failure: code = %v, want Internal", status.Code(err))
	}
}
