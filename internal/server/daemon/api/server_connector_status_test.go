// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// server_connector_status_test.go — the operator-scoped GetConnectorAuthStatus
// (ADR-0015 decision 4): it delegates to the same status view the dashboard
// reads with the tenant carried explicitly, and answers Unavailable when no
// reader is wired, so the controller never reports a health nobody checked.
package api

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	daemonoperatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

type fakeAuthStatusReader struct {
	tenant    string
	connector string
	resp      *tenantv1.GetConnectorAuthStatusResponse
}

func (f *fakeAuthStatusReader) AuthStatus(_ context.Context, tenant auth.TenantID, connector string) *tenantv1.GetConnectorAuthStatusResponse {
	f.tenant, f.connector = tenant.String(), connector
	return f.resp
}

// A revoked grant reaches the operator as REFRESH_FAILING carrying the
// vendor's own error code — the only thing that tells a revoked grant from a
// misconfigured client.
func TestGetConnectorAuthStatus_DelegatesWithTheRequestTenant(t *testing.T) {
	reader := &fakeAuthStatusReader{resp: &tenantv1.GetConnectorAuthStatusResponse{
		State:            tenantv1.ConnectorAuthState_CONNECTOR_AUTH_STATE_REFRESH_FAILING,
		LastRefreshError: "invalid_grant",
	}}
	srv := NewDaemonServer(&mockDaemon{}, nil, nil).WithConnectorAuthStatusReader(reader)

	resp, err := srv.GetConnectorAuthStatus(context.Background(), &daemonoperatorv1.GetConnectorAuthStatusRequest{
		TenantId: "acme", Connector: "github",
	})
	if err != nil {
		t.Fatalf("GetConnectorAuthStatus: %v", err)
	}
	if reader.tenant != "acme" || reader.connector != "github" {
		t.Errorf("delegated (%q, %q), want (acme, github)", reader.tenant, reader.connector)
	}
	if got := resp.GetStatus().GetState(); got != tenantv1.ConnectorAuthState_CONNECTOR_AUTH_STATE_REFRESH_FAILING {
		t.Errorf("state = %v, want REFRESH_FAILING", got)
	}
	if got := resp.GetStatus().GetLastRefreshError(); got != "invalid_grant" {
		t.Errorf("last_refresh_error = %q, want the vendor error code", got)
	}
}

func TestGetConnectorAuthStatus_UnwiredIsUnavailable(t *testing.T) {
	srv := NewDaemonServer(&mockDaemon{}, nil, nil)
	_, err := srv.GetConnectorAuthStatus(context.Background(), &daemonoperatorv1.GetConnectorAuthStatusRequest{
		TenantId: "acme", Connector: "github",
	})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("code = %v, want Unavailable", status.Code(err))
	}
}

func TestGetConnectorAuthStatus_ValidatesInput(t *testing.T) {
	srv := NewDaemonServer(&mockDaemon{}, nil, nil).
		WithConnectorAuthStatusReader(&fakeAuthStatusReader{resp: &tenantv1.GetConnectorAuthStatusResponse{}})

	if _, err := srv.GetConnectorAuthStatus(context.Background(),
		&daemonoperatorv1.GetConnectorAuthStatusRequest{Connector: "github"}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("empty tenant_id code = %v, want InvalidArgument", status.Code(err))
	}
	if _, err := srv.GetConnectorAuthStatus(context.Background(),
		&daemonoperatorv1.GetConnectorAuthStatusRequest{TenantId: "acme"}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("empty connector code = %v, want InvalidArgument", status.Code(err))
	}
}
