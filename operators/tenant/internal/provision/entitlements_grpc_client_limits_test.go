// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package provision

import (
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	operatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
)

// captureLimitsServer records the SetAgentEnrollmentLimitsRequest it received,
// or answers with err.
type captureLimitsServer struct {
	operatorv1.UnimplementedDaemonOperatorServiceServer
	got *operatorv1.SetAgentEnrollmentLimitsRequest
	err error
}

func (s *captureLimitsServer) SetAgentEnrollmentLimits(_ context.Context, req *operatorv1.SetAgentEnrollmentLimitsRequest) (*operatorv1.SetAgentEnrollmentLimitsResponse, error) {
	s.got = req
	return &operatorv1.SetAgentEnrollmentLimitsResponse{}, s.err
}

func limitsClient(t *testing.T, srv *captureLimitsServer) *EntitlementsGRPCClient {
	t.Helper()
	return bufconnClient(t, srv)
}

// TestSetAgentEnrollmentLimits_SendsTheCapInSeconds guards gibson#597: the
// operator reports spec.maxRuntime to the daemon as whole seconds, keyed by
// tenant and agent name.
func TestSetAgentEnrollmentLimits_SendsTheCapInSeconds(t *testing.T) {
	srv := &captureLimitsServer{}
	c := limitsClient(t, srv)
	if err := c.SetAgentEnrollmentLimits(context.Background(), "tenant-acme", "breach-checker", 15*time.Minute); err != nil {
		t.Fatalf("SetAgentEnrollmentLimits: %v", err)
	}
	if srv.got.GetTenantId() != "tenant-acme" || srv.got.GetAgentName() != "breach-checker" || srv.got.GetMaxRuntimeSeconds() != 900 {
		t.Errorf("request = %+v, want tenant-acme, breach-checker, 900 seconds", srv.got)
	}
}

// TestSetAgentEnrollmentLimits_RPCErrorNamesTheAgent proves a daemon refusal
// keeps its status code and names the tenant and the agent.
func TestSetAgentEnrollmentLimits_RPCErrorNamesTheAgent(t *testing.T) {
	c := limitsClient(t, &captureLimitsServer{err: status.Error(codes.Unavailable, "platform Postgres not configured")})
	err := c.SetAgentEnrollmentLimits(context.Background(), "tenant-acme", "breach-checker", time.Minute)
	if status.Code(err) != codes.Unavailable || !strings.Contains(err.Error(), "tenant-acme/breach-checker") {
		t.Fatalf("error = %v, want Unavailable naming tenant-acme/breach-checker", err)
	}
}
