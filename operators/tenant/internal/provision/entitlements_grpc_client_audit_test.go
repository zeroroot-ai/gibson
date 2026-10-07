// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package provision

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	operatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
	"github.com/zeroroot-ai/gibson/operators/internal/audit"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
)

// captureAuditServer records the EmitAuditEventRequest it received, or
// refuses it with err.
type captureAuditServer struct {
	operatorv1.UnimplementedDaemonOperatorServiceServer
	got *operatorv1.EmitAuditEventRequest
	err error
}

func (s *captureAuditServer) EmitAuditEvent(_ context.Context, req *operatorv1.EmitAuditEventRequest) (*operatorv1.EmitAuditEventResponse, error) {
	if s.err != nil {
		return nil, s.err
	}
	s.got = req
	return &operatorv1.EmitAuditEventResponse{}, nil
}

func auditClient(t *testing.T, srv operatorv1.DaemonOperatorServiceServer) *EntitlementsGRPCClient {
	t.Helper()
	return bufconnClient(t, srv)
}

// The client sends each field of the record (gibson#583).
func TestEmitAuditEvent_SendsTheRecord(t *testing.T) {
	srv := &captureAuditServer{}
	c := auditClient(t, srv)
	var sink audit.Sink = c
	err := sink.EmitAuditEvent(context.Background(), audit.Event{
		Action: audit.ActionSagaStep, TenantID: "acme", TargetType: "tenant", TargetID: "acme",
		Result: audit.ResultFailure, Reason: "redis down", Fields: map[string]string{"step": "InitRedisKeyspace"},
	})
	if err != nil {
		t.Fatalf("EmitAuditEvent: %v", err)
	}
	ev := srv.got.GetEvent()
	if ev.GetType() != audit.ActionSagaStep || ev.GetTenantId() != "acme" || ev.GetTargetType() != "tenant" ||
		ev.GetTargetId() != "acme" || ev.GetResult() != audit.ResultFailure || ev.GetReason() != "redis down" ||
		ev.GetFields()["step"] != "InitRedisKeyspace" {
		t.Fatalf("sent event = %v", ev)
	}
}

// A record the daemon could not write is a transient error, so the saga
// retries the step and makes no change meanwhile.
func TestEmitAuditEvent_UnwrittenRecordIsTransient(t *testing.T) {
	c := auditClient(t, &captureAuditServer{err: status.Error(codes.Unavailable, "the audit record could not be written")})
	err := c.EmitAuditEvent(context.Background(), audit.Event{Action: audit.ActionSagaStep, TenantID: "acme", TargetType: "tenant", TargetID: "acme"})
	if !errors.Is(err, clients.ErrUnreachable) {
		t.Fatalf("err = %v, want ErrUnreachable", err)
	}
}
