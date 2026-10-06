// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemonaudit

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc"

	operatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
	"github.com/zeroroot-ai/gibson/operators/internal/audit"
)

type fakeDaemon struct {
	operatorv1.DaemonOperatorServiceClient
	got []*operatorv1.EmitAuditEventRequest
}

func (f *fakeDaemon) EmitAuditEvent(_ context.Context, in *operatorv1.EmitAuditEventRequest, _ ...grpc.CallOption) (*operatorv1.EmitAuditEventResponse, error) {
	f.got = append(f.got, in)
	return &operatorv1.EmitAuditEventResponse{}, nil
}

// The sink never dials at boot. It dials on the first record, and a failed
// dial is tried again on the next record (gibson#583).
func TestSink_DialsOnUseAndRetries(t *testing.T) {
	daemon := &fakeDaemon{}
	dials := 0
	s, err := New(func(context.Context) (operatorv1.DaemonOperatorServiceClient, func() error, error) {
		dials++
		if dials == 1 {
			return nil, nil, errors.New("no SPIRE agent yet")
		}
		return daemon, func() error { return nil }, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if dials != 0 {
		t.Fatalf("the sink dialed at construction: %d", dials)
	}
	ev := audit.Event{Action: audit.ActionPlatformBootstrap, TenantID: "_system", TargetType: "platformbootstrap", TargetID: "platform"}
	if err := s.EmitAuditEvent(context.Background(), ev); err == nil {
		t.Fatal("a failed dial sent nothing and must say so")
	}
	if err := s.EmitAuditEvent(context.Background(), ev); err != nil {
		t.Fatalf("second record: %v", err)
	}
	if err := s.EmitAuditEvent(context.Background(), ev); err != nil {
		t.Fatalf("third record: %v", err)
	}
	if dials != 2 || len(daemon.got) != 2 || daemon.got[0].GetEvent().GetType() != audit.ActionPlatformBootstrap {
		t.Fatalf("dials = %d, sent = %d; want one retry dial and two records", dials, len(daemon.got))
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestSettings_RequiresBoth(t *testing.T) {
	env := map[string]string{"GIBSON_DAEMON_GRPC_ADDRESS": "gibson:50051"}
	if _, _, err := Settings(func(k string) string { return env[k] }); err == nil {
		t.Fatal("Settings accepted no daemon SPIFFE id")
	}
	env["GIBSON_DAEMON_SPIFFE_ID"] = "spiffe://example.org/platform/daemon"
	if addr, svid, err := Settings(func(k string) string { return env[k] }); err != nil || addr == "" || svid == "" {
		t.Fatalf("Settings = %q %q %v", addr, svid, err)
	}
}
