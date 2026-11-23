// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	enginemission "github.com/zeroroot-ai/gibson/internal/engine/mission"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	daemonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/daemon/v1"
)

// The error of a failed tenant tuple write has the same code on each path that
// creates a mission: Unavailable, so the caller retries. The message of the
// authorization store can hold "not found", and the handler maps a message by its
// text, so a plain message check would give this error NotFound.
func tenantRecordErr() error {
	return fmt.Errorf("failed to create mission: %w",
		fmt.Errorf("%w: mission m1: tuple not found, invalid store", enginemission.ErrTenantRecordFailed))
}

func TestCreateMission_ATenantRecordFailureIsUnavailable(t *testing.T) {
	daemon := &mockDaemon{createMissionFn: func(context.Context, CreateMissionData) (CreateMissionResultData, error) {
		return CreateMissionResultData{}, tenantRecordErr()
	}}
	server := NewDaemonServer(daemon, nil, nil)
	ctx := ctxWithTenantAdmin(context.Background(), "acme", "123456789012345678")

	_, err := server.CreateMission(ctx, &daemonpb.CreateMissionRequest{Name: "scan-by-hand", TargetId: "t1", MissionDefinitionId: "d1"})
	if got := status_grpc.Code(err); got != codes.Unavailable {
		t.Fatalf("code = %v (%v), want Unavailable", got, err)
	}
}

func TestPreserveStatus_ATenantRecordFailureIsUnavailable(t *testing.T) {
	// The start path (RunMission, the inbound A2A start) maps through preserveStatus.
	err := preserveStatus(tenantRecordErr(), "failed to start mission")
	if got := status_grpc.Code(err); got != codes.Unavailable {
		t.Fatalf("code = %v (%v), want Unavailable", got, err)
	}
	if got := status_grpc.Code(preserveStatus(errors.New("boom"), "x")); got != codes.Internal {
		t.Fatalf("a plain error keeps Internal, got %v", got)
	}
}

// A tenant with no data plane has no Agent Skills and no outside agents: the
// handlers answer NotFound, not Internal.
func TestSkillAndOutsideStatus_ATenantWithNoDataPlaneIsNotFound(t *testing.T) {
	err := fmt.Errorf("agent skill store: acquire conn: %w", &datapool.NotProvisionedError{Tenant: "e2e-stranger"})
	if got := status_grpc.Code(agentSkillStatus(context.Background(), "ListAgentSkills", err)); got != codes.NotFound {
		t.Fatalf("agent skill code = %v, want NotFound", got)
	}
	if got := status_grpc.Code(outsideAgentStatus("ListOutsideAgents", err)); got != codes.NotFound {
		t.Fatalf("outside agent code = %v, want NotFound", got)
	}
	if got := status_grpc.Code(agentSkillStatus(context.Background(), "x", errors.New("boom"))); got != codes.Internal {
		t.Fatalf("a plain error keeps Internal, got %v", got)
	}
}
