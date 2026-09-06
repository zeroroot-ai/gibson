// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	bankpb "github.com/zeroroot-ai/sdk/api/gen/gibson/bank/v1"
	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
)

type recordingMemberStatus struct {
	tenant, member string
	status         *bankpb.MemberStatus
	err            error
}

func (r *recordingMemberStatus) ReportMemberStatus(_ context.Context, tenant, member string, st *bankpb.MemberStatus) error {
	if r.err != nil {
		return r.err
	}
	r.tenant, r.member, r.status = tenant, member, st
	return nil
}

// TestHeartbeat_AMemberStatusGoesToTheSink asserts that a heartbeat carrying a
// member status is recorded under the caller's tenant and the member the
// instance id names, without touching the component registry, and that the
// sink's refusal is the caller's answer.
func TestHeartbeat_AMemberStatusGoesToTheSink(t *testing.T) {
	sink := &recordingMemberStatus{}
	svc := NewComponentServiceServer(&listRegistry{}, &noopWorkQueue{}, testLogger(), nil, nil, nil, nil).
		WithMemberStatusSink(sink)
	st := &bankpb.MemberStatus{State: bankpb.MemberState_MEMBER_STATE_BUSY, JobsInFlight: 1, Cap: 1}

	resp, err := svc.Heartbeat(componentCtx("component:agent:claude"), &componentpb.HeartbeatRequest{InstanceId: "m-1", Member: st})
	if err != nil || !resp.GetRegistered() {
		t.Fatalf("Heartbeat = %v, %v", resp, err)
	}
	if sink.tenant != "test-tenant" || sink.member != "m-1" || sink.status.GetJobsInFlight() != 1 {
		t.Fatalf("sink got %s/%s %+v", sink.tenant, sink.member, sink.status)
	}

	sink.err = errors.New("no such member")
	if _, err := svc.Heartbeat(componentCtx("component:agent:claude"), &componentpb.HeartbeatRequest{InstanceId: "m-9", Member: st}); status.Code(err) != codes.NotFound {
		t.Fatalf("err = %v, want NotFound", err)
	}
}

// TestHeartbeat_AMemberStatusOnADaemonWithNoBanksIsRefused asserts the
// heartbeat is refused, not dropped, when nothing records member status.
func TestHeartbeat_AMemberStatusOnADaemonWithNoBanksIsRefused(t *testing.T) {
	svc := NewComponentServiceServer(&listRegistry{}, &noopWorkQueue{}, testLogger(), nil, nil, nil, nil)
	_, err := svc.Heartbeat(componentCtx("component:agent:claude"), &componentpb.HeartbeatRequest{
		InstanceId: "m-1", Member: &bankpb.MemberStatus{State: bankpb.MemberState_MEMBER_STATE_IDLE},
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("err = %v, want FailedPrecondition", err)
	}
}
