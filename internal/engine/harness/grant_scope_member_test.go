// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"slices"
	"testing"

	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
)

// TestMemberBaseGrantRPCs_IsTheLifetimeSurfaceAndNothingMore: a member acting
// as itself may take work and report on it. It may not read the tenant's World,
// submit a finding, call a tool, or spend the model budget — those need the
// authority of whoever asked for the turn.
func TestMemberBaseGrantRPCs_IsTheLifetimeSurfaceAndNothingMore(t *testing.T) {
	got := MemberBaseGrantRPCs()
	want := map[string]bool{
		"PullJob": true, "SubscribeInput": true,
		"ReportJobState": true, "ReportDeliverable": true,
		"PutSessionContext": true, "GetSessionContext": true,
		"Heartbeat": true, "RenewCapabilityGrant": true,
	}
	if len(got) != len(want) {
		t.Fatalf("base grant = %v, want exactly the lifetime surface", got)
	}
	for _, rpc := range got {
		if !want[methodName(rpc)] {
			t.Errorf("%s is on the base grant; a member acting as itself must not hold it", rpc)
		}
	}
	for _, forbidden := range []string{"SubmitFinding", "Observe", "WorldView", "LLMComplete", "CallToolProto", "GetCredential", "DelegateToAgent"} {
		for _, rpc := range got {
			if methodName(rpc) == forbidden {
				t.Errorf("%s must not be on the base grant: it is the work of a turn, not of a member", forbidden)
			}
		}
	}
}

// TestMemberBaseGrantRPCs_NamesOnlyRealMethods: every base-grant name comes
// from the generated descriptor, so a retired RPC cannot survive here.
func TestMemberBaseGrantRPCs_NamesOnlyRealMethods(t *testing.T) {
	known := map[string]bool{}
	for _, m := range descriptorMethodNames() {
		known[m] = true
	}
	for name := range memberBaseRPCs {
		if !known[name] {
			t.Errorf("memberBaseRPCs names %q, which HarnessCallbackService does not have", name)
		}
	}
	for _, rpc := range MemberBaseGrantRPCs() {
		if rpc == renewCapabilityGrantRPC || rpc == memberHeartbeatRPC {
			continue
		}
		if !known[methodName(rpc)] {
			t.Errorf("%s is not a method on the descriptor", rpc)
		}
	}
	// The heartbeat lives on ComponentService. Check it against THAT descriptor,
	// so a renamed heartbeat cannot survive here either.
	comp := componentpb.ComponentService_ServiceDesc
	found := false
	for _, m := range comp.Methods {
		if "/"+comp.ServiceName+"/"+m.MethodName == memberHeartbeatRPC {
			found = true
		}
	}
	if !found {
		t.Errorf("%s is not a method on ComponentService", memberHeartbeatRPC)
	}
}

// TestGrantRPCs_AreDisjointExceptRenewal: the two grants divide the surface;
// only renewal is on both, because both outlive one token.
func TestGrantRPCs_AreDisjointExceptRenewal(t *testing.T) {
	base := map[string]bool{}
	for _, rpc := range MemberBaseGrantRPCs() {
		base[rpc] = true
	}
	for _, rpc := range TurnGrantRPCs() {
		if base[rpc] && rpc != renewCapabilityGrantRPC {
			t.Errorf("%s is on both grants; the split is what keeps a member's authority out of a turn", rpc)
		}
	}
}

// TestMemberBaseGrantRPCs_IsStable: a minted grant must be byte-stable.
func TestMemberBaseGrantRPCs_IsStable(t *testing.T) {
	if !slices.Equal(MemberBaseGrantRPCs(), MemberBaseGrantRPCs()) {
		t.Error("the base grant list must be stable")
	}
}
