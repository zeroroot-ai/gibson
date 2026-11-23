// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"slices"

	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
)

// MemberBaseGrantRPCs returns the allowed_rpcs of a member's base grant.
//
// Renewal is included because a member outlives any one grant's lifetime: a
// base grant that could not be renewed would silently stop a bank after an hour
// and look like a dead member.
func MemberBaseGrantRPCs() []string {
	desc := harnesspb.HarnessCallbackService_ServiceDesc
	out := make([]string, 0, len(memberBaseRPCs)+1)
	for _, m := range descriptorMethodNames() {
		if _, ok := memberBaseRPCs[m]; ok {
			out = append(out, "/"+desc.ServiceName+"/"+m)
		}
	}
	out = append(out, memberHeartbeatRPC, renewCapabilityGrantRPC)
	return out
}

// memberHeartbeatRPC is the component-registry heartbeat. It is on the base
// grant because a member that cannot heartbeat between turns is marked dead by
// the reconciler, and a member's only credential off-cluster is its grant
// (gibson#1605). It is a constant rather than a descriptor lookup because it
// lives on ComponentService, not on the callback service; the test checks it
// against that descriptor.
const memberHeartbeatRPC = "/gibson.component.v1.ComponentService/Heartbeat"

// grantableMemberHarnessCalls are the harness calls that a loop grant may add to
// the base grant of a member, with the reason for each (gibson#1612). The tool
// call is not on the list because a grant of a tool class implies it.
var grantableMemberHarnessCalls = map[string]string{
	"SubmitFinding": "report a finding that the loop of the member found",
}

// toolCallRPCName is the harness call that carries search_tools and invoke_tool.
const toolCallRPCName = "CallToolProto"

// GrantableMemberHarnessCalls returns the names that a loop grant may hold in
// its harness calls, sorted.
func GrantableMemberHarnessCalls() []string {
	out := make([]string, 0, len(grantableMemberHarnessCalls))
	for name := range grantableMemberHarnessCalls {
		out = append(out, name)
	}
	slices.Sort(out)
	return out
}

// MemberLoopGrantRPCs returns the allowed_rpcs that a loop grant adds to the
// base grant of a member: the tool call when the grant names a tool class, and
// each granted harness call. The names come from the generated descriptor, so a
// retired RPC cannot survive in a grant. A name that is not grantable is
// dropped, so an old row cannot widen a member.
func MemberLoopGrantRPCs(g *LoopGrant) []string {
	if g == nil {
		return nil
	}
	desc := harnesspb.HarnessCallbackService_ServiceDesc
	known := map[string]bool{}
	for _, m := range descriptorMethodNames() {
		known[m] = true
	}
	names := map[string]bool{}
	if len(g.ToolClasses) > 0 {
		names[toolCallRPCName] = true
	}
	for _, c := range g.HarnessCalls {
		if _, ok := grantableMemberHarnessCalls[c]; ok {
			names[c] = true
		}
	}
	out := make([]string, 0, len(names))
	for n := range names {
		if known[n] {
			out = append(out, "/"+desc.ServiceName+"/"+n)
		}
	}
	slices.Sort(out)
	return out
}
