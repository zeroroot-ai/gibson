// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
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
