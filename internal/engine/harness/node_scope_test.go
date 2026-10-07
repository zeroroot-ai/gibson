// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
)

// A delegated agent gets the node and the network scope of its caller, and
// is never a fork source or a fork.
func TestInheritNodeScope(t *testing.T) {
	network := &agent.NodeNetwork{Targets: []string{"10.0.0.5:443"}}
	caller := MissionContext{NodeID: "exploit", NodeNetwork: network}
	in := agent.Task{Goal: "scan", NodeID: "forged", StartsFrom: "recon", Forkable: true}

	got := inheritNodeScope(in, caller)
	if got.NodeID != "exploit" || got.Network != network {
		t.Fatalf("task = %+v; want the node and the network of the caller", got)
	}
	if got.StartsFrom != "" || got.Forkable {
		t.Fatalf("task = %+v; a delegation must not fork", got)
	}
	if got.Goal != "scan" {
		t.Fatalf("goal = %q", got.Goal)
	}
}
