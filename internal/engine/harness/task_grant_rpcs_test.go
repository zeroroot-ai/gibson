// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/platform/capabilitygrant"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
)

// taskGrantRPCsNotInDescriptor returns the entries of list that name a
// HarnessCallbackService method the generated service descriptor does not have.
// It is the check behind the guard below, split out so a synthetic bad list can
// prove the guard fails (CLAUDE.md § 8: a guard that cannot fail is worse than
// no guard).
//
// An entry outside the callback service — the DaemonService renewal RPC — is
// not the descriptor's business and is reported by extraAllowed instead.
func taskGrantRPCsNotInDescriptor(list []string, extraAllowed map[string]bool) []string {
	desc := harnesspb.HarnessCallbackService_ServiceDesc
	known := map[string]bool{}
	for _, m := range desc.Methods {
		known["/"+desc.ServiceName+"/"+m.MethodName] = true
	}
	for _, st := range desc.Streams {
		known["/"+desc.ServiceName+"/"+st.StreamName] = true
	}
	var unknown []string
	for _, rpc := range list {
		if extraAllowed[rpc] {
			continue
		}
		if !strings.HasPrefix(rpc, "/"+desc.ServiceName+"/") {
			unknown = append(unknown, rpc)
			continue
		}
		if !known[rpc] {
			unknown = append(unknown, rpc)
		}
	}
	return unknown
}

// taskGrantExtraRPCs are the entries the grant carries that are deliberately
// not HarnessCallbackService methods.
var taskGrantExtraRPCs = map[string]bool{
	"/gibson.daemon.v1.DaemonService/RenewCapabilityGrant": true,
}

// TestTaskGrantAllowedRPCs_NamesNoRetiredMethod is the guard gibson#1603 asks
// for: no name on a task grant may be absent from the generated descriptor.
// The hand-kept list this replaced still named MemoryGet, MemorySet,
// MemoryDelete and GraphRAGQuery, none of which exist any more.
func TestTaskGrantAllowedRPCs_NamesNoRetiredMethod(t *testing.T) {
	if unknown := taskGrantRPCsNotInDescriptor(taskGrantAllowedRPCs(), taskGrantExtraRPCs); len(unknown) > 0 {
		t.Errorf("task grant names %d method(s) the descriptor does not have: %v", len(unknown), unknown)
	}
}

// TestTaskGrantRPCsNotInDescriptor_CatchesARetiredName is the failing fixture
// for the guard above. A list carrying one of the retired names must be
// reported, or the guard proves nothing.
func TestTaskGrantRPCsNotInDescriptor_CatchesARetiredName(t *testing.T) {
	bad := []string{
		"/gibson.harness.v1.HarnessCallbackService/Observe",
		"/gibson.harness.v1.HarnessCallbackService/MemoryGet",
		"/gibson.daemon.v1.DaemonService/RenewCapabilityGrant",
		"/gibson.other.v1.Service/Whatever",
	}
	got := taskGrantRPCsNotInDescriptor(bad, taskGrantExtraRPCs)
	if len(got) != 2 {
		t.Fatalf("unknown = %v, want the retired MemoryGet and the foreign RPC", got)
	}
	if got[0] != "/gibson.harness.v1.HarnessCallbackService/MemoryGet" {
		t.Errorf("first unknown = %q, want the retired MemoryGet", got[0])
	}
	if got[1] != "/gibson.other.v1.Service/Whatever" {
		t.Errorf("second unknown = %q, want the RPC outside the callback service", got[1])
	}
}

// TestTaskGrantAllowedRPCs_CoversTheCallbackSurface: the list is derived from
// the service descriptor, so the ADR-0012 write path and the knowledge reads
// are on it (gibson#1603), secret resolution is not, and renewal is.
func TestTaskGrantAllowedRPCs_CoversTheCallbackSurface(t *testing.T) {
	got := map[string]bool{}
	for _, r := range taskGrantAllowedRPCs() {
		got[r] = true
	}
	for _, want := range []string{
		"/gibson.harness.v1.HarnessCallbackService/Observe",
		"/gibson.harness.v1.HarnessCallbackService/WorldView",
		"/gibson.harness.v1.HarnessCallbackService/QueryNodes",
		"/gibson.harness.v1.HarnessCallbackService/SubmitFinding",
		"/gibson.harness.v1.HarnessCallbackService/LLMComplete",
		"/gibson.daemon.v1.DaemonService/RenewCapabilityGrant",
	} {
		if !got[want] {
			t.Errorf("missing %s", want)
		}
	}
	for r := range got {
		if strings.HasSuffix(r, "/GetCredential") {
			t.Errorf("secret resolution must not be on a task grant: %s", r)
		}
	}
	if len(got) < 20 {
		t.Errorf("only %d RPCs; the descriptor has more", len(got))
	}
}

// TestMinterFrom: the factory reads the daemon's minter at harness creation.
func TestMinterFrom(t *testing.T) {
	if minterFrom(nil) != nil {
		t.Fatal("nil getter must yield nil")
	}
	var current *capabilitygrant.Minter
	get := func() *capabilitygrant.Minter { return current }
	if minterFrom(get) != nil {
		t.Fatal("getter returning nil must yield nil")
	}
	current = testMinter(t)
	if minterFrom(get) != current {
		t.Fatal("getter must be read at call time")
	}
}

// TestMintCGForWork_UsesTheDescriptorList: a harness with a minter issues a
// task grant for the dispatched component.
func TestMintCGForWork_UsesTheDescriptorList(t *testing.T) {
	h := newRemoteAgentHarness(t, &queueFake{}, remoteAgentInstances())
	h.cgMinter = testMinter(t)
	h.missionCtx.ID = types.NewID()
	h.missionCtx.TenantID = "acme"
	h.missionCtx.MissionRunID = "run-1"
	if tok := h.mintCGForWork("claude", "agent"); tok == "" {
		t.Fatal("expected a minted task grant")
	}
}
