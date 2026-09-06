// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"slices"
	"strings"
	"testing"

	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
)

func methodName(fullMethod string) string {
	if i := strings.LastIndex(fullMethod, "/"); i >= 0 {
		return fullMethod[i+1:]
	}
	return fullMethod
}

// TestMemberBaseRPCs_EveryEntryStatesItsReason: the list widens what a
// compromised member can do with nobody behind it, so each entry says why.
func TestMemberBaseRPCs_EveryEntryStatesItsReason(t *testing.T) {
	for name, reason := range memberBaseRPCs {
		if strings.TrimSpace(reason) == "" {
			t.Errorf("memberBaseRPCs[%q] has no reason", name)
		}
	}
}

// TestTurnGrantRPCs_CarriesTheWorkAndNotTheMember: a turn does the work and
// carries the sender's authority. It must not be able to take another job or
// acknowledge another turn's input.
func TestTurnGrantRPCs_CarriesTheWorkAndNotTheMember(t *testing.T) {
	got := TurnGrantRPCs()
	has := func(name string) bool {
		return slices.ContainsFunc(got, func(rpc string) bool { return methodName(rpc) == name })
	}
	for _, want := range []string{"Observe", "WorldView", "SubmitFinding", "CallToolProto", "DelegateToAgent", "LLMComplete"} {
		if !has(want) {
			t.Errorf("%s is the work of a turn and must be on the turn grant", want)
		}
	}
	for _, forbidden := range []string{"PullJob", "SubscribeInput", "ReportJobState", "ReportDeliverable", "PutSessionContext", "GetSessionContext"} {
		if has(forbidden) {
			t.Errorf("%s belongs to the member, not to a turn; one sender's authority must not reach another's work", forbidden)
		}
	}
	if has("GetCredential") {
		t.Error("GetCredential must not be on a turn grant: a turn's credentials are the job's declared names, decided per job")
	}
	if !has("RenewCapabilityGrant") {
		t.Error("a long-running turn must be able to renew before its grant expires")
	}
}

// TestGrantRPCs_AreStable: a minted grant must be byte-stable, or two identical
// dispatches would produce different tokens and nothing could compare them.
func TestGrantRPCs_AreStable(t *testing.T) {
	if !slices.Equal(TurnGrantRPCs(), TurnGrantRPCs()) {
		t.Error("the turn grant list must be stable")
	}
	if !slices.IsSorted(descriptorMethodNames()) {
		t.Error("descriptor names must be sorted, or the lists are not stable")
	}
}

// TestTurnGrantRPCs_CoversTheDescriptor: everything the service has, minus what
// is deliberately excluded, is on the turn grant. A new callback RPC is on it
// the day it lands rather than the day someone remembers.
func TestTurnGrantRPCs_CoversTheDescriptor(t *testing.T) {
	excluded := turnExcludedRPCs()
	want := 0
	for _, m := range descriptorMethodNames() {
		if _, skip := excluded[m]; !skip {
			want++
		}
	}
	if got := len(TurnGrantRPCs()) - 1; got != want { // -1 for renewal
		t.Fatalf("turn grant covers %d callback methods, want %d", got, want)
	}
	if len(harnesspb.HarnessCallbackService_ServiceDesc.Methods) == 0 {
		t.Fatal("the descriptor is empty; the derivation would be silently vacuous")
	}
}

func TestCredentialAllowedByJob(t *testing.T) {
	declared := []string{"gitlab-token", "npm-token"}
	if !CredentialAllowedByJob(declared, "gitlab-token") {
		t.Error("a declared credential must be allowed")
	}
	if CredentialAllowedByJob(declared, "site-admin") {
		t.Error("a credential the job never declared must be refused")
	}
	if CredentialAllowedByJob(declared, "") || CredentialAllowedByJob(declared, "   ") {
		t.Error("an empty name is not a declared credential")
	}
	if CredentialAllowedByJob(nil, "gitlab-token") {
		t.Error("a job that declares nothing reaches no credential")
	}
}
