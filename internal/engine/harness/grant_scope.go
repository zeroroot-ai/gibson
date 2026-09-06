// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"slices"
	"strings"

	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
)

// Grant scopes for a bank member (ADR-0019 decision 2, gibson#1711).
//
// A one-shot dispatch holds ONE grant for its whole run, so the run's grant and
// the run's authority are the same thing. A member is different: one sandbox
// serves many dispatches over its life, and the authority of one sender must
// not become the authority of the next. So a member holds two kinds of grant.
//
//   - The BASE grant, minted once at launch, covers what the member does as
//     itself: pull a job, follow its inbox, report what it is doing, report a
//     deliverable, renew. It reaches nothing tenant-shaped. A member that lost
//     its base grant to an attacker could take work and report on it; it could
//     not read a finding, call a tool, or spend the tenant's model budget.
//   - The TURN grant, minted per input, covers the work of that one turn and
//     carries the authority of the sender who asked for it.
//
// Both lists are derived from the generated service descriptor, so a retired
// RPC cannot survive in either (gibson#1603).

// memberBaseRPCs is the lifetime surface: what a member may call as itself,
// between turns, with no sender behind it.
//
// It is written as a set of method NAMES rather than full paths so the
// descriptor check below can prove every one of them exists. Adding a name here
// widens what a compromised member can do with no sender's authority, which is
// why the list is short and each entry says why it is on it.
var memberBaseRPCs = map[string]string{
	"PullJob":           "take the next queued job of its own bank",
	"SubscribeInput":    "follow its own inbox",
	"ReportJobState":    "say which job it is working on and which session holds it",
	"ReportDeliverable": "record what it pushed at wrap-up",
	"PutSessionContext": "archive its own Claude session between turns",
	"GetSessionContext": "read its own archive back after a restart",
}

// turnExcludedRPCs are the methods a TURN grant never carries, and why.
//
// GetCredential is excluded because a turn's credentials are decided per job,
// not per grant: the callback resolves them against the job's declared
// credential_names, and putting the RPC on the grant would say the member may
// read any credential the tenant has.
//
// The base-grant methods are excluded because a turn is not the member acting
// as itself. A turn that could pull another job or acknowledge another turn's
// input would let one sender's authority reach into another's work, and a turn
// that could rewrite the member's session archive could poison the next turn.
func turnExcludedRPCs() map[string]struct{} {
	out := map[string]struct{}{"GetCredential": {}}
	for m := range memberBaseRPCs {
		out[m] = struct{}{}
	}
	return out
}

// TurnGrantRPCs returns the allowed_rpcs of one turn's grant: the work surface,
// minus what belongs to the member rather than to the turn.
//
// It is descriptor-derived for the same reason the task-grant list is: a
// hand-kept list drifts, and the drift is invisible until a callback fails in
// production (gibson#1603).
func TurnGrantRPCs() []string {
	desc := harnesspb.HarnessCallbackService_ServiceDesc
	excluded := turnExcludedRPCs()
	names := descriptorMethodNames()
	out := make([]string, 0, len(names)+1)
	for _, m := range names {
		if _, skip := excluded[m]; skip {
			continue
		}
		out = append(out, "/"+desc.ServiceName+"/"+m)
	}
	out = append(out, renewCapabilityGrantRPC)
	return out
}

// renewCapabilityGrantRPC is the one method outside HarnessCallbackService that
// both grants carry: a long-running turn and a long-lived member both have to
// renew before their grant expires.
const renewCapabilityGrantRPC = "/gibson.daemon.v1.DaemonService/RenewCapabilityGrant"

// descriptorMethodNames returns every method name of HarnessCallbackService,
// unary and streaming, sorted so a minted grant is byte-stable.
func descriptorMethodNames() []string {
	desc := harnesspb.HarnessCallbackService_ServiceDesc
	out := make([]string, 0, len(desc.Methods)+len(desc.Streams))
	for _, m := range desc.Methods {
		out = append(out, m.MethodName)
	}
	for _, st := range desc.Streams {
		out = append(out, st.StreamName)
	}
	slices.Sort(out)
	return out
}

// CredentialAllowedByJob reports whether a job's spec declares the named
// credential.
//
// This is the per-turn credential boundary, and it is deliberately answered
// from the STORED JobSpec rather than from a claim on the grant. A claim can be
// copied out of a token; the spec is what the opener declared and what a person
// can read back on the job. The two would also have to be kept in step, and the
// one that drifted would be the one an attacker found.
func CredentialAllowedByJob(declared []string, name string) bool {
	name = strings.TrimSpace(name)
	if name == "" {
		return false
	}
	return slices.Contains(declared, name)
}
