// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Guard tests for the harness callback listener's per-peer method policy
// (identity-assertion-gaps finding 2 / GHSA-cwgm-qw3c-4ph7, GHSA-2mmp-x243-f69j).
//
// The listener previously carried a DENYLIST (callbackDeniedSVIDs) naming only
// the dashboard. Its failure mode is the one a denylist always has: every peer
// it did not name — the Envoy SVID, the daemon loopback SVID, and any SVID
// added to GIBSON_CALLBACK_PEER_SVIDS later — kept unbounded (subject, tenant)
// assertion across every RPC on the service, GetCredential included. These
// tests pin the inverted, fail-closed shape.

package harness

import (
	"context"
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// serviceDescMethods enumerates every fully-qualified method name on the
// generated HarnessCallbackService descriptor — unary and streaming.
func serviceDescMethods() []string {
	desc := harnesspb.HarnessCallbackService_ServiceDesc
	methods := make([]string, 0, len(desc.Methods)+len(desc.Streams))
	for _, m := range desc.Methods {
		methods = append(methods, "/"+desc.ServiceName+"/"+m.MethodName)
	}
	for _, s := range desc.Streams {
		methods = append(methods, "/"+desc.ServiceName+"/"+s.StreamName)
	}
	return methods
}

// TestCallbackMethodPolicy_ClassifiesEveryRPC is the completeness guard. A new
// RPC added to the proto must be classified deliberately; it must not inherit
// access from an unclassified fall-through, and it must not silently lose it.
func TestCallbackMethodPolicy_ClassifiesEveryRPC(t *testing.T) {
	var unclassified []string
	for _, method := range serviceDescMethods() {
		if _, ok := callbackMethodPolicy[method]; !ok {
			unclassified = append(unclassified, method)
		}
	}
	assert.Empty(t, unclassified,
		"every HarnessCallbackService RPC must be classified in callbackMethodPolicy as "+
			"agent-surface XOR denied. Unclassified RPCs: %v", unclassified)

	// And nothing stale: a key that no longer exists on the service is a policy
	// entry nobody enforces.
	live := make(map[string]bool)
	for _, m := range serviceDescMethods() {
		live[m] = true
	}
	for method := range callbackMethodPolicy {
		assert.True(t, live[method],
			"callbackMethodPolicy classifies %q, which is not a method on HarnessCallbackService_ServiceDesc", method)
	}
}

// TestCallbackMethodPolicy_EveryDecisionHasReason keeps the table auditable:
// both allow and deny entries must say why.
func TestCallbackMethodPolicy_EveryDecisionHasReason(t *testing.T) {
	for method, decision := range callbackMethodPolicy {
		assert.NotEmpty(t, decision.reason, "callbackMethodPolicy[%q] has no reason", method)
	}
}

// TestCallbackAgentSurface_MatchesImplementedRPCs is the reconciliation test.
// The agent-surface grant is pinned to exactly the RPCs this daemon serves: a
// missing grant would break a live in-mission callback, and a surplus grant
// would be a standing over-grant on an RPC that cannot even be handled.
//
// The unimplemented map pins the proto-declared RPCs that have no handler in
// this package — they fall through to
// UnimplementedHarnessCallbackServiceServer. Adding a handler means removing
// the RPC from this map AND flipping its callbackMethodPolicy entry to
// agentSurface, in the same change.
func TestCallbackAgentSurface_MatchesImplementedRPCs(t *testing.T) {
	unimplemented := map[string]bool{
		harnesspb.HarnessCallbackService_GetPlanContext_FullMethodName:  true,
		harnesspb.HarnessCallbackService_ReportStepHints_FullMethodName: true,
		// The three job callbacks a DISPATCHED AGENT calls to drive a bank.
		// They mirror JobService and land with the job node executor,
		// gibson#1713. The four a MEMBER calls landed in gibson#1711 and are
		// deliberately absent here.
		harnesspb.HarnessCallbackService_OpenJob_FullMethodName:   true,
		harnesspb.HarnessCallbackService_SendInput_FullMethodName: true,
		harnesspb.HarnessCallbackService_CloseJob_FullMethodName:  true,
		// WorldView handler landed in gibson#1377 — no longer unimplemented.
		// Session-context store handlers landed (gibson#1184,
		// callback_session_context.go) — no longer unimplemented.
		// DevboxExec (gibson#1183) is IMPLEMENTED as of setec#239 landing the
		// in-VM exec channel — callback_devbox_exec.go serves it through the
		// session-sandbox registry — so it is deliberately absent here and
		// carries agentSurface: true.
	}

	for _, method := range serviceDescMethods() {
		decision, ok := callbackMethodPolicy[method]
		require.True(t, ok, "%s unclassified — see TestCallbackMethodPolicy_ClassifiesEveryRPC", method)
		if unimplemented[method] {
			assert.False(t, decision.agentSurface,
				"%s has no handler on this daemon; granting it to the agent-callback peers "+
					"is a standing over-grant", method)
			continue
		}
		assert.True(t, decision.agentSurface,
			"%s is served by a handler in this package and is part of the in-mission agent "+
				"callback surface; denying it BREAKS a live callback path", method)
	}
}

// TestCallbackPeerMethodPolicies_DashboardGetsNothing pins the dashboard to a
// policed-but-empty policy: present so startup validation passes, granting zero
// methods so every request is denied.
func TestCallbackPeerMethodPolicies_DashboardGetsNothing(t *testing.T) {
	policies := callbackPeerMethodPolicies()

	methods, policed := policies[callbackDashboardSVID]
	require.True(t, policed, "the dashboard must be POLICED (present with an empty set), not absent — "+
		"absence would trip validateCallbackPeerPolicies at boot")
	assert.Empty(t, methods, "the dashboard must be granted zero HarnessCallbackService methods")
}

// TestCallbackPeerMethodPolicies_AgentPeersGetTheAgentSurface pins the Envoy and
// daemon-loopback peers to the classified agent surface plus the health probes —
// and NOT to anything outside it.
func TestCallbackPeerMethodPolicies_AgentPeersGetTheAgentSurface(t *testing.T) {
	policies := callbackPeerMethodPolicies()

	for _, svid := range []string{callbackEnvoySVID, callbackDaemonSVID} {
		t.Run(svid, func(t *testing.T) {
			methods, policed := policies[svid]
			require.True(t, policed, "%s must have an explicit method policy", svid)

			assert.True(t, methods[harnesspb.HarnessCallbackService_GetCredential_FullMethodName],
				"GetCredential must remain reachable for the agent-callback peers — the per-secret "+
					"can_resolve Check in the handler is what gates it, not the method policy")
			assert.True(t, methods[healthCheckMethod], "health probes traverse the same mTLS channel")

			assert.False(t, methods[harnesspb.HarnessCallbackService_GetPlanContext_FullMethodName],
				"GetPlanContext has no handler; it must not be granted")
			assert.False(t, methods["/grpc.reflection.v1.ServerReflection/ServerReflectionInfo"],
				"gRPC reflection is a dev-only debug surface and gets no standing grant on a "+
					"SPIFFE-pinned listener")
		})
	}
}

// TestValidateCallbackPeerPolicies_RejectsUnclassifiedPeer is the boot-time
// fail-closed guard: adding an SVID to GIBSON_CALLBACK_PEER_SVIDS without
// classifying it must stop the daemon, not produce a peer that is silently
// denied every call.
func TestValidateCallbackPeerPolicies_RejectsUnclassifiedPeer(t *testing.T) {
	policies := callbackPeerMethodPolicies()

	newPeer := spiffeid.RequireFromString("spiffe://zeroroot.ai/platform/some-new-thing")
	err := validateCallbackPeerPolicies([]spiffeid.ID{newPeer}, policies)
	require.Error(t, err, "an mTLS-allow-listed callback peer with no method policy must refuse to start")
	assert.Contains(t, err.Error(), "some-new-thing", "the error must name the offending peer")
}

// TestValidateCallbackPeerPolicies_AcceptsConfiguredPeers pins the three SVIDs
// the chart actually renders (helm/gibson/values.yaml, values-kind.yaml,
// gitops envs/dev). If this fails, the deployed peer set and this policy have
// drifted and the callback path would be dead on arrival.
func TestValidateCallbackPeerPolicies_AcceptsConfiguredPeers(t *testing.T) {
	configured := []spiffeid.ID{
		spiffeid.RequireFromString(callbackDashboardSVID),
		spiffeid.RequireFromString(callbackEnvoySVID),
		spiffeid.RequireFromString(callbackDaemonSVID),
	}
	require.NoError(t, validateCallbackPeerPolicies(configured, callbackPeerMethodPolicies()))
}

// --- checkCallbackPeerAuthz: the three fail-closed axes ---

func TestCheckCallbackPeerAuthz_UnknownPeerDenied(t *testing.T) {
	logger, _ := newBufferLogger()
	err := checkCallbackPeerAuthz(
		context.Background(),
		"spiffe://zeroroot.ai/platform/some-new-thing", true,
		harnesspb.HarnessCallbackService_GetCredential_FullMethodName,
		callbackPeerMethodPolicies(), logger,
	)
	require.Error(t, err, "REGRESSION (GHSA-cwgm-qw3c-4ph7): a peer SVID with no method policy must be "+
		"DENIED, not defaulted to allowed. Under the old denylist any peer it did not name — including "+
		"one added to GIBSON_CALLBACK_PEER_SVIDS later — got every RPC including GetCredential")
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestCheckCallbackPeerAuthz_UnresolvedSVIDDenied(t *testing.T) {
	logger, _ := newBufferLogger()
	err := checkCallbackPeerAuthz(
		context.Background(),
		"", false,
		harnesspb.HarnessCallbackService_GetCredential_FullMethodName,
		callbackPeerMethodPolicies(), logger,
	)
	require.Error(t, err, "REGRESSION (GHSA-cwgm-qw3c-4ph7): a peer whose SPIFFE ID cannot be resolved "+
		"must be DENIED. The old interceptors skipped the check entirely when peerSPIFFEID returned "+
		"ok=false, so an unidentifiable peer passed straight through to the header-trusting interceptor")
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestCheckCallbackPeerAuthz_KnownPeerDeniedOutsidePolicy(t *testing.T) {
	logger, _ := newBufferLogger()
	err := checkCallbackPeerAuthz(
		context.Background(),
		callbackEnvoySVID, true,
		harnesspb.HarnessCallbackService_GetPlanContext_FullMethodName,
		callbackPeerMethodPolicies(), logger,
	)
	require.Error(t, err, "a KNOWN peer must still be denied a method outside its policy — the old "+
		"denylist had no per-method dimension at all")
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestCheckCallbackPeerAuthz_DashboardDeniedEverything(t *testing.T) {
	logger, _ := newBufferLogger()
	for _, method := range serviceDescMethods() {
		err := checkCallbackPeerAuthz(
			context.Background(), callbackDashboardSVID, true, method,
			callbackPeerMethodPolicies(), logger,
		)
		require.Error(t, err, "the dashboard SVID must be denied %s", method)
		assert.Equal(t, codes.PermissionDenied, status.Code(err))
	}
}

func TestCheckCallbackPeerAuthz_AgentPeerAllowedInPolicy(t *testing.T) {
	logger, _ := newBufferLogger()
	for _, svid := range []string{callbackEnvoySVID, callbackDaemonSVID} {
		err := checkCallbackPeerAuthz(
			context.Background(), svid, true,
			harnesspb.HarnessCallbackService_LLMComplete_FullMethodName,
			callbackPeerMethodPolicies(), logger,
		)
		assert.NoError(t, err, "%s must still reach its classified agent-surface methods — this fix "+
			"must not break the live in-mission callback path", svid)
	}
}
