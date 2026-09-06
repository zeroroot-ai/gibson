// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	grpccodes "google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	daemonoperatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
)

// descriptorMethodFQNs enumerates every DaemonOperatorService method's
// fully-qualified gRPC name straight from the generated service descriptor
// (DaemonOperatorService_ServiceDesc). This is the same descriptor grpc-go
// registers handlers from, so it is authoritative: a newly-added RPC appears
// here automatically. The fully-qualified form ("/<service>/<method>") matches
// both the operatorMethodPolicy keys and the info.FullMethod the runtime bypass
// inspects.
func descriptorMethodFQNs() []string {
	desc := daemonoperatorv1.DaemonOperatorService_ServiceDesc
	fqns := make([]string, 0, len(desc.Methods)+len(desc.Streams))
	for _, m := range desc.Methods {
		fqns = append(fqns, "/"+desc.ServiceName+"/"+m.MethodName)
	}
	for _, s := range desc.Streams {
		fqns = append(fqns, "/"+desc.ServiceName+"/"+s.StreamName)
	}
	return fqns
}

// TestOperatorMethodPolicy_ClassifiesEveryDescriptorMethod is the core guard:
// it derives the method set from the generated service descriptor and asserts
// operatorMethodPolicy classifies EXACTLY that set — every descriptor method is
// classified once (allowed XOR denied), and no policy entry refers to a method
// that no longer exists on the descriptor.
//
// Adding a new DaemonOperatorService RPC without classifying it here FAILS this
// test, killing the recurring omission bug (gibson#621/#949/#1043) and its
// inverse (a stale grant for a removed method). Each classification also
// carries a non-empty reason so the policy stays an auditable allow/deny table.
func TestOperatorMethodPolicy_ClassifiesEveryDescriptorMethod(t *testing.T) {
	// Both direct-dial peers carry a full classification table; the guard
	// runs over each so a new RPC cannot slip past either (gibson#1566 added
	// the connector-operator as the second policed peer).
	for name, policy := range map[string]map[string]operatorMethodDecision{
		"operatorMethodPolicy":          operatorMethodPolicy,
		"connectorOperatorMethodPolicy": connectorOperatorMethodPolicy,
	} {
		t.Run(name, func(t *testing.T) {
			assertPolicyClassifiesDescriptor(t, name, policy)
		})
	}
}

// assertPolicyClassifiesDescriptor is the descriptor-driven guard for one
// policy table: every DaemonOperatorService method is classified with a
// reason, and no stale entry names a method the descriptor no longer has.
func assertPolicyClassifiesDescriptor(t *testing.T, name string, policy map[string]operatorMethodDecision) {
	t.Helper()
	descriptorMethods := descriptorMethodFQNs()
	require.NotEmpty(t, descriptorMethods, "service descriptor must expose at least one method")

	descriptorSet := make(map[string]bool, len(descriptorMethods))
	for _, fqn := range descriptorMethods {
		descriptorSet[fqn] = true
	}

	// Every descriptor method must be classified.
	for _, fqn := range descriptorMethods {
		decision, classified := policy[fqn]
		assert.Truef(t, classified,
			"DaemonOperatorService method %q is not classified in %s; "+
				"add an allowed or denied entry with a reason", fqn, name)
		if classified {
			assert.NotEmptyf(t, decision.reason,
				"classification for %q must carry a reason", fqn)
		}
	}

	// No policy entry may reference a method absent from the descriptor (stale grant).
	for fqn := range policy {
		assert.Truef(t, descriptorSet[fqn],
			"%s classifies %q which is not on the DaemonOperatorService "+
				"descriptor; remove the stale entry", name, fqn)
	}

	// allowed XOR denied is structural (a method is one map entry with a bool),
	// but assert the partition is exhaustive over the descriptor.
	assert.Len(t, policy, len(descriptorSet),
		"%s must classify exactly the descriptor's method set", name)
}

// TestConnectorOperatorMethodPolicy_AllowedSetIsExactlyTheFinalizerRPC pins the
// connector-operator's grant to the one RPC its ConnectorInstance finalizer
// dials (ADR-0015 §5). A surplus grant is an over-grant; a missing one wedges
// every connector delete behind a PermissionDenied.
func TestConnectorOperatorMethodPolicy_AllowedSetIsExactlyTheFinalizerRPC(t *testing.T) {
	got := make([]string, 0, 1)
	for method := range connectorOperatorAllowedMethods() {
		got = append(got, method)
	}
	assert.ElementsMatch(t,
		[]string{daemonoperatorv1.DaemonOperatorService_RevokeConnectorGrant_FullMethodName}, got,
		"connector-operator may call exactly RevokeConnectorGrant")
	assert.False(t, operatorAllowedMethods()[daemonoperatorv1.DaemonOperatorService_RevokeConnectorGrant_FullMethodName],
		"the tenant-operator must not inherit the connector-operator's finalizer RPC")
}

// TestOperatorMethodPolicy_AllowedSetEqualsActualCallSet is the least-privilege
// reconciliation: the operator-allowed set must equal EXACTLY the set of RPCs
// the tenant-operator actually dials. It fails on BOTH a missing grant (the
// recurring provisioning-breaking bug) and a surplus grant (a standing
// over-grant such as the UpsertTenantQuota / EmitAuditEvent ones removed here).
//
// operatorActualCallSet is a curated, human-maintained list. When the operator
// starts (or stops) calling an RPC, update this list AND the allowed/denied
// classification in operatorMethodPolicy together — this test is the tripwire
// that forces both edits.
func TestOperatorMethodPolicy_AllowedSetEqualsActualCallSet(t *testing.T) {
	// The 10 DaemonOperatorService RPCs the tenant-operator (operators/tenant)
	// actually calls over the SPIFFE direct-dial path. UpsertTenantQuota and
	// EmitAuditEvent are deliberately ABSENT: no caller is wired, so granting
	// them would be an over-grant (least privilege).
	operatorActualCallSet := []string{
		daemonoperatorv1.DaemonOperatorService_WriteAccessTuples_FullMethodName,
		daemonoperatorv1.DaemonOperatorService_ListFeatureTuples_FullMethodName,
		daemonoperatorv1.DaemonOperatorService_SeedCatalogTenantEnabled_FullMethodName,
		daemonoperatorv1.DaemonOperatorService_SetTenantZitadelOrg_FullMethodName,
		daemonoperatorv1.DaemonOperatorService_ListPendingTenantProvisioning_FullMethodName,
		daemonoperatorv1.DaemonOperatorService_EnqueueTenantProvisioning_FullMethodName,
		daemonoperatorv1.DaemonOperatorService_AckTenantProvisioned_FullMethodName,
		daemonoperatorv1.DaemonOperatorService_ReportTenantStatus_FullMethodName,
		daemonoperatorv1.DaemonOperatorService_ListPendingTenantOps_FullMethodName,
		daemonoperatorv1.DaemonOperatorService_AckTenantOp_FullMethodName,
	}

	want := append([]string(nil), operatorActualCallSet...)
	sort.Strings(want)

	got := make([]string, 0, len(operatorActualCallSet))
	for method := range operatorAllowedMethods() {
		got = append(got, method)
	}
	sort.Strings(got)

	// ElementsMatch reports both the missing and the surplus members, so a
	// failure pinpoints whether a grant is absent or over-broad.
	assert.ElementsMatch(t, want, got,
		"operator-allowed set must equal the operator's actual call set exactly "+
			"(missing grant => provisioning breaks; surplus grant => over-grant)")
}

// allowedMethod returns one FQN the tenant-operator is allowed to call, for use
// in the bypass tests below.
func allowedMethod() string {
	return daemonoperatorv1.DaemonOperatorService_WriteAccessTuples_FullMethodName
}

// deniedMethod returns one operator-DENIED DaemonOperatorService FQN (no caller
// wired), for use in the bypass tests below.
func deniedMethod() string {
	return daemonoperatorv1.DaemonOperatorService_UpsertTenantQuota_FullMethodName
}

// TestSpiffePeerMethodPolicies_OnlyOperatorsArePoliced asserts the policed
// peer set is exactly the two operators: EnvoyID and any browser-path SVID
// are deliberately absent (they transit Envoy + ext-authz, never this bypass).
func TestSpiffePeerMethodPolicies_OnlyOperatorsArePoliced(t *testing.T) {
	policies := spiffePeerMethodPolicies()

	// In a PRODUCTION build exactly two peers are policed. A test_fixtures
	// build adds the exit-test runner and nothing else — that identity does not
	// exist in the production binary at all (e2e_peer_policy_stub.go), which is
	// what keeps this invariant meaningful where it matters. Assert the exact
	// membership rather than only the count, so a future extra peer in either
	// build has to be added here deliberately.
	want := []string{tenantOperatorSVID, connectorOperatorSVID}
	if isTestFixturesBuild {
		want = append(want, "spiffe://zeroroot.ai/platform/e2e-runner")
	}
	got := make([]string, 0, len(policies))
	for id := range policies {
		got = append(got, id)
	}
	sort.Strings(want)
	sort.Strings(got)
	require.Equal(t, want, got, "the policed direct-dial peers are a closed set")
	methods, ok := policies[tenantOperatorSVID]
	require.True(t, ok, "tenant-operator must have an explicit method policy")
	assert.True(t, methods[allowedMethod()], "tenant-operator policy must permit its allowed methods")
	assert.False(t, methods[deniedMethod()], "tenant-operator policy must not permit operator-denied methods")

	revoke := daemonoperatorv1.DaemonOperatorService_RevokeConnectorGrant_FullMethodName
	connMethods, ok := policies[connectorOperatorSVID]
	require.True(t, ok, "connector-operator must have an explicit method policy")
	assert.True(t, connMethods[revoke], "connector-operator policy must permit RevokeConnectorGrant")
	assert.False(t, connMethods[allowedMethod()], "connector-operator policy must not permit tenant-operator methods")
	assert.False(t, methods[revoke], "tenant-operator policy must not permit RevokeConnectorGrant")
}

// TestValidateAllowedPeerPolicies covers the fail-loud-at-startup contract
// (gibson#1052): a configured AllowedPeerIDs entry with no method policy makes
// the daemon refuse to start, while a policed peer (tenant-operator) and an
// empty list pass.
func TestValidateAllowedPeerPolicies(t *testing.T) {
	policies := spiffePeerMethodPolicies()

	t.Run("empty allow-list passes", func(t *testing.T) {
		assert.NoError(t, validateAllowedPeerPolicies(nil, policies))
		assert.NoError(t, validateAllowedPeerPolicies([]string{}, policies))
	})

	t.Run("policed tenant-operator passes", func(t *testing.T) {
		assert.NoError(t, validateAllowedPeerPolicies([]string{tenantOperatorSVID}, policies))
	})

	t.Run("unpoliced peer fails loud", func(t *testing.T) {
		err := validateAllowedPeerPolicies(
			[]string{"spiffe://zeroroot.ai/platform/dashboard"}, policies)
		require.Error(t, err, "an allowed peer with no method policy must fail startup")
		assert.Contains(t, err.Error(), "spiffe://zeroroot.ai/platform/dashboard")
		assert.Contains(t, err.Error(), "gibson#1052")
	})

	t.Run("policed + unpoliced mix fails and names the unpoliced peer", func(t *testing.T) {
		err := validateAllowedPeerPolicies(
			[]string{tenantOperatorSVID, "spiffe://zeroroot.ai/platform/daemon"}, policies)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "spiffe://zeroroot.ai/platform/daemon")
		assert.NotContains(t, err.Error(), tenantOperatorSVID,
			"only the unpoliced peer should be reported")
	})
}

// TestSpiffeBypassDecision covers the fail-closed request-time contract
// (gibson#1052 + #245):
//   - an unpoliced allowed peer is DENIED (not granted);
//   - the tenant-operator is allowed only for its classified methods;
//   - a non-allow-listed SVID (EnvoyID / browser path) falls through to the
//     ext-authz header path (matched=false, no error).
func TestSpiffeBypassDecision(t *testing.T) {
	policies := spiffePeerMethodPolicies()
	allowed := []string{tenantOperatorSVID}

	t.Run("tenant-operator allowed method is authorised", func(t *testing.T) {
		ok, err := spiffeBypassDecision(tenantOperatorSVID, allowedMethod(), allowed, policies)
		require.NoError(t, err)
		assert.True(t, ok, "policed peer calling an allowed method must be authorised")
	})

	t.Run("tenant-operator denied method is PermissionDenied", func(t *testing.T) {
		ok, err := spiffeBypassDecision(tenantOperatorSVID, deniedMethod(), allowed, policies)
		assert.False(t, ok)
		require.Error(t, err)
		assert.Equal(t, grpccodes.PermissionDenied, grpcstatus.Code(err))
	})

	t.Run("tenant-operator unknown method is PermissionDenied", func(t *testing.T) {
		ok, err := spiffeBypassDecision(tenantOperatorSVID,
			"/gibson.daemon.operator.v1.DaemonOperatorService/NoSuchMethod", allowed, policies)
		assert.False(t, ok)
		require.Error(t, err)
		assert.Equal(t, grpccodes.PermissionDenied, grpcstatus.Code(err))
	})

	t.Run("allow-listed peer with no method policy is DENIED (fail-closed)", func(t *testing.T) {
		unpoliced := "spiffe://zeroroot.ai/platform/dashboard"
		// The peer is allow-listed at the TLS layer but has NO method policy —
		// the gibson#1052 fail-open gap. It must be denied, not granted.
		ok, err := spiffeBypassDecision(unpoliced, allowedMethod(),
			[]string{tenantOperatorSVID, unpoliced}, policies)
		assert.False(t, ok, "an unpoliced allowed peer must NOT be granted bypass access")
		require.Error(t, err, "an unpoliced allowed peer must be denied")
		assert.Equal(t, grpccodes.PermissionDenied, grpcstatus.Code(err))
		assert.Contains(t, grpcstatus.Convert(err).Message(), "gibson#1052")
	})

	t.Run("non-allow-listed SVID falls through to ext-authz path", func(t *testing.T) {
		// EnvoyID is never in AllowedPeerIDs — it must fall through, not deny.
		ok, err := spiffeBypassDecision("spiffe://zeroroot.ai/platform/envoy",
			allowedMethod(), allowed, policies)
		assert.False(t, ok, "a non-allow-listed peer is not bypassed")
		assert.NoError(t, err, "a non-allow-listed peer must fall through, NOT be denied")
	})
}
