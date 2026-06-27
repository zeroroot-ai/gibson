package daemon

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
	descriptorMethods := descriptorMethodFQNs()
	require.NotEmpty(t, descriptorMethods, "service descriptor must expose at least one method")

	descriptorSet := make(map[string]bool, len(descriptorMethods))
	for _, fqn := range descriptorMethods {
		descriptorSet[fqn] = true
	}

	// Every descriptor method must be classified.
	for _, fqn := range descriptorMethods {
		decision, classified := operatorMethodPolicy[fqn]
		assert.Truef(t, classified,
			"DaemonOperatorService method %q is not classified in operatorMethodPolicy; "+
				"add an operator-allowed or operator-denied entry with a reason", fqn)
		if classified {
			assert.NotEmptyf(t, decision.reason,
				"classification for %q must carry a reason", fqn)
		}
	}

	// No policy entry may reference a method absent from the descriptor (stale grant).
	for fqn := range operatorMethodPolicy {
		assert.Truef(t, descriptorSet[fqn],
			"operatorMethodPolicy classifies %q which is not on the DaemonOperatorService "+
				"descriptor; remove the stale entry", fqn)
	}

	// allowed XOR denied is structural (a method is one map entry with a bool),
	// but assert the partition is exhaustive over the descriptor.
	assert.Len(t, operatorMethodPolicy, len(descriptorSet),
		"operatorMethodPolicy must classify exactly the descriptor's method set")
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
	// The 9 DaemonOperatorService RPCs the tenant-operator (operators/tenant)
	// actually calls over the SPIFFE direct-dial path. UpsertTenantQuota and
	// EmitAuditEvent are deliberately ABSENT: no caller is wired, so granting
	// them would be an over-grant (least privilege).
	operatorActualCallSet := []string{
		daemonoperatorv1.DaemonOperatorService_WriteAccessTuples_FullMethodName,
		daemonoperatorv1.DaemonOperatorService_ListFeatureTuples_FullMethodName,
		daemonoperatorv1.DaemonOperatorService_SeedCatalogTenantEnabled_FullMethodName,
		daemonoperatorv1.DaemonOperatorService_SetTenantZitadelOrg_FullMethodName,
		daemonoperatorv1.DaemonOperatorService_ListPendingTenantProvisioning_FullMethodName,
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
