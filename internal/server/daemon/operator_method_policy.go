package daemon

import (
	"fmt"
	"sort"
	"strings"

	grpccodes "google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	daemonoperatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
)

// tenantOperatorSVID is the only SPIFFE workload identity permitted to use the
// daemon's control-plane direct-dial bypass (ADR-0002). After gibson#1049 the
// DaemonOperatorService is single-consumer: the tenant-operator. Every other
// peer (browser path) must transit Envoy + ext-authz and carry the
// ext-authz-shaped headers.
const tenantOperatorSVID = "spiffe://zeroroot.ai/platform/tenant-operator"

// operatorMethodDecision classifies a single DaemonOperatorService method for
// the tenant-operator's SPIFFE direct-dial bypass. Exactly one of the two
// states applies to each method:
//
//   - allowed == true  → the tenant-operator legitimately calls this RPC; the
//     SPIFFE bypass authorises it.
//   - allowed == false → operator-denied (least privilege). A direct-dial call
//     to this method returns PermissionDenied. reason documents WHY it is
//     denied (today: no caller is wired, so the grant would be a standing
//     over-grant).
//
// reason is required for both states so the policy reads as an auditable
// allow/deny table.
type operatorMethodDecision struct {
	allowed bool
	reason  string
}

// operatorMethodPolicy is the SINGLE SOURCE OF TRUTH classifying EVERY
// DaemonOperatorService method as operator-allowed XOR operator-denied. It
// replaces the hand-edited inline allowlist literal that silently drifted
// behind the RPC surface three times (gibson#621/#949/#1043) — each omission
// denied the operator a method it actually called, breaking tenant
// provisioning (the founding TenantMember was never written and the user was
// stuck "no access to workspace").
//
// Two tests in operator_method_policy_test.go keep this honest:
//
//  1. A descriptor-driven GUARD test enumerates the methods from the generated
//     DaemonOperatorService_ServiceDesc and fails if ANY method is missing from
//     this map (or is classified more than once). Adding a new RPC without
//     classifying it here therefore FAILS CI — killing the recurring omission
//     bug and its inverse ("just allow the operator everything").
//
//  2. A RECONCILIATION test pins the operator-allowed set to exactly the
//     operator's actual call set (the 9 RPCs it dials). It fails on BOTH a
//     missing grant (the recurring bug) and a surplus grant (an over-grant),
//     enforcing least privilege.
//
// The runtime SPIFFE bypass (internal/server/daemon/grpc.go) derives its
// per-peer allowlist from operatorAllowedMethods(), so enforcement and policy
// can never disagree.
//
// Keys are the fully-qualified gRPC method names (the constants generated
// alongside the service), which are exactly what the bypass matches against the
// inbound info.FullMethod.
var operatorMethodPolicy = map[string]operatorMethodDecision{
	// --- operator-allowed: the 9 RPCs the tenant-operator actually calls ---
	daemonoperatorv1.DaemonOperatorService_WriteAccessTuples_FullMethodName: {
		allowed: true,
		reason:  "operator writes the founding-owner + role FGA tuples during provisioning",
	},
	daemonoperatorv1.DaemonOperatorService_ListFeatureTuples_FullMethodName: {
		allowed: true,
		reason:  "operator reads feature tuples while reconciling tenant entitlements",
	},
	daemonoperatorv1.DaemonOperatorService_SeedCatalogTenantEnabled_FullMethodName: {
		allowed: true,
		reason:  "operator seeds catalog-tenant-enabled rows during provisioning",
	},
	daemonoperatorv1.DaemonOperatorService_SetTenantZitadelOrg_FullMethodName: {
		allowed: true,
		reason:  "operator records the tenant->Zitadel-org mapping in the Entitlements saga step (gibson#621)",
	},
	daemonoperatorv1.DaemonOperatorService_ListPendingTenantProvisioning_FullMethodName: {
		allowed: true,
		reason:  "operator-pull provisioning loop drains pending tenants (gibson#949)",
	},
	daemonoperatorv1.DaemonOperatorService_AckTenantProvisioned_FullMethodName: {
		allowed: true,
		reason:  "operator acks each pulled tenant once provisioned (gibson#949)",
	},
	daemonoperatorv1.DaemonOperatorService_ReportTenantStatus_FullMethodName: {
		allowed: true,
		reason:  "operator reports tenant status back to the daemon (gibson#948/dashboard#813)",
	},
	daemonoperatorv1.DaemonOperatorService_ListPendingTenantOps_FullMethodName: {
		allowed: true,
		reason:  "operator drains the tenant_admin_ops queue (migration 018)",
	},
	daemonoperatorv1.DaemonOperatorService_AckTenantOp_FullMethodName: {
		allowed: true,
		reason:  "operator acks each drained tenant_admin_ops entry (migration 018)",
	},

	// --- operator-denied: least privilege, no caller wired ---
	daemonoperatorv1.DaemonOperatorService_UpsertTenantQuota_FullMethodName: {
		allowed: false,
		reason:  "no current caller; re-add when wired",
	},
	daemonoperatorv1.DaemonOperatorService_EmitAuditEvent_FullMethodName: {
		allowed: false,
		reason:  "no current caller; re-add when wired",
	},
}

// operatorAllowedMethods returns the set of fully-qualified DaemonOperatorService
// method names the tenant-operator is authorised to call over the SPIFFE
// direct-dial bypass, derived from operatorMethodPolicy. The runtime bypass in
// grpc.go consumes this so its enforcement always tracks the classified policy.
func operatorAllowedMethods() map[string]bool {
	allowed := make(map[string]bool, len(operatorMethodPolicy))
	for method, decision := range operatorMethodPolicy {
		if decision.allowed {
			allowed[method] = true
		}
	}
	return allowed
}

// spiffePeerMethodPolicies returns the per-SVID method allowlist for every
// SPIFFE peer permitted to use the daemon's control-plane direct-dial bypass
// (ADR-0002). A peer in AllowedPeerIDs that is NOT a key here has NO method
// policy and is therefore DENIED at request time AND rejected at startup
// (fail-closed, gibson#1052): there is no implicit "allow all" fall-through.
//
// Today the tenant-operator is the sole policed peer. EnvoyID is deliberately
// absent: browser-path traffic transits Envoy + ext-authz and never uses this
// bypass, so it must never appear here or in AllowedPeerIDs. A new direct-dial
// peer must be given an explicit method policy here before it can be added to
// AllowedPeerIDs.
func spiffePeerMethodPolicies() map[string]map[string]bool {
	return map[string]map[string]bool{
		tenantOperatorSVID: operatorAllowedMethods(),
	}
}

// validateAllowedPeerPolicies enforces — at daemon startup — that every
// configured SPIFFE direct-dial peer (AllowedPeerIDs) has an explicit method
// policy in policies. The daemon fails loud (returns an error) otherwise, in
// keeping with its fail-loud-on-missing-dependency convention.
//
// Before gibson#1052 an allow-listed peer with no method policy fell through to
// UNRESTRICTED method access (fail-open). This validation closes that gap at
// boot: a misconfigured AllowedPeerIDs entry can never reach the request path.
// Callers that legitimately need direct-dial access must be given an explicit
// policy in spiffePeerMethodPolicies; callers that must transit Envoy +
// ext-authz (e.g. the dashboard) must NOT be listed in AllowedPeerIDs.
func validateAllowedPeerPolicies(allowedPeerIDs []string, policies map[string]map[string]bool) error {
	var unpoliced []string
	for _, peer := range allowedPeerIDs {
		if _, ok := policies[peer]; !ok {
			unpoliced = append(unpoliced, peer)
		}
	}
	if len(unpoliced) == 0 {
		return nil
	}
	sort.Strings(unpoliced)
	return fmt.Errorf(
		"SPIFFE mTLS: AllowedPeerIDs entries %q have no method policy; "+
			"an allow-listed direct-dial peer with no policy would otherwise get "+
			"unrestricted daemon method access (fail-open, gibson#1052). "+
			"Give each peer an explicit method policy in spiffePeerMethodPolicies, "+
			"or remove it from AllowedPeerIDs if it must transit Envoy + ext-authz "+
			"(e.g. the dashboard). The daemon refuses to start fail-open.",
		strings.Join(unpoliced, ", "))
}

// spiffeBypassDecision is the fail-closed authorization decision for a SPIFFE
// direct-dial peer (identified by svid) calling method. It is the single
// source of truth the runtime bypass in grpc.go consumes, extracted as a pure
// function so the fail-closed semantics are unit-testable without TLS plumbing.
//
// Returns:
//   - (false, nil): svid is not an allow-listed direct-dial peer (e.g. EnvoyID
//     or any browser-path SVID). The caller falls through to the standard
//     ext-authz header path; this is NOT an error.
//   - (true, nil): svid is allow-listed AND has an explicit method policy that
//     permits method. The caller synthesises the peer identity and serves.
//   - (false, PermissionDenied): svid is allow-listed but either has NO method
//     policy (the gibson#1052 fail-open gap, now denied) or its policy does not
//     list method (#245 least-privilege).
func spiffeBypassDecision(svid, method string, allowedPeerIDs []string, policies map[string]map[string]bool) (bool, error) {
	allowListed := false
	for _, peer := range allowedPeerIDs {
		if svid == peer {
			allowListed = true
			break
		}
	}
	if !allowListed {
		// Not a direct-dial peer — fall through to the ext-authz header path.
		return false, nil
	}
	methods, policed := policies[svid]
	if !policed {
		// Allow-listed at the TLS layer but no method policy: deny rather than
		// fall through to unrestricted access (fail-closed, gibson#1052).
		// Startup validation already rejects this configuration; this branch is
		// defense-in-depth.
		return false, grpcstatus.Errorf(grpccodes.PermissionDenied,
			"SPIFFE peer %q is mTLS-allow-listed but has no method policy; "+
				"direct-dial denied (fail-closed, gibson#1052)", svid)
	}
	if !methods[method] {
		return false, grpcstatus.Errorf(grpccodes.PermissionDenied,
			"SPIFFE peer %q is not authorised to call %q", svid, method)
	}
	return true, nil
}
