package daemon

import (
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
