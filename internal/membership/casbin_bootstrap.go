package membership

import (
	"fmt"
	"log/slog"

	"github.com/casbin/casbin/v2"
)

// BootstrapTenantRoles creates the role hierarchy and base policies for a tenant.
//
// The four built-in roles form a linear inheritance chain:
//
//	owner → admin → operator → viewer
//
// Each role is assigned only the policies that it ADDS to the role below it.
// Permissions cascade automatically through Casbin's domain-scoped group
// inheritance so there is no duplication of viewer/operator grants at higher levels.
//
// Role summary:
//   - viewer:   read-only access to missions, findings, graphrag, and memory
//   - operator: adds mission execution, tool/agent use, LLM access, and memory writes
//   - admin:    adds team and component management, API key management, settings,
//               and write access to findings and graphrag
//   - owner:    adds billing, tenant deletion, and ownership transfer
//
// Idempotent — safe to call multiple times. AddPolicy and AddGroupingPolicy both
// return (false, nil) when the rule already exists, so duplicate calls are ignored.
func BootstrapTenantRoles(enforcer *casbin.Enforcer, tenantID string) error {
	if enforcer == nil {
		return nil
	}

	if tenantID == "" {
		return fmt.Errorf("membership: BootstrapTenantRoles requires a non-empty tenantID")
	}

	// Role hierarchy: owner inherits admin, admin inherits operator, operator inherits viewer.
	// These are domain-scoped (third field = tenantID) so they do not bleed across tenants.
	hierarchy := [][3]string{
		{"owner", "admin", tenantID},
		{"admin", "operator", tenantID},
		{"operator", "viewer", tenantID},
	}

	for _, g := range hierarchy {
		if _, err := enforcer.AddGroupingPolicy(g[0], g[1], g[2]); err != nil {
			slog.Warn("casbin: failed to add role hierarchy",
				"from", g[0],
				"to", g[1],
				"tenant", tenantID,
				"error", err,
			)
		}
	}

	// Base policies: only the ADDITIONS each role contributes beyond what it inherits.

	// viewer — base level: read-only access.
	viewerPolicies := [][4]string{
		{"viewer", tenantID, "missions", "read"},
		{"viewer", tenantID, "findings", "read"},
		{"viewer", tenantID, "graphrag", "read"},
		{"viewer", tenantID, "memory", "read"},
	}

	// operator — adds execution, tooling, LLM access, and memory writes.
	operatorPolicies := [][4]string{
		{"operator", tenantID, "missions", "execute"},
		{"operator", tenantID, "findings", "export"},
		{"operator", tenantID, "memory", "write"},
		{"operator", tenantID, "llm", "complete"},
		{"operator", tenantID, "tools", "execute"},
		{"operator", tenantID, "agents", "delegate"},
	}

	// admin — adds team/component management and write access to findings and graphrag.
	adminPolicies := [][4]string{
		{"admin", tenantID, "team", "manage"},
		{"admin", tenantID, "components", "manage"},
		{"admin", tenantID, "apikeys", "manage"},
		{"admin", tenantID, "settings", "manage"},
		{"admin", tenantID, "findings", "write"},
		{"admin", tenantID, "graphrag", "write"},
	}

	// owner — adds billing, tenant lifecycle, and ownership transfer.
	ownerPolicies := [][4]string{
		{"owner", tenantID, "billing", "*"},
		{"owner", tenantID, "tenant", "delete"},
		{"owner", tenantID, "ownership", "transfer"},
	}

	allPolicies := make([][4]string, 0,
		len(viewerPolicies)+len(operatorPolicies)+len(adminPolicies)+len(ownerPolicies),
	)
	allPolicies = append(allPolicies, viewerPolicies...)
	allPolicies = append(allPolicies, operatorPolicies...)
	allPolicies = append(allPolicies, adminPolicies...)
	allPolicies = append(allPolicies, ownerPolicies...)

	for _, p := range allPolicies {
		if _, err := enforcer.AddPolicy(p[0], p[1], p[2], p[3]); err != nil {
			slog.Warn("casbin: failed to add policy",
				"role", p[0],
				"tenant", p[1],
				"resource", p[2],
				"action", p[3],
				"error", err,
			)
		}
	}

	slog.Info("casbin: tenant role hierarchy bootstrapped", "tenant", tenantID)

	return nil
}
