// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package capabilitygrant

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
)

// ClientCapabilityGrants is the single kind->grant policy table (ADR-0046): the
// capability tuples written at enrollment beyond the base identity tuples
// (owner / belongs_to / member), keyed by FGA principal type.
//
//   - agent_principal, tool_principal — clients/invokers (ADR-0045: an agent or
//     tool is "server AND client"). Granted direct_execute on the system
//     backplane (component:_system) so their CG-JWT authorizes the
//     COMPONENT-identity client RPCs (RunMission, CallTool, the
//     mission-management surface).
//   - plugin_principal — invoked-only for DRIVING the platform (it never calls
//     RunMission/CallTool), but it still RECEIVES its dispatched work by polling
//     the backplane (PollWork/SubmitResult). Those receive RPCs are gated on
//     can_poll_work, so a plugin is granted direct_receive_work on
//     component:_system — which satisfies can_poll_work WITHOUT granting
//     can_execute, so a plugin can receive work but cannot drive the platform
//     (ADR-0066). Before ADR-0066 a plugin got no client grant and its first
//     PollWork failed authz.
//
// This is the one auditable place that answers "what does each kind get at
// enrollment." Both the human enrollment path (daemon/api CreateAgentIdentity)
// and the SPIFFE-SVID path (ProvisionPluginPrincipal) call it, so the two never
// drift. Tool/plugin principals are valid grantees for these relations as of the
// symmetric model (gibson#659).
func ClientCapabilityGrants(principalID, fgaType string) []authz.Tuple {
	switch fgaType {
	case "agent_principal", "tool_principal":
		return []authz.Tuple{
			{User: principalID, Relation: "direct_execute", Object: "component:_system"},
		}
	case "plugin_principal":
		return []authz.Tuple{
			{User: principalID, Relation: "direct_receive_work", Object: "component:_system"},
		}
	default:
		return nil
	}
}

// PluginPrincipalKind is the FGA principal type a first-party plugin enrols as.
const PluginPrincipalKind = "plugin_principal"

// ProvisionPluginPrincipal idempotently writes the FGA identity of a first-party
// plugin that authenticated with a SPIFFE JWT-SVID (ADR-0066), and returns the
// deterministic principal reference (plugin_principal:<vendor>) and the resolved
// owner user id.
//
// vendor is the plugin name parsed from the verified SVID's SPIFFE ID; tenantID
// is the install tenant the first-party plugin binds to (the model has no
// tenant-less principal). The owner is resolved from the tenant, not supplied —
// see the dynamic-resolution note below.
//
// The tuples are exactly the ones CreateAgentIdentity writes for a human-enrolled
// principal — owner, tenant belongs_to, tenant membership — plus the plugin's
// client grant from ClientCapabilityGrants (direct_receive_work: receive work,
// not drive). FGA Write is idempotent, so a restart re-presenting a fresh SVID
// re-writes the same tuples with no effect.
//
// A first-party plugin has no Zitadel machine user: under ADR-0045 a component
// authenticates to the daemon with a capability-grant JWT, never a Zitadel token,
// so FGA is the sole authority for its tenancy and permissions and the principal
// is a deterministic FGA subject rather than one keyed to a service account.
func (s *CapabilityGrantService) ProvisionPluginPrincipal(ctx context.Context, vendor, tenantID string) (principalRef, ownerUserID string, err error) {
	vendor = strings.TrimSpace(vendor)
	if vendor == "" {
		return "", "", errors.New("capabilitygrant: ProvisionPluginPrincipal: empty plugin vendor")
	}
	if tenantID == "" {
		return "", "", errors.New("capabilitygrant: ProvisionPluginPrincipal: install tenant is required (set GIBSON_PLATFORM_TENANT)")
	}
	if s.authorizer == nil {
		return "", "", errors.New("capabilitygrant: ProvisionPluginPrincipal: authorizer is required")
	}

	// Resolve the install tenant's owner DYNAMICALLY at enrol time (ADR-0066).
	// The owner is minted by first-admin DURING install and cannot be known
	// before the daemon starts, so it is looked up here rather than pre-set from
	// a static env — that avoids a bootstrap chicken-and-egg and a fragile
	// two-phase "install then re-configure the daemon" deploy. A plugin enrols
	// after the platform is up, so the owner tuple exists by then; if the enrol
	// raced first-admin, the error propagates and the plugin retries on backoff.
	ownerUserID, err = s.resolveTenantOwner(ctx, tenantID)
	if err != nil {
		return "", "", err
	}

	principalRef = PluginPrincipalKind + ":" + vendor
	tuples := []authz.Tuple{
		{User: "user:" + ownerUserID, Relation: "owner", Object: principalRef},
		{User: "tenant:" + tenantID, Relation: "belongs_to", Object: principalRef},
		{User: principalRef, Relation: "member", Object: "tenant:" + tenantID},
	}
	tuples = append(tuples, ClientCapabilityGrants(principalRef, PluginPrincipalKind)...)
	if err := s.authorizer.Write(ctx, tuples); err != nil {
		return "", "", fmt.Errorf("capabilitygrant: ProvisionPluginPrincipal: provision %q: %w", principalRef, err)
	}
	return principalRef, ownerUserID, nil
}

// resolveTenantOwner returns the bare user id (no "user:" prefix) that owns the
// given tenant, from the FGA store. Zero owners is a RETRYABLE error — the owner
// is simply not provisioned yet (enrol raced first-admin). More than one owner
// resolves to the lexicographically-first, logged, so the choice is stable
// across a plugin's re-enrolments rather than depending on FGA's result order.
func (s *CapabilityGrantService) resolveTenantOwner(ctx context.Context, tenantID string) (string, error) {
	owners, err := s.authorizer.ListUsers(ctx, "tenant", "tenant:"+tenantID, "owner")
	if err != nil {
		return "", fmt.Errorf("capabilitygrant: resolve owner of tenant %q: %w", tenantID, err)
	}
	ids := make([]string, 0, len(owners))
	for _, o := range owners {
		ids = append(ids, strings.TrimPrefix(o, "user:"))
	}
	sort.Strings(ids)
	switch len(ids) {
	case 0:
		return "", fmt.Errorf("capabilitygrant: install tenant %q has no owner yet "+
			"(first-admin has not provisioned it); the plugin will retry", tenantID)
	case 1:
		return ids[0], nil
	default:
		s.logger.WarnContext(ctx, "capabilitygrant: install tenant has multiple owners; using the first deterministically",
			slog.String("tenant_id", tenantID),
			slog.Int("owner_count", len(ids)),
			slog.String("chosen", ids[0]),
		)
		return ids[0], nil
	}
}
