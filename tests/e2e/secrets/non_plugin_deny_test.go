// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"testing"
	"time"

	agentidentityv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/agentidentity/v1"
	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
)

// TestNonPluginDeny is the evidence for non-plugin-secret-isolation
// Requirement 6 on a live cluster. An agent and a tool check in at the edge
// and ask for a secret of their own tenant. ext-authz refuses both with
// PermissionDenied: the FGA model gives agent_principal and tool_principal no
// relation to a secret at all. A plugin that no tenant admin bound to the
// secret is refused as well: can_resolve is a grant for one secret, never a
// property of the kind.
func TestNonPluginDeny(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	v := requireVenue(ctx, t)

	id := runID()
	secret := v.seedSecret(t, "npi-deny-"+id)

	for _, p := range []struct {
		kind  agentidentityv1.PrincipalKind
		label string
	}{
		{agentidentityv1.PrincipalKind_PRINCIPAL_KIND_AGENT, "agent"},
		{agentidentityv1.PrincipalKind_PRINCIPAL_KIND_TOOL, "tool"},
		{agentidentityv1.PrincipalKind_PRINCIPAL_KIND_PLUGIN, "unbound-plugin"},
	} {
		t.Run(p.label, func(t *testing.T) {
			c := v.provision(ctx, t, p.kind, fmt.Sprintf("npi-%s-%s", p.label, id))
			requirePermissionDenied(t, fmt.Sprintf("ComponentService.GetCredential(%s) as %s", secret, p.label), func() error {
				_, err := c.credentials.GetCredential(ctx, &componentpb.GetCredentialRequest{Name: secret})
				return err //nolint:wrapcheck // the status error is the assertion subject
			})
		})
	}
}
