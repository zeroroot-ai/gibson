// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package authz

import "testing"

// The connector grant — a refresh token, a client id, and the human who
// authorized them — is platform-only (ADR-0064). No component may resolve it.
//
// That is not enforced by anyone remembering not to write a tuple. It is
// structural: `secret.can_resolve` admits ONLY `plugin_principal`, so an
// agent, a tool or a user cannot hold it whatever tuples exist, and a secret
// with no plugin_principal tuple is unresolvable by everything.
//
// This test exists because the property is easy to erode by widening one type
// list in model.fga for an unrelated reason. If that happens, the failure
// should surface here — naming the connector grant — rather than as a
// third-party vendor MCP server quietly gaining standing access to a
// customer's GitLab.
func TestConnectorGrant_OnlyPluginPrincipalsCanEverResolveASecret(t *testing.T) {
	m := gibsonFGAModel()

	// The one subject type that may hold can_resolve. A connector is a plugin,
	// so this is how its ACCESS TOKEN is reachable at all.
	admitted, err := m.admitsSubjectType("secret", "can_resolve", "plugin_principal", map[string]bool{})
	if err != nil {
		t.Fatalf("resolve plugin_principal: %v", err)
	}
	if !admitted {
		t.Fatal("plugin_principal must be able to hold can_resolve, or no connector could read its access token")
	}

	// Everything else must be refused by the model itself. agent_principal is
	// the one that matters most in practice: an agent calls a connector, and
	// if it could resolve secrets directly the whole plugin-only credential
	// boundary would be decorative.
	for _, subject := range []string{"user", "agent_principal", "tool_principal", "tenant"} {
		admitted, err := m.admitsSubjectType("secret", "can_resolve", subject, map[string]bool{})
		if err != nil {
			t.Fatalf("resolve %s: %v", subject, err)
		}
		if admitted {
			t.Errorf("%s can hold secret.can_resolve — the connector grant is no longer "+
				"platform-only, and a refresh token is reachable by a non-plugin principal", subject)
		}
	}
}
