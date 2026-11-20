// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package incidentreport

import "strings"

// ResponseAction names one tool that contains an incident, or releases a
// containment, and the NIST 800-53 controls that a call of it is evidence for.
type ResponseAction struct {
	// ToolID is "mcp:<connector>:<tool>". The connector is the directory name
	// in the `connectors` repo.
	ToolID string
	// Controls are control ids of the pack `nist-800-53-r5`.
	Controls []string
}

// responseActions is the set of response actions of ADR-0180. The ids are the
// tool names of the servers in the `connectors` repo (branch
// feat/first-servers). The mapping to controls is the judgment of Zero Root:
// IR-4 is incident handling, which includes containment. AC-2 is account
// management, AC-12 is session termination and SC-7 is boundary protection.
// The report states evidence and never a verdict.
var responseActions = []ResponseAction{
	{"mcp:okta:revoke_user_sessions", []string{"ac-12", "ir-4"}},
	{"mcp:okta:suspend_user", []string{"ac-2", "ir-4"}},
	{"mcp:okta:unsuspend_user", []string{"ac-2", "ir-4"}},
	{"mcp:entra-id:revoke_sign_in_sessions", []string{"ac-12", "ir-4"}},
	{"mcp:entra-id:disable_account", []string{"ac-2", "ir-4"}},
	{"mcp:entra-id:enable_account", []string{"ac-2", "ir-4"}},
	{"mcp:crowdstrike:contain_host", []string{"sc-7", "ir-4"}},
	{"mcp:crowdstrike:lift_containment", []string{"sc-7", "ir-4"}},
	{"mcp:defender-endpoint:isolate_device", []string{"sc-7", "ir-4"}},
	{"mcp:defender-endpoint:release_device", []string{"sc-7", "ir-4"}},
	{"mcp:sentinelone:disconnect_from_network", []string{"sc-7", "ir-4"}},
	{"mcp:sentinelone:reconnect_to_network", []string{"sc-7", "ir-4"}},
}

// ResponseActions returns a copy of the set of response actions.
func ResponseActions() []ResponseAction {
	out := make([]ResponseAction, len(responseActions))
	for i, a := range responseActions {
		out[i] = ResponseAction{ToolID: a.ToolID, Controls: append([]string(nil), a.Controls...)}
	}
	return out
}

// lookupAction returns the response action for a tool id.
func lookupAction(toolID string) (ResponseAction, bool) {
	for _, a := range responseActions {
		if a.ToolID == toolID {
			return a, true
		}
	}
	return ResponseAction{}, false
}

// splitToolID splits "mcp:<connector>:<tool>".
func splitToolID(toolID string) (connector, tool string) {
	parts := strings.SplitN(toolID, ":", 3)
	if len(parts) != 3 {
		return "", toolID
	}
	return parts[1], parts[2]
}
