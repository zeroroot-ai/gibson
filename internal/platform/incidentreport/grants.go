// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package incidentreport

import (
	"context"
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/platform/capabilitygrant"
)

// AgentGrantSource lists the grants of the agents with one name in one tenant.
// *capabilitygrant.CapabilityGrantStore implements it.
type AgentGrantSource interface {
	GrantsByAgentName(ctx context.Context, tenantID, agentName string) ([]capabilitygrant.AgentGrant, error)
}

// StoreGrants resolves the grant of a response action from the grant store.
type StoreGrants struct {
	Source AgentGrantSource
}

// GrantFor returns the active grant that covers toolID for the agent, or nil.
//
// A grant covers a tool when its component reference is the tool id, or when
// its capability name is "execute:tool:" followed by the tool id or by the
// connector prefix "mcp:<connector>". The name form follows the capability
// names of fga_bridge.go. A connector tool is not an FGA component today, so
// the match on the exact tool id is the one that the gate of gibson#1474 is
// expected to write.
func (g StoreGrants) GrantFor(ctx context.Context, tenant, agentName, toolID string) (*Grant, error) {
	grants, err := g.Source.GrantsByAgentName(ctx, tenant, agentName)
	if err != nil {
		return nil, fmt.Errorf("incidentreport: grants of agent %q: %w", agentName, err)
	}
	connector, _ := splitToolID(toolID)
	for _, gr := range grants {
		if gr.Status != "active" {
			continue
		}
		if gr.ComponentRef == toolID || gr.ComponentRef == "component:"+toolID ||
			gr.CapabilityName == "execute:tool:"+toolID ||
			gr.CapabilityName == "execute:tool:mcp:"+connector {
			return &Grant{
				ID: gr.ID, Capability: gr.CapabilityName,
				GrantedBy: gr.OwnerUserID, GrantedAtUnix: gr.GrantedAt.Unix(),
			}, nil
		}
	}
	return nil, nil //nolint:nilnil // nil means that no grant is recorded for the tool
}
