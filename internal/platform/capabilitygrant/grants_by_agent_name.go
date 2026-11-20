// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package capabilitygrant

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// AgentGrant is a grant of an agent, with the person who owns the agent.
type AgentGrant struct {
	Grant
	// OwnerUserID is the person who owns the agent and gave the grant. It is
	// empty for an autonomous agent with no owner.
	OwnerUserID string
}

// GrantsByAgentName returns the grants of the agents of one tenant with one
// name, oldest first. The incident report uses it: a Timeline event names the
// agent run, and the run names the agent, so the name is the join key
// (gibson#1480). The tenant is a predicate of the query, so a name in another
// tenant reads nothing.
func (s *CapabilityGrantStore) GrantsByAgentName(ctx context.Context, tenantID, agentName string) ([]AgentGrant, error) {
	if tenantID == "" {
		return nil, errors.New("capabilitygrant: GrantsByAgentName: tenant is required")
	}
	if agentName == "" {
		return nil, errors.New("capabilitygrant: GrantsByAgentName: agent name is required")
	}
	const query = `
SELECT g.id, g.agent_id, g.capability_name, g.component_ref, g.status, g.granted_at, COALESCE(a.user_id, '')
FROM   capability_grant_grants g
JOIN   capability_grant_agents a ON a.id = g.agent_id
WHERE  a.tenant_id = $1
  AND  a.name = $2
ORDER BY g.granted_at ASC`

	rows, err := s.db.QueryContext(ctx, query, tenantID, agentName)
	if err != nil {
		return nil, fmt.Errorf("capabilitygrant: GrantsByAgentName %q: %w", agentName, err)
	}
	defer rows.Close()

	var out []AgentGrant
	for rows.Next() {
		var g AgentGrant
		var grantedAt time.Time
		if err := rows.Scan(&g.ID, &g.AgentID, &g.CapabilityName, &g.ComponentRef, &g.Status, &grantedAt, &g.OwnerUserID); err != nil {
			return nil, fmt.Errorf("capabilitygrant: GrantsByAgentName %q: scan: %w", agentName, err)
		}
		g.GrantedAt = grantedAt
		out = append(out, g)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("capabilitygrant: GrantsByAgentName %q: rows: %w", agentName, err)
	}
	return out, nil
}
