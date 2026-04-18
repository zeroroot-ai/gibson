package orchestrator

import (
	"context"
	"fmt"

	"github.com/zero-day-ai/gibson/internal/graphrag/graph"
	"github.com/zero-day-ai/gibson/internal/mission"
)

// MissionPolicySource implements PolicySource by reading from a MissionDefinition.
// It extracts data_policy configuration from mission nodes.
type MissionPolicySource struct {
	definition *mission.MissionDefinition
}

// NewMissionPolicySource creates a PolicySource from a mission definition.
func NewMissionPolicySource(def *mission.MissionDefinition) PolicySource {
	return &MissionPolicySource{
		definition: def,
	}
}

// GetDataPolicy retrieves the data policy for a specific agent from the mission definition.
// Returns nil if no policy is defined for the agent.
func (m *MissionPolicySource) GetDataPolicy(agentName string) (*DataPolicy, error) {
	if m.definition == nil {
		return nil, fmt.Errorf("mission definition is nil")
	}

	// Search through mission nodes to find the agent
	for _, node := range m.definition.Nodes {
		if node.Type == mission.NodeTypeAgent && node.AgentName == agentName {
			// Found the agent node - check if it has a data policy
			if node.DataPolicy == nil {
				return nil, nil // No policy defined
			}

			// Convert mission.DataPolicy to orchestrator.DataPolicy
			// They should have the same structure, but we need to copy
			return &DataPolicy{
				OutputScope: node.DataPolicy.OutputScope,
				InputScope:  node.DataPolicy.InputScope,
				Reuse:       node.DataPolicy.Reuse,
			}, nil
		}
	}

	// Agent not found in definition - return nil policy
	return nil, nil
}

// GraphNodeStore implements NodeStore using the GraphRAG graph database.
// It counts nodes stored by agents within specific scopes.
type GraphNodeStore struct {
	graphClient  graph.GraphClient
	missionRunID string // Current mission run ID for scope filtering
}

// NewGraphNodeStore creates a NodeStore backed by GraphRAG.
func NewGraphNodeStore(client graph.GraphClient, missionRunID string) NodeStore {
	return &GraphNodeStore{
		graphClient:  client,
		missionRunID: missionRunID,
	}
}

// CountByAgentInScope counts nodes stored by an agent within a specific scope.
// Scope determines the filtering:
//   - "mission_run": Count nodes in current run only
//   - "mission": Count nodes across all runs of this mission
//   - "global": Count nodes across all missions
//
// Nodes are identified as belonging to an agent via the "agent_name" property.
func (g *GraphNodeStore) CountByAgentInScope(ctx context.Context, agentName, scope string) (int, error) {
	// Build Cypher query based on scope
	var cypher string
	params := map[string]interface{}{
		"agent_name": agentName,
	}

	switch scope {
	case ScopeMissionRun:
		// Count nodes in current mission run only
		cypher = `
			MATCH (mr:MissionRun {id: $mission_run_id})
			MATCH (n)-[:BELONGS_TO*]->(mr)
			WHERE n.agent_name = $agent_name
			RETURN count(n) as count
		`
		params["mission_run_id"] = g.missionRunID

	case ScopeMission:
		// Count nodes across all runs of this mission
		// First get the mission from the current run, then count all nodes across all runs
		cypher = `
			MATCH (mr:MissionRun {id: $mission_run_id})-[:RUN_OF]->(m:Mission)
			MATCH (n)-[:BELONGS_TO*]->(:MissionRun)-[:RUN_OF]->(m)
			WHERE n.agent_name = $agent_name
			RETURN count(n) as count
		`
		params["mission_run_id"] = g.missionRunID

	case ScopeGlobal:
		// Count nodes across all missions
		cypher = `
			MATCH (n)
			WHERE n.agent_name = $agent_name
			RETURN count(n) as count
		`

	default:
		return 0, fmt.Errorf("invalid scope '%s': must be mission_run|mission|global", scope)
	}

	// Execute query
	result, err := g.graphClient.Query(ctx, cypher, params)
	if err != nil {
		return 0, fmt.Errorf("failed to count nodes by agent: %w", err)
	}

	if len(result.Records) == 0 {
		return 0, nil
	}

	// Extract count from result
	countValue := result.Records[0]["count"]
	if countValue == nil {
		return 0, nil
	}

	// Handle different numeric types that Neo4j might return
	switch v := countValue.(type) {
	case int64:
		return int(v), nil
	case int:
		return v, nil
	case float64:
		return int(v), nil
	default:
		return 0, fmt.Errorf("unexpected count type: %T", countValue)
	}
}
