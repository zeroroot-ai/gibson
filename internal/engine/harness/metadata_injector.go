package harness

import (
	"context"
	"fmt"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/harness/middleware"
	"github.com/zeroroot-ai/sdk/graphrag"
)

// MetadataInjector injects mission context metadata into GraphRAG nodes.
// It ensures that all stored nodes have proper provenance tracking by automatically
// adding mission_id, mission_run_id, agent_run_id, and discovered_at properties.
//
// The injector enforces a security policy: agents CANNOT set these reserved properties
// themselves. If an agent attempts to set any reserved property, the injection will fail
// with an error, preventing agents from spoofing their execution context.
//
// This policy ensures data integrity and reliable audit trails in the knowledge graph.
type MetadataInjector interface {
	// Inject adds mission context metadata to a node before storage.
	// It extracts mission_id, mission_run_id, and agent_run_id from the context
	// and injects them as node properties along with the current timestamp.
	//
	// Returns an error if:
	//   - The node already has any reserved property set (policy violation)
	//   - Required context values are missing from the context
	Inject(ctx context.Context, node *graphrag.GraphNode) error
}

// metadataInjector implements MetadataInjector with policy enforcement.
type metadataInjector struct {
	// reservedProps are property names that only the harness can set.
	// Agents attempting to set these will receive an error.
	reservedProps []string
}

// NewMetadataInjector creates a new MetadataInjector with the standard set of
// reserved properties that agents cannot set.
//
// Reserved properties:
//   - mission_id: The mission identifier from the execution context
//   - mission_run_id: The unique identifier for this mission run
//   - agent_run_id: The unique identifier for this agent execution
//   - discovered_at: Unix timestamp when the node was stored
func NewMetadataInjector() MetadataInjector {
	return &metadataInjector{
		reservedProps: []string{
			"mission_id",
			"mission_run_id",
			"agent_run_id",
			"discovered_at",
		},
	}
}

// Inject adds mission context metadata to the node's properties.
//
// The injection process:
// 1. Validates that the agent hasn't set any reserved properties
// 2. Extracts mission_id from middleware context
// 3. Extracts mission_run_id from harness context
// 4. Extracts agent_run_id from harness context
// 5. Adds discovered_at timestamp
//
// If the node already has any reserved property set, this returns an error
// to prevent agents from spoofing their execution context.
//
// Parameters:
//   - ctx: Context containing mission metadata (must have mission_id, mission_run_id, agent_run_id)
//   - node: The GraphNode to inject metadata into
//
// Returns:
//   - nil if injection succeeds
//   - error if a reserved property is already set or if required context is missing
func (m *metadataInjector) Inject(ctx context.Context, node *graphrag.GraphNode) error {
	if node == nil {
		return fmt.Errorf("cannot inject metadata into nil node")
	}

	// Step 1: Validate that agent hasn't set reserved properties
	for _, prop := range m.reservedProps {
		if _, exists := node.Properties[prop]; exists {
			return fmt.Errorf("cannot set reserved property '%s': this property is injected by the harness", prop)
		}
	}

	// Step 2: Extract mission_id from middleware context
	missionID, _ := middleware.GetMissionContext(ctx)
	if missionID == "" {
		return fmt.Errorf("mission_id not found in context")
	}

	// Step 3: Extract mission_run_id from harness context
	missionRunID := MissionRunIDFromContext(ctx)
	if missionRunID == "" {
		return fmt.Errorf("mission_run_id not found in context")
	}

	// Step 4: Extract agent_run_id from harness context
	agentRunID := AgentRunIDFromContext(ctx)
	if agentRunID == "" {
		return fmt.Errorf("agent_run_id not found in context")
	}

	// Step 5: Inject all metadata properties
	node.Properties["mission_id"] = missionID
	node.Properties["mission_run_id"] = missionRunID
	node.Properties["agent_run_id"] = agentRunID
	// Use RFC3339 format (24-hour time with timezone) for consistency and readability
	node.Properties["discovered_at"] = time.Now().UTC().Format(time.RFC3339)

	return nil
}
