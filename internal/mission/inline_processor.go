package mission

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/zero-day-ai/gibson/internal/types"
)

// TargetCreator defines the interface for creating targets.
type TargetCreator interface {
	Create(ctx context.Context, target *types.Target) error
}

// WorkflowCreator defines the interface for creating workflow definitions.
type WorkflowCreator interface {
	CreateDefinition(ctx context.Context, def *MissionDefinition) error
}

// InlineConfigProcessor processes inline target and workflow configurations,
// converting them to stored entities.
type InlineConfigProcessor struct {
	targetCreator   TargetCreator
	workflowCreator WorkflowCreator
}

// NewInlineConfigProcessor creates a new inline configuration processor.
func NewInlineConfigProcessor(targetCreator TargetCreator, workflowCreator WorkflowCreator) *InlineConfigProcessor {
	return &InlineConfigProcessor{
		targetCreator:   targetCreator,
		workflowCreator: workflowCreator,
	}
}

// ProcessInlineTarget processes an inline target configuration and creates a target entity.
// Returns the created target ID and any error encountered.
func (p *InlineConfigProcessor) ProcessInlineTarget(ctx context.Context, config *InlineTarget) (types.ID, error) {
	// Validate the inline target configuration
	if err := ValidateInlineTarget(config); err != nil {
		return "", fmt.Errorf("inline target validation failed: %w", err)
	}

	// Generate a unique ID for the inline target
	targetID := types.ID(fmt.Sprintf("inline-target-%s", uuid.New().String()))

	// Convert inline config to target entity
	target := &types.Target{
		ID:          targetID,
		Name:        fmt.Sprintf("inline-target-%s", time.Now().Format("20060102-150405")),
		Type:        "recon", // Inline targets are reconnaissance targets
		Description: fmt.Sprintf("Inline target with profile: %s, depth: %d", config.Profile, config.Depth),
		Status:      types.TargetStatusActive,
		Timeout:     300, // 5 minutes default timeout
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	// Add metadata to track inline source
	target.Config = map[string]interface{}{
		"source":  "inline",
		"profile": config.Profile,
		"depth":   config.Depth,
		"seeds":   convertSeedsToMap(config.Seeds),
	}

	if len(config.Excluded) > 0 {
		target.Config["excluded"] = config.Excluded
	}

	// Merge user-provided metadata
	if config.Metadata != nil {
		for k, v := range config.Metadata {
			target.Config[k] = v
		}
	}

	// Create the target entity
	if err := p.targetCreator.Create(ctx, target); err != nil {
		return "", fmt.Errorf("failed to create inline target: %w", err)
	}

	return targetID, nil
}

// ProcessInlineWorkflow processes an inline workflow configuration and creates a workflow definition.
// Returns the created workflow ID and any error encountered.
func (p *InlineConfigProcessor) ProcessInlineWorkflow(ctx context.Context, config *InlineWorkflow) (types.ID, error) {
	// Validate the inline workflow configuration
	if err := ValidateInlineWorkflow(config); err != nil {
		return "", fmt.Errorf("inline workflow validation failed: %w", err)
	}

	// Generate a unique ID for the inline workflow
	workflowID := types.ID(fmt.Sprintf("inline-workflow-%s", uuid.New().String()))

	// Determine workflow name
	workflowName := config.Name
	if workflowName == "" {
		workflowName = fmt.Sprintf("inline-workflow-%s", time.Now().Format("20060102-150405"))
	}

	// Convert inline config to workflow definition
	definition := &MissionDefinition{
		ID:          workflowID,
		Name:        workflowName,
		Description: "Inline workflow definition",
		Version:     "1.0.0",
		CreatedAt:   time.Now(),
	}

	// Add metadata to track inline source
	definition.Metadata = map[string]any{
		"source":     "inline",
		"node_count": len(config.Nodes),
		"created_at": time.Now().Format(time.RFC3339),
	}

	// Merge user-provided metadata
	if config.Metadata != nil {
		for k, v := range config.Metadata {
			definition.Metadata[k] = v
		}
	}

	// Convert nodes and edges to workflow structure
	// Store the inline workflow configuration in the definition metadata
	// This allows the workflow engine to use the inline definition
	definition.Metadata["inline_nodes"] = convertNodesToMap(config.Nodes)
	if len(config.Edges) > 0 {
		definition.Metadata["inline_edges"] = convertEdgesToMap(config.Edges)
	}

	// Create the workflow definition
	if err := p.workflowCreator.CreateDefinition(ctx, definition); err != nil {
		return "", fmt.Errorf("failed to create inline workflow: %w", err)
	}

	return workflowID, nil
}

// convertSeedsToMap converts target seeds to a map representation.
func convertSeedsToMap(seeds []*TargetSeed) []map[string]string {
	result := make([]map[string]string, len(seeds))
	for i, seed := range seeds {
		result[i] = map[string]string{
			"value": seed.Value,
			"type":  seed.Type,
			"scope": seed.Scope,
		}
	}
	return result
}

// convertNodesToMap converts workflow nodes to a map representation.
func convertNodesToMap(nodes []*WorkflowNode) []map[string]any {
	result := make([]map[string]any, len(nodes))
	for i, node := range nodes {
		nodeMap := map[string]any{
			"id":   node.ID,
			"type": node.Type,
			"name": node.Name,
		}
		if len(node.DependsOn) > 0 {
			nodeMap["depends_on"] = node.DependsOn
		}
		if node.Config != nil {
			nodeMap["config"] = node.Config
		}
		result[i] = nodeMap
	}
	return result
}

// convertEdgesToMap converts workflow edges to a map representation.
func convertEdgesToMap(edges []*WorkflowEdge) []map[string]string {
	result := make([]map[string]string, len(edges))
	for i, edge := range edges {
		edgeMap := map[string]string{
			"from": edge.From,
			"to":   edge.To,
		}
		if edge.Condition != "" {
			edgeMap["condition"] = edge.Condition
		}
		result[i] = edgeMap
	}
	return result
}
