// Package harness provides the agent execution environment.
package harness

import (
	"context"
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/agent"
	"github.com/zeroroot-ai/gibson/internal/types"
	sdkgraphrag "github.com/zeroroot-ai/sdk/graphrag"
)

// NoopGraphRAGBridge is a no-op implementation of GraphRAGBridge that discards all findings.
// Used when GraphRAG is disabled or not configured.
type NoopGraphRAGBridge struct{}

// StoreAsync does nothing (no-op).
func (n *NoopGraphRAGBridge) StoreAsync(ctx context.Context, finding agent.Finding, missionID types.ID, targetID *types.ID) {
	// No-op: discard finding
}

// Shutdown does nothing (no-op).
func (n *NoopGraphRAGBridge) Shutdown(ctx context.Context) error {
	return nil
}

// Health returns healthy status (no-op).
func (n *NoopGraphRAGBridge) Health(ctx context.Context) types.HealthStatus {
	return types.NewHealthStatus(types.HealthStateHealthy, "GraphRAG disabled (no-op bridge)")
}

// NoopGraphRAGQueryBridge is a no-op implementation of GraphRAGQueryBridge.
// All query methods return ErrGraphRAGNotEnabled.
type NoopGraphRAGQueryBridge struct{}

// ErrGraphRAGNotEnabled is returned when GraphRAG operations are attempted
// but GraphRAG is not configured.
var ErrGraphRAGNotEnabled = fmt.Errorf("GraphRAG is not enabled. Configure GraphRAG provider in config to use these operations")

// StoreNode returns ErrGraphRAGNotEnabled.
func (n *NoopGraphRAGQueryBridge) StoreNode(ctx context.Context, node sdkgraphrag.GraphNode, missionID, agentName string) (string, error) {
	return "", ErrGraphRAGNotEnabled
}

// CreateRelationship returns ErrGraphRAGNotEnabled.
func (n *NoopGraphRAGQueryBridge) CreateRelationship(ctx context.Context, relationship sdkgraphrag.Relationship) error {
	return ErrGraphRAGNotEnabled
}

// StoreBatch returns ErrGraphRAGNotEnabled.
func (n *NoopGraphRAGQueryBridge) StoreBatch(ctx context.Context, batch sdkgraphrag.Batch, missionID, agentName string) ([]string, error) {
	return nil, ErrGraphRAGNotEnabled
}

// GetNode returns ErrGraphRAGNotEnabled.
func (n *NoopGraphRAGQueryBridge) GetNode(ctx context.Context, nodeID string) (sdkgraphrag.GraphNode, error) {
	return sdkgraphrag.GraphNode{}, ErrGraphRAGNotEnabled
}

// GetRelationships returns ErrGraphRAGNotEnabled.
func (n *NoopGraphRAGQueryBridge) GetRelationships(ctx context.Context, nodeID string, relType string) ([]sdkgraphrag.Relationship, error) {
	return nil, ErrGraphRAGNotEnabled
}

// StoreSemantic returns ErrGraphRAGNotEnabled.
func (n *NoopGraphRAGQueryBridge) StoreSemantic(ctx context.Context, node sdkgraphrag.GraphNode, missionID, agentName string) (string, error) {
	return "", ErrGraphRAGNotEnabled
}

// StoreStructured returns ErrGraphRAGNotEnabled.
func (n *NoopGraphRAGQueryBridge) StoreStructured(ctx context.Context, node sdkgraphrag.GraphNode, missionID, agentName string) (string, error) {
	return "", ErrGraphRAGNotEnabled
}

// Health returns healthy status (no-op).
func (n *NoopGraphRAGQueryBridge) Health(ctx context.Context) types.HealthStatus {
	return types.NewHealthStatus(types.HealthStateHealthy, "GraphRAG disabled (no-op query bridge)")
}
