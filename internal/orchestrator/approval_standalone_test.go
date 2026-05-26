package orchestrator_test

import (
	"context"
	"testing"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/events"
	"github.com/zeroroot-ai/gibson/internal/graphrag/graph"
	"github.com/zeroroot-ai/gibson/internal/orchestrator"
	"github.com/zeroroot-ai/gibson/internal/types"
)

// mockGraphClient is a minimal mock for testing approval manager
type mockGraphClient struct {
	queryFunc func(ctx context.Context, cypher string, params map[string]any) (graph.QueryResult, error)
}

func (m *mockGraphClient) Query(ctx context.Context, cypher string, params map[string]any) (graph.QueryResult, error) {
	if m.queryFunc != nil {
		return m.queryFunc(ctx, cypher, params)
	}
	return graph.QueryResult{Records: []map[string]any{}}, nil
}

func (m *mockGraphClient) Connect(ctx context.Context) error { return nil }
func (m *mockGraphClient) Close(ctx context.Context) error   { return nil }
func (m *mockGraphClient) Health(ctx context.Context) types.HealthStatus {
	return types.NewHealthStatus(types.HealthStateHealthy, "")
}
func (m *mockGraphClient) CreateNode(ctx context.Context, labels []string, props map[string]any) (string, error) {
	return "", nil
}
func (m *mockGraphClient) CreateRelationship(ctx context.Context, fromID, toID, relType string, props map[string]any) error {
	return nil
}
func (m *mockGraphClient) DeleteNode(ctx context.Context, id string) error { return nil }

func (m *mockGraphClient) ExecuteRead(ctx context.Context, fn func(neo4j.ManagedTransaction) (any, error)) (any, error) {
	return fn(nil)
}

func (m *mockGraphClient) ExecuteWrite(ctx context.Context, fn func(neo4j.ManagedTransaction) (any, error)) (any, error) {
	return fn(nil)
}

// mockEventBus captures published events for testing
type mockEventBus struct {
	events []events.Event
}

func (m *mockEventBus) Publish(event events.Event) {
	m.events = append(m.events, event)
}

func TestApprovalManager_Basic(t *testing.T) {
	missionID := types.NewID().String()
	nodeID := types.NewID().String()

	client := &mockGraphClient{
		queryFunc: func(ctx context.Context, cypher string, params map[string]any) (graph.QueryResult, error) {
			return graph.QueryResult{
				Records: []map[string]any{
					{"id": params["id"]},
				},
			}, nil
		},
	}

	bus := &mockEventBus{}
	manager := orchestrator.NewNeo4jApprovalManager(client, bus)

	// Test creating a request
	req := orchestrator.ApprovalRequest{
		MissionID:     missionID,
		NodeID:        nodeID,
		Context:       "Please approve this action",
		Timeout:       5 * time.Minute,
		TimeoutAction: "reject",
	}

	approvalID, err := manager.CreateRequest(context.Background(), req)

	require.NoError(t, err)
	assert.NotEmpty(t, approvalID)

	// Verify event was published
	require.Equal(t, 1, len(bus.events))
	assert.Equal(t, events.EventApprovalRequested, bus.events[0].Type)
}

func TestApprovalManager_Validation(t *testing.T) {
	client := &mockGraphClient{}
	bus := &mockEventBus{}
	manager := orchestrator.NewNeo4jApprovalManager(client, bus)

	// Test missing mission ID
	req := orchestrator.ApprovalRequest{
		NodeID:        types.NewID().String(),
		Context:       "test",
		TimeoutAction: "reject",
	}

	_, err := manager.CreateRequest(context.Background(), req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mission ID cannot be empty")
}
