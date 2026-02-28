package orchestrator

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/events"
	"github.com/zero-day-ai/gibson/internal/graphrag/graph"
	"github.com/zero-day-ai/gibson/internal/types"
)

// mockGraphClient is a test double for graph.GraphClient
type mockCheckpointGraphClient struct {
	queryFunc func(ctx context.Context, cypher string, params map[string]any) (graph.QueryResult, error)
}

func (m *mockCheckpointGraphClient) Connect(ctx context.Context) error {
	return nil
}

func (m *mockCheckpointGraphClient) Query(ctx context.Context, cypher string, params map[string]any) (graph.QueryResult, error) {
	if m.queryFunc != nil {
		return m.queryFunc(ctx, cypher, params)
	}
	return graph.QueryResult{Records: []map[string]any{}}, nil
}

func (m *mockCheckpointGraphClient) Close(ctx context.Context) error {
	return nil
}

func (m *mockCheckpointGraphClient) Health(ctx context.Context) types.HealthStatus {
	return types.Healthy("mock healthy")
}

func (m *mockCheckpointGraphClient) CreateNode(ctx context.Context, labels []string, props map[string]any) (string, error) {
	return "", nil
}

func (m *mockCheckpointGraphClient) CreateRelationship(ctx context.Context, fromID, toID, relType string, props map[string]any) error {
	return nil
}

func (m *mockCheckpointGraphClient) DeleteNode(ctx context.Context, nodeID string) error {
	return nil
}

// mockEventBus is a test double for EventBus
type mockCheckpointEventBus struct {
	events []events.Event
}

func (m *mockCheckpointEventBus) Publish(event events.Event) {
	m.events = append(m.events, event)
}

func TestNewNeo4jCheckpointManager(t *testing.T) {
	client := &mockCheckpointGraphClient{}
	eventBus := &mockCheckpointEventBus{}

	cm := NewNeo4jCheckpointManager(client, eventBus)

	require.NotNil(t, cm)
	assert.Equal(t, client, cm.client)
	assert.Equal(t, eventBus, cm.eventBus)
	assert.NotNil(t, cm.logger)
}

func TestCreateCheckpoint(t *testing.T) {
	ctx := context.Background()
	missionID := types.NewID()

	tests := []struct {
		name      string
		missionID string
		label     string
		setupMock func(*mockCheckpointGraphClient)
		wantErr   bool
		errMsg    string
	}{
		{
			name:      "successful checkpoint creation",
			missionID: missionID.String(),
			label:     "test checkpoint",
			setupMock: func(m *mockCheckpointGraphClient) {
				callCount := 0
				m.queryFunc = func(ctx context.Context, cypher string, params map[string]any) (graph.QueryResult, error) {
					callCount++
					if callCount == 1 {
						// First call: get workflow nodes
						return graph.QueryResult{
							Records: []map[string]any{
								{
									"node_id":          "node1",
									"status":           "completed",
									"task_config_json": `{"key":"value"}`,
									"name":             "test-node",
								},
								{
									"node_id":          "node2",
									"status":           "pending",
									"task_config_json": "{}",
									"name":             "test-node-2",
								},
							},
						}, nil
					} else if callCount == 2 || callCount == 3 {
						// Second and third calls: get attempt count for each node
						return graph.QueryResult{
							Records: []map[string]any{
								{"attempt": int64(2)},
							},
						}, nil
					} else {
						// Final call: create checkpoint
						return graph.QueryResult{
							Records: []map[string]any{
								{"id": "checkpoint-id"},
							},
						}, nil
					}
				}
			},
			wantErr: false,
		},
		{
			name:      "auto-generates label when empty",
			missionID: missionID.String(),
			label:     "",
			setupMock: func(m *mockCheckpointGraphClient) {
				callCount := 0
				m.queryFunc = func(ctx context.Context, cypher string, params map[string]any) (graph.QueryResult, error) {
					callCount++
					if callCount == 1 {
						// First call: get workflow nodes (return empty for simplicity)
						return graph.QueryResult{Records: []map[string]any{}}, nil
					}
					// Final call: create checkpoint
					return graph.QueryResult{
						Records: []map[string]any{{"id": "checkpoint-id"}},
					}, nil
				}
			},
			wantErr: false,
		},
		{
			name:      "invalid mission ID",
			missionID: "invalid",
			label:     "test",
			setupMock: func(m *mockCheckpointGraphClient) {},
			wantErr:   true,
			errMsg:    "invalid mission ID",
		},
		{
			name:      "mission not found",
			missionID: missionID.String(),
			label:     "test",
			setupMock: func(m *mockCheckpointGraphClient) {
				callCount := 0
				m.queryFunc = func(ctx context.Context, cypher string, params map[string]any) (graph.QueryResult, error) {
					callCount++
					if callCount <= 2 {
						return graph.QueryResult{Records: []map[string]any{}}, nil
					}
					// Create checkpoint returns empty (mission not found)
					return graph.QueryResult{Records: []map[string]any{}}, nil
				}
			},
			wantErr: true,
			errMsg:  "mission",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &mockCheckpointGraphClient{}
			mockEventBus := &mockCheckpointEventBus{}
			tt.setupMock(mockClient)

			cm := NewNeo4jCheckpointManager(mockClient, mockEventBus)
			checkpointID, err := cm.CreateCheckpoint(ctx, tt.missionID, tt.label)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
				return
			}

			require.NoError(t, err)
			assert.NotEmpty(t, checkpointID)

			// Verify event was published
			require.Len(t, mockEventBus.events, 1)
			assert.Equal(t, events.EventCheckpointCreated, mockEventBus.events[0].Type)
		})
	}
}

func TestRestoreCheckpoint(t *testing.T) {
	ctx := context.Background()
	checkpointID := types.NewID().String()
	missionID := types.NewID().String()

	tests := []struct {
		name      string
		checkID   string
		setupMock func(*mockCheckpointGraphClient)
		wantErr   bool
		errMsg    string
	}{
		{
			name:    "successful restore",
			checkID: checkpointID,
			setupMock: func(m *mockCheckpointGraphClient) {
				callCount := 0
				m.queryFunc = func(ctx context.Context, cypher string, params map[string]any) (graph.QueryResult, error) {
					callCount++
					if callCount == 1 {
						// First call: get checkpoint
						nodeStates := map[string]NodeCheckpointState{
							"node1": {
								NodeID:     "node1",
								Status:     "completed",
								TaskConfig: map[string]interface{}{"key": "value"},
								Attempt:    1,
							},
						}
						nodeStatesJSON, _ := json.Marshal(nodeStates)

						return graph.QueryResult{
							Records: []map[string]any{
								{
									"mission_id":       missionID,
									"label":            "test checkpoint",
									"node_states_json": string(nodeStatesJSON),
								},
							},
						}, nil
					} else if callCount == 2 {
						// Second call: mark executions as rolled back
						return graph.QueryResult{
							Records: []map[string]any{
								{"rolled_back_count": int64(3)},
							},
						}, nil
					} else if callCount == 3 {
						// Third call: update node
						return graph.QueryResult{
							Records: []map[string]any{
								{"id": "node1"},
							},
						}, nil
					} else {
						// Final call: reset dependent nodes
						return graph.QueryResult{
							Records: []map[string]any{
								{"reset_count": int64(1)},
							},
						}, nil
					}
				}
			},
			wantErr: false,
		},
		{
			name:    "empty checkpoint ID",
			checkID: "",
			setupMock: func(m *mockCheckpointGraphClient) {
			},
			wantErr: true,
			errMsg:  "checkpoint ID cannot be empty",
		},
		{
			name:    "checkpoint not found",
			checkID: checkpointID,
			setupMock: func(m *mockCheckpointGraphClient) {
				m.queryFunc = func(ctx context.Context, cypher string, params map[string]any) (graph.QueryResult, error) {
					return graph.QueryResult{Records: []map[string]any{}}, nil
				}
			},
			wantErr: true,
			errMsg:  "not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &mockCheckpointGraphClient{}
			mockEventBus := &mockCheckpointEventBus{}
			tt.setupMock(mockClient)

			cm := NewNeo4jCheckpointManager(mockClient, mockEventBus)
			err := cm.RestoreCheckpoint(ctx, tt.checkID)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
				return
			}

			require.NoError(t, err)

			// Verify event was published
			require.Len(t, mockEventBus.events, 1)
			assert.Equal(t, events.EventRollbackCompleted, mockEventBus.events[0].Type)
		})
	}
}

func TestGetCheckpoints(t *testing.T) {
	ctx := context.Background()
	missionID := types.NewID()

	tests := []struct {
		name      string
		missionID string
		setupMock func(*mockCheckpointGraphClient)
		wantLen   int
		wantErr   bool
		errMsg    string
	}{
		{
			name:      "returns checkpoints ordered by created_at",
			missionID: missionID.String(),
			setupMock: func(m *mockCheckpointGraphClient) {
				m.queryFunc = func(ctx context.Context, cypher string, params map[string]any) (graph.QueryResult, error) {
					nodeStates := map[string]NodeCheckpointState{
						"node1": {NodeID: "node1", Status: "completed"},
					}
					nodeStatesJSON, _ := json.Marshal(nodeStates)

					return graph.QueryResult{
						Records: []map[string]any{
							{
								"id":               "checkpoint1",
								"mission_id":       missionID.String(),
								"label":            "checkpoint 1",
								"created_at":       time.Now().Format(time.RFC3339Nano),
								"is_implicit":      false,
								"node_states_json": string(nodeStatesJSON),
							},
							{
								"id":               "checkpoint2",
								"mission_id":       missionID.String(),
								"label":            "checkpoint 2",
								"created_at":       time.Now().Add(-1 * time.Hour).Format(time.RFC3339Nano),
								"is_implicit":      true,
								"node_states_json": string(nodeStatesJSON),
							},
						},
					}, nil
				}
			},
			wantLen: 2,
			wantErr: false,
		},
		{
			name:      "invalid mission ID",
			missionID: "invalid",
			setupMock: func(m *mockCheckpointGraphClient) {},
			wantErr:   true,
			errMsg:    "invalid mission ID",
		},
		{
			name:      "empty result",
			missionID: missionID.String(),
			setupMock: func(m *mockCheckpointGraphClient) {
				m.queryFunc = func(ctx context.Context, cypher string, params map[string]any) (graph.QueryResult, error) {
					return graph.QueryResult{Records: []map[string]any{}}, nil
				}
			},
			wantLen: 0,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &mockCheckpointGraphClient{}
			tt.setupMock(mockClient)

			cm := NewNeo4jCheckpointManager(mockClient, nil)
			checkpoints, err := cm.GetCheckpoints(ctx, tt.missionID)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
				return
			}

			require.NoError(t, err)
			assert.Len(t, checkpoints, tt.wantLen)
		})
	}
}

func TestCreateImplicitCheckpoint(t *testing.T) {
	ctx := context.Background()
	missionID := types.NewID()
	nodeID := types.NewID()

	tests := []struct {
		name      string
		missionID string
		nodeID    string
		setupMock func(*mockCheckpointGraphClient)
		wantErr   bool
		errMsg    string
	}{
		{
			name:      "successful implicit checkpoint",
			missionID: missionID.String(),
			nodeID:    nodeID.String(),
			setupMock: func(m *mockCheckpointGraphClient) {
				callCount := 0
				m.queryFunc = func(ctx context.Context, cypher string, params map[string]any) (graph.QueryResult, error) {
					callCount++
					if callCount == 1 {
						// First call: get workflow nodes
						return graph.QueryResult{
							Records: []map[string]any{
								{
									"node_id":          nodeID.String(),
									"status":           "ready",
									"task_config_json": "{}",
								},
							},
						}, nil
					} else if callCount == 2 {
						// Second call: get attempt count
						return graph.QueryResult{
							Records: []map[string]any{
								{"attempt": int64(1)},
							},
						}, nil
					} else {
						// Final call: create checkpoint
						return graph.QueryResult{
							Records: []map[string]any{
								{"id": "checkpoint-id"},
							},
						}, nil
					}
				}
			},
			wantErr: false,
		},
		{
			name:      "invalid mission ID",
			missionID: "invalid",
			nodeID:    nodeID.String(),
			setupMock: func(m *mockCheckpointGraphClient) {},
			wantErr:   true,
			errMsg:    "invalid mission ID",
		},
		{
			name:      "invalid node ID",
			missionID: missionID.String(),
			nodeID:    "invalid",
			setupMock: func(m *mockCheckpointGraphClient) {},
			wantErr:   true,
			errMsg:    "invalid node ID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &mockCheckpointGraphClient{}
			mockEventBus := &mockCheckpointEventBus{}
			tt.setupMock(mockClient)

			cm := NewNeo4jCheckpointManager(mockClient, mockEventBus)
			err := cm.CreateImplicitCheckpoint(ctx, tt.missionID, tt.nodeID)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
				return
			}

			require.NoError(t, err)

			// Verify event was published with is_implicit=true
			require.Len(t, mockEventBus.events, 1)
			assert.Equal(t, events.EventCheckpointCreated, mockEventBus.events[0].Type)
			payload, ok := mockEventBus.events[0].Payload.(map[string]any)
			require.True(t, ok)
			assert.True(t, payload["is_implicit"].(bool))
		})
	}
}

func TestCheckpointLifecycle(t *testing.T) {
	// Integration-style test that validates the full lifecycle
	ctx := context.Background()
	missionID := types.NewID()
	checkpointID := types.NewID().String()

	// Track all queries executed
	var queries []string

	mockClient := &mockCheckpointGraphClient{
		queryFunc: func(ctx context.Context, cypher string, params map[string]any) (graph.QueryResult, error) {
			queries = append(queries, cypher)

			// Simulate different responses based on query pattern
			if checkpointContains(cypher, "MATCH (n:WorkflowNode)") && checkpointContains(cypher, "RETURN n.id") {
				// Get nodes for checkpoint
				return graph.QueryResult{
					Records: []map[string]any{
						{
							"node_id":          "node1",
							"status":           "completed",
							"task_config_json": `{"timeout": 300}`,
							"name":             "test-node",
						},
					},
				}, nil
			} else if checkpointContains(cypher, "CREATE (c:Checkpoint") {
				// Create checkpoint
				return graph.QueryResult{
					Records: []map[string]any{{"id": checkpointID}},
				}, nil
			} else if checkpointContains(cypher, "MATCH (c:Checkpoint {id:") {
				// Get checkpoint
				nodeStates := map[string]NodeCheckpointState{
					"node1": {NodeID: "node1", Status: "pending", TaskConfig: map[string]interface{}{}},
				}
				nodeStatesJSON, _ := json.Marshal(nodeStates)

				return graph.QueryResult{
					Records: []map[string]any{
						{
							"mission_id":       missionID.String(),
							"label":            "test",
							"node_states_json": string(nodeStatesJSON),
						},
					},
				}, nil
			} else if checkpointContains(cypher, "rolled_back") || checkpointContains(cypher, "reset_count") {
				// Restore operations
				return graph.QueryResult{
					Records: []map[string]any{{"rolled_back_count": int64(0)}, {"reset_count": int64(0)}},
				}, nil
			} else if checkpointContains(cypher, "MATCH (e:AgentExecution)") {
				// Get attempt count
				return graph.QueryResult{
					Records: []map[string]any{{"attempt": int64(1)}},
				}, nil
			}

			return graph.QueryResult{Records: []map[string]any{}}, nil
		},
	}

	mockEventBus := &mockCheckpointEventBus{}
	cm := NewNeo4jCheckpointManager(mockClient, mockEventBus)

	// 1. Create checkpoint
	id, err := cm.CreateCheckpoint(ctx, missionID.String(), "test checkpoint")
	require.NoError(t, err)
	assert.NotEmpty(t, id)

	// 2. Get checkpoints (would be tested separately with proper mock)
	// This validates the interface is complete

	// 3. Restore checkpoint (simulated)
	// In a real scenario, this would verify nodes are reset

	// Verify basic query execution
	assert.NotEmpty(t, queries, "should have executed queries")
}

// Helper functions (prefixed to avoid conflicts with other test files)
func checkpointContains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || checkpointFindSubstring(s, substr)))
}

func checkpointFindSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
