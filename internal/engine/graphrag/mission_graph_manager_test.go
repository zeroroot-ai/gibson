package graphrag

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/graphrag/graph"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// mockGraphClient is a mock implementation of graph.GraphClient for testing.
type mockGraphClient struct {
	queryFunc func(ctx context.Context, cypher string, params map[string]any) (graph.QueryResult, error)
}

func (m *mockGraphClient) Connect(ctx context.Context) error {
	return nil
}

func (m *mockGraphClient) Close(ctx context.Context) error {
	return nil
}

func (m *mockGraphClient) Health(ctx context.Context) types.HealthStatus {
	return types.Healthy("mock client is healthy")
}

func (m *mockGraphClient) Query(ctx context.Context, cypher string, params map[string]any) (graph.QueryResult, error) {
	if m.queryFunc != nil {
		return m.queryFunc(ctx, cypher, params)
	}
	return graph.QueryResult{}, nil
}

func (m *mockGraphClient) CreateNode(ctx context.Context, labels []string, props map[string]any) (string, error) {
	return "", nil
}

func (m *mockGraphClient) CreateRelationship(ctx context.Context, fromID, toID, relType string, props map[string]any) error {
	return nil
}

func (m *mockGraphClient) DeleteNode(ctx context.Context, nodeID string) error {
	return nil
}

func (m *mockGraphClient) ExecuteRead(ctx context.Context, fn func(neo4j.ManagedTransaction) (any, error)) (any, error) {
	return fn(nil)
}

func (m *mockGraphClient) ExecuteWrite(ctx context.Context, fn func(neo4j.ManagedTransaction) (any, error)) (any, error) {
	return fn(nil)
}

// TestNewMissionGraphManager tests the constructor
func TestNewMissionGraphManager(t *testing.T) {
	client := &mockGraphClient{}
	manager := NewMissionGraphManager(client)

	require.NotNil(t, manager)
	assert.Equal(t, client, manager.graphClient)
}

// TestEnsureMissionNode_Success tests successful mission node creation
func TestEnsureMissionNode_Success(t *testing.T) {
	tests := []struct {
		name       string
		missionID  string
		setupMock  func() *mockGraphClient
		wantErr    bool
		errMessage string
	}{
		{
			name:      "creates new mission node",
			missionID: "mission-123",
			setupMock: func() *mockGraphClient {
				return &mockGraphClient{
					queryFunc: func(ctx context.Context, cypher string, params map[string]any) (graph.QueryResult, error) {
						// Verify MERGE query structure
						assert.Contains(t, cypher, "MERGE (m:mission {name: $name, target_id: $target_id})")
						assert.Contains(t, cypher, "ON CREATE SET m.id = $id, m.created_at = timestamp()")
						assert.Contains(t, cypher, "RETURN m.id as mission_id")

						// Verify parameters
						assert.Equal(t, "test-mission", params["name"])
						assert.Equal(t, "target-123", params["target_id"])
						assert.NotEmpty(t, params["id"])

						// Return created mission ID
						return graph.QueryResult{
							Records: []map[string]any{
								{"mission_id": "mission-123"},
							},
						}, nil
					},
				}
			},
		},
		{
			name:      "returns existing mission node",
			missionID: "existing-mission-456",
			setupMock: func() *mockGraphClient {
				return &mockGraphClient{
					queryFunc: func(ctx context.Context, cypher string, params map[string]any) (graph.QueryResult, error) {
						// Return existing mission ID
						return graph.QueryResult{
							Records: []map[string]any{
								{"mission_id": "existing-mission-456"},
							},
						}, nil
					},
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := tt.setupMock()
			manager := NewMissionGraphManager(client)

			missionID, err := manager.EnsureMissionNode(context.Background(), "test-mission", "target-123")

			require.NoError(t, err)
			assert.Equal(t, tt.missionID, missionID)
		})
	}
}

// TestEnsureMissionNode_ValidationErrors tests input validation
func TestEnsureMissionNode_ValidationErrors(t *testing.T) {
	tests := []struct {
		name       string
		missionMgr *MissionGraphManager
		mission    string
		targetID   string
		wantErr    string
	}{
		{
			name:       "nil client",
			missionMgr: NewMissionGraphManager(nil),
			mission:    "test-mission",
			targetID:   "target-123",
			wantErr:    "graph client is nil",
		},
		{
			name:       "empty mission name",
			missionMgr: NewMissionGraphManager(&mockGraphClient{}),
			mission:    "",
			targetID:   "target-123",
			wantErr:    "mission name cannot be empty",
		},
		{
			name:       "empty target ID",
			missionMgr: NewMissionGraphManager(&mockGraphClient{}),
			mission:    "test-mission",
			targetID:   "",
			wantErr:    "target ID cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.missionMgr.EnsureMissionNode(context.Background(), tt.mission, tt.targetID)

			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

// TestEnsureMissionNode_QueryErrors tests error handling during query execution
func TestEnsureMissionNode_QueryErrors(t *testing.T) {
	tests := []struct {
		name      string
		setupMock func() *mockGraphClient
		wantErr   string
	}{
		{
			name: "query execution fails",
			setupMock: func() *mockGraphClient {
				return &mockGraphClient{
					queryFunc: func(ctx context.Context, cypher string, params map[string]any) (graph.QueryResult, error) {
						return graph.QueryResult{}, errors.New("connection timeout")
					},
				}
			},
			wantErr: "failed to ensure mission node",
		},
		{
			name: "no records returned",
			setupMock: func() *mockGraphClient {
				return &mockGraphClient{
					queryFunc: func(ctx context.Context, cypher string, params map[string]any) (graph.QueryResult, error) {
						return graph.QueryResult{
							Records: []map[string]any{},
						}, nil
					},
				}
			},
			wantErr: "query returned no records",
		},
		{
			name: "invalid mission_id type",
			setupMock: func() *mockGraphClient {
				return &mockGraphClient{
					queryFunc: func(ctx context.Context, cypher string, params map[string]any) (graph.QueryResult, error) {
						return graph.QueryResult{
							Records: []map[string]any{
								{"mission_id": 123}, // Invalid: should be string
							},
						}, nil
					},
				}
			},
			wantErr: "mission_id has invalid type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := tt.setupMock()
			manager := NewMissionGraphManager(client)

			_, err := manager.EnsureMissionNode(context.Background(), "test-mission", "target-123")

			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

// TestCreateMissionRunNode_Success tests successful mission run node creation
func TestCreateMissionRunNode_Success(t *testing.T) {
	tests := []struct {
		name       string
		runID      string
		runNumber  int
		setupMock  func() *mockGraphClient
		wantErr    bool
		errMessage string
	}{
		{
			name:      "creates mission run with run_number 1",
			runID:     "run-abc123",
			runNumber: 1,
			setupMock: func() *mockGraphClient {
				return &mockGraphClient{
					queryFunc: func(ctx context.Context, cypher string, params map[string]any) (graph.QueryResult, error) {
						// Verify CREATE query structure (not MERGE)
						assert.Contains(t, cypher, "CREATE (r:mission_run {")
						assert.Contains(t, cypher, "CREATE (r)-[:BELONGS_TO]->(m)")
						assert.NotContains(t, cypher, "MERGE") // Must use CREATE

						// Verify node properties
						assert.Equal(t, "mission-123", params["mission_id"])
						assert.Equal(t, 1, params["run_number"])
						assert.NotEmpty(t, params["run_id"])

						// Verify query matches mission by ID
						assert.Contains(t, cypher, "MATCH (m:mission {id: $mission_id})")

						return graph.QueryResult{
							Records: []map[string]any{
								{"run_id": "run-abc123"},
							},
						}, nil
					},
				}
			},
		},
		{
			name:      "creates mission run with run_number 5",
			runID:     "run-xyz789",
			runNumber: 5,
			setupMock: func() *mockGraphClient {
				return &mockGraphClient{
					queryFunc: func(ctx context.Context, cypher string, params map[string]any) (graph.QueryResult, error) {
						assert.Equal(t, 5, params["run_number"])
						return graph.QueryResult{
							Records: []map[string]any{
								{"run_id": "run-xyz789"},
							},
						}, nil
					},
				}
			},
		},
		{
			name:      "creates mission run with run_number 0",
			runID:     "run-zero",
			runNumber: 0,
			setupMock: func() *mockGraphClient {
				return &mockGraphClient{
					queryFunc: func(ctx context.Context, cypher string, params map[string]any) (graph.QueryResult, error) {
						assert.Equal(t, 0, params["run_number"])
						return graph.QueryResult{
							Records: []map[string]any{
								{"run_id": "run-zero"},
							},
						}, nil
					},
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := tt.setupMock()
			manager := NewMissionGraphManager(client)

			runID, err := manager.CreateMissionRunNode(context.Background(), "mission-123", tt.runNumber)

			require.NoError(t, err)
			assert.Equal(t, tt.runID, runID)
		})
	}
}

// TestCreateMissionRunNode_ValidationErrors tests input validation
func TestCreateMissionRunNode_ValidationErrors(t *testing.T) {
	tests := []struct {
		name       string
		missionMgr *MissionGraphManager
		missionID  string
		runNumber  int
		wantErr    string
	}{
		{
			name:       "nil client",
			missionMgr: NewMissionGraphManager(nil),
			missionID:  "mission-123",
			runNumber:  1,
			wantErr:    "graph client is nil",
		},
		{
			name:       "empty mission ID",
			missionMgr: NewMissionGraphManager(&mockGraphClient{}),
			missionID:  "",
			runNumber:  1,
			wantErr:    "mission ID cannot be empty",
		},
		{
			name:       "negative run number",
			missionMgr: NewMissionGraphManager(&mockGraphClient{}),
			missionID:  "mission-123",
			runNumber:  -1,
			wantErr:    "run number cannot be negative",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.missionMgr.CreateMissionRunNode(context.Background(), tt.missionID, tt.runNumber)

			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

// TestCreateMissionRunNode_QueryErrors tests error handling during query execution
func TestCreateMissionRunNode_QueryErrors(t *testing.T) {
	tests := []struct {
		name      string
		setupMock func() *mockGraphClient
		wantErr   string
	}{
		{
			name: "query execution fails",
			setupMock: func() *mockGraphClient {
				return &mockGraphClient{
					queryFunc: func(ctx context.Context, cypher string, params map[string]any) (graph.QueryResult, error) {
						return graph.QueryResult{}, errors.New("connection lost")
					},
				}
			},
			wantErr: "failed to create mission run node",
		},
		{
			name: "mission not found (no records)",
			setupMock: func() *mockGraphClient {
				return &mockGraphClient{
					queryFunc: func(ctx context.Context, cypher string, params map[string]any) (graph.QueryResult, error) {
						return graph.QueryResult{
							Records: []map[string]any{},
						}, nil
					},
				}
			},
			wantErr: "mission may not exist",
		},
		{
			name: "invalid run_id type",
			setupMock: func() *mockGraphClient {
				return &mockGraphClient{
					queryFunc: func(ctx context.Context, cypher string, params map[string]any) (graph.QueryResult, error) {
						return graph.QueryResult{
							Records: []map[string]any{
								{"run_id": 456}, // Invalid: should be string
							},
						}, nil
					},
				}
			},
			wantErr: "run_id has invalid type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := tt.setupMock()
			manager := NewMissionGraphManager(client)

			_, err := manager.CreateMissionRunNode(context.Background(), "mission-123", 1)

			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

// TestUpdateMissionRunStatus_Success tests successful status updates
func TestUpdateMissionRunStatus_Success(t *testing.T) {
	tests := []struct {
		name              string
		status            string
		shouldSetComplete bool
	}{
		{
			name:              "update to running",
			status:            "running",
			shouldSetComplete: false,
		},
		{
			name:              "update to completed",
			status:            "completed",
			shouldSetComplete: true,
		},
		{
			name:              "update to failed",
			status:            "failed",
			shouldSetComplete: true,
		},
		{
			name:              "update to cancelled",
			status:            "cancelled",
			shouldSetComplete: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &mockGraphClient{
				queryFunc: func(ctx context.Context, cypher string, params map[string]any) (graph.QueryResult, error) {
					// Verify query structure
					assert.Contains(t, cypher, "MATCH (r:mission_run {id: $run_id})")
					assert.Contains(t, cypher, "SET r.status = $status")

					// Verify completed_at is set for terminal states
					if tt.shouldSetComplete {
						assert.Contains(t, cypher, "r.completed_at = timestamp()")
					} else {
						// Ensure completed_at is NOT set for non-terminal states
						assert.NotContains(t, cypher, "completed_at")
					}

					// Verify parameters
					assert.Equal(t, "run-123", params["run_id"])
					assert.Equal(t, tt.status, params["status"])

					return graph.QueryResult{
						Records: []map[string]any{
							{"run_id": "run-123"},
						},
					}, nil
				},
			}

			manager := NewMissionGraphManager(client)
			err := manager.UpdateMissionRunStatus(context.Background(), "run-123", tt.status)

			require.NoError(t, err)
		})
	}
}

// TestUpdateMissionRunStatus_ValidationErrors tests input validation
func TestUpdateMissionRunStatus_ValidationErrors(t *testing.T) {
	tests := []struct {
		name       string
		missionMgr *MissionGraphManager
		runID      string
		status     string
		wantErr    string
	}{
		{
			name:       "nil client",
			missionMgr: NewMissionGraphManager(nil),
			runID:      "run-123",
			status:     "completed",
			wantErr:    "graph client is nil",
		},
		{
			name:       "empty run ID",
			missionMgr: NewMissionGraphManager(&mockGraphClient{}),
			runID:      "",
			status:     "completed",
			wantErr:    "run ID cannot be empty",
		},
		{
			name:       "empty status",
			missionMgr: NewMissionGraphManager(&mockGraphClient{}),
			runID:      "run-123",
			status:     "",
			wantErr:    "status cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.missionMgr.UpdateMissionRunStatus(context.Background(), tt.runID, tt.status)

			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

// TestUpdateMissionRunStatus_QueryErrors tests error handling during query execution
func TestUpdateMissionRunStatus_QueryErrors(t *testing.T) {
	tests := []struct {
		name      string
		setupMock func() *mockGraphClient
		wantErr   string
	}{
		{
			name: "query execution fails",
			setupMock: func() *mockGraphClient {
				return &mockGraphClient{
					queryFunc: func(ctx context.Context, cypher string, params map[string]any) (graph.QueryResult, error) {
						return graph.QueryResult{}, errors.New("database unavailable")
					},
				}
			},
			wantErr: "failed to update mission run status",
		},
		{
			name: "mission run not found",
			setupMock: func() *mockGraphClient {
				return &mockGraphClient{
					queryFunc: func(ctx context.Context, cypher string, params map[string]any) (graph.QueryResult, error) {
						return graph.QueryResult{
							Records: []map[string]any{},
						}, nil
					},
				}
			},
			wantErr: "mission run not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := tt.setupMock()
			manager := NewMissionGraphManager(client)

			err := manager.UpdateMissionRunStatus(context.Background(), "run-123", "completed")

			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

// TestMissionGraphManager_CypherQueries verifies exact Cypher query generation
func TestMissionGraphManager_CypherQueries(t *testing.T) {
	t.Run("EnsureMissionNode uses MERGE", func(t *testing.T) {
		client := &mockGraphClient{
			queryFunc: func(ctx context.Context, cypher string, params map[string]any) (graph.QueryResult, error) {
				// Normalize whitespace for comparison
				normalized := strings.Join(strings.Fields(cypher), " ")

				// Must use MERGE, not CREATE
				assert.Contains(t, normalized, "MERGE (m:mission")
				assert.NotContains(t, normalized, "CREATE (m:mission")

				return graph.QueryResult{
					Records: []map[string]any{{"mission_id": "test"}},
				}, nil
			},
		}
		manager := NewMissionGraphManager(client)
		_, _ = manager.EnsureMissionNode(context.Background(), "test", "target")
	})

	t.Run("CreateMissionRunNode uses CREATE not MERGE", func(t *testing.T) {
		client := &mockGraphClient{
			queryFunc: func(ctx context.Context, cypher string, params map[string]any) (graph.QueryResult, error) {
				// Normalize whitespace for comparison
				normalized := strings.Join(strings.Fields(cypher), " ")

				// Must use CREATE, not MERGE
				assert.Contains(t, normalized, "CREATE (r:mission_run")
				assert.NotContains(t, normalized, "MERGE (r:mission_run")

				// Must create BELONGS_TO relationship
				assert.Contains(t, normalized, "CREATE (r)-[:BELONGS_TO]->(m)")

				return graph.QueryResult{
					Records: []map[string]any{{"run_id": "test"}},
				}, nil
			},
		}
		manager := NewMissionGraphManager(client)
		_, _ = manager.CreateMissionRunNode(context.Background(), "mission-123", 1)
	})

	t.Run("UpdateMissionRunStatus sets properties correctly", func(t *testing.T) {
		client := &mockGraphClient{
			queryFunc: func(ctx context.Context, cypher string, params map[string]any) (graph.QueryResult, error) {
				normalized := strings.Join(strings.Fields(cypher), " ")

				// Must use SET for updates
				assert.Contains(t, normalized, "SET r.status = $status")

				return graph.QueryResult{
					Records: []map[string]any{{"run_id": "test"}},
				}, nil
			},
		}
		manager := NewMissionGraphManager(client)
		_ = manager.UpdateMissionRunStatus(context.Background(), "run-123", "completed")
	})
}
