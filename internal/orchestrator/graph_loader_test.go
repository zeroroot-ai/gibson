package orchestrator

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zero-day-ai/gibson/internal/graphrag/graph"
	"github.com/zero-day-ai/gibson/internal/mission"
	"github.com/zero-day-ai/gibson/internal/types"
	missionv1 "github.com/zero-day-ai/sdk/api/gen/gibson/mission/v1"
)

// mustProto converts a mirror MissionDefinition fixture to its proto
// equivalent for tests. Failures fail the test outright. Tests still
// author fixtures with the mirror struct because PR3 keeps the mirror
// alive for daemon callers; PR4 retypes both the daemon callers and
// these fixtures simultaneously.
func mustProto(t *testing.T, def *mission.MissionDefinition) *missionv1.MissionDefinition {
	t.Helper()
	if def == nil {
		return nil
	}
	out, err := mission.MirrorToProto(def)
	if err != nil {
		t.Fatalf("mirror→proto: %v", err)
	}
	return out
}

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

// TestNewGraphLoader tests the constructor
func TestNewGraphLoader(t *testing.T) {
	client := &mockGraphClient{}
	loader := NewGraphLoader(client, nil)

	require.NotNil(t, loader)
	assert.Equal(t, client, loader.graphClient)
	assert.NotNil(t, loader.logger)
}

// TestLoadMission_Success tests successful mission definition storage
func TestLoadMission_Success(t *testing.T) {
	tests := []struct {
		name         string
		def          *mission.MissionDefinition
		definitionID string
		setupMock    func(t *testing.T) *mockGraphClient
	}{
		{
			name: "stores new mission definition",
			def: &mission.MissionDefinition{
				Name:        "test-mission",
				Description: "A test mission",
				Version:     "1.0.0",
				TargetRef:   "target-123",
				Nodes: map[string]*mission.MissionNode{
					"node1": {ID: "node1", Type: mission.NodeTypeAgent, AgentName: "recon"},
				},
				Edges: []mission.MissionEdge{
					{From: "node1", To: "node2"},
				},
			},
			definitionID: "def-123",
			setupMock: func(t *testing.T) *mockGraphClient {
				return &mockGraphClient{
					queryFunc: func(ctx context.Context, cypher string, params map[string]any) (graph.QueryResult, error) {
						// Verify MERGE by hash
						assert.Contains(t, cypher, "MERGE (md:mission_definition {definition_hash: $hash})")
						assert.Contains(t, cypher, "ON CREATE SET")

						// Verify parameters
						assert.Equal(t, "test-mission", params["name"])
						assert.Equal(t, "A test mission", params["description"])
						assert.Equal(t, "1.0.0", params["version"])
						assert.Equal(t, "target-123", params["target_ref"])
						assert.NotEmpty(t, params["hash"])
						assert.NotEmpty(t, params["nodes_json"])
						assert.NotEmpty(t, params["edges_json"])

						return graph.QueryResult{
							Records: []map[string]any{
								{"definition_id": "def-123"},
							},
						}, nil
					},
				}
			},
		},
		{
			name: "returns existing definition for same content",
			def: &mission.MissionDefinition{
				Name:      "existing-mission",
				TargetRef: "target-456",
			},
			definitionID: "existing-def-456",
			setupMock: func(t *testing.T) *mockGraphClient {
				return &mockGraphClient{
					queryFunc: func(ctx context.Context, cypher string, params map[string]any) (graph.QueryResult, error) {
						// Return existing definition ID
						return graph.QueryResult{
							Records: []map[string]any{
								{"definition_id": "existing-def-456"},
							},
						}, nil
					},
				}
			},
		},
		{
			name: "handles nil nodes and edges",
			def: &mission.MissionDefinition{
				Name:      "minimal-mission",
				TargetRef: "target-789",
				Nodes:     nil,
				Edges:     nil,
			},
			definitionID: "def-minimal",
			setupMock: func(t *testing.T) *mockGraphClient {
				return &mockGraphClient{
					queryFunc: func(ctx context.Context, cypher string, params map[string]any) (graph.QueryResult, error) {
						// Verify nil is serialized as null
						assert.Equal(t, "null", params["nodes_json"])
						assert.Equal(t, "null", params["edges_json"])

						return graph.QueryResult{
							Records: []map[string]any{
								{"definition_id": "def-minimal"},
							},
						}, nil
					},
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := tt.setupMock(t)
			loader := NewGraphLoader(client, nil)

			definitionID, err := loader.LoadMission(context.Background(), mustProto(t, tt.def))

			require.NoError(t, err)
			assert.Equal(t, tt.definitionID, definitionID)
		})
	}
}

// TestLoadMission_ValidationErrors tests input validation
func TestLoadMission_ValidationErrors(t *testing.T) {
	tests := []struct {
		name    string
		loader  *GraphLoader
		def     *mission.MissionDefinition
		wantErr string
	}{
		{
			name:    "nil client",
			loader:  NewGraphLoader(nil, nil),
			def:     &mission.MissionDefinition{Name: "test"},
			wantErr: "graph client is nil",
		},
		{
			name:    "nil definition",
			loader:  NewGraphLoader(&mockGraphClient{}, nil),
			def:     nil,
			wantErr: "mission definition cannot be nil",
		},
		{
			name:    "empty name",
			loader:  NewGraphLoader(&mockGraphClient{}, nil),
			def:     &mission.MissionDefinition{Name: ""},
			wantErr: "mission definition name cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.loader.LoadMission(context.Background(), mustProto(t, tt.def))

			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

// TestLoadMission_QueryErrors tests error handling during query execution
func TestLoadMission_QueryErrors(t *testing.T) {
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
			wantErr: "failed to store mission definition",
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
			name: "invalid definition_id type",
			setupMock: func() *mockGraphClient {
				return &mockGraphClient{
					queryFunc: func(ctx context.Context, cypher string, params map[string]any) (graph.QueryResult, error) {
						return graph.QueryResult{
							Records: []map[string]any{
								{"definition_id": 123}, // Invalid: should be string
							},
						}, nil
					},
				}
			},
			wantErr: "definition_id has invalid type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := tt.setupMock()
			loader := NewGraphLoader(client, nil)

			def := &mission.MissionDefinition{
				Name:      "test-mission",
				TargetRef: "target-123",
			}

			_, err := loader.LoadMission(context.Background(), mustProto(t, def))

			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

// TestLoadMission_Deduplication tests that identical definitions produce the same hash
func TestLoadMission_Deduplication(t *testing.T) {
	var capturedHashes []string

	client := &mockGraphClient{
		queryFunc: func(ctx context.Context, cypher string, params map[string]any) (graph.QueryResult, error) {
			hash, ok := params["hash"].(string)
			require.True(t, ok)
			capturedHashes = append(capturedHashes, hash)

			return graph.QueryResult{
				Records: []map[string]any{
					{"definition_id": "def-123"},
				},
			}, nil
		},
	}

	loader := NewGraphLoader(client, nil)

	// Create two identical definitions
	def1 := &mission.MissionDefinition{
		Name:        "recon-mission",
		Description: "Reconnaissance mission",
		Version:     "1.0.0",
		TargetRef:   "target-abc",
		Nodes: map[string]*mission.MissionNode{
			"scan": {ID: "scan", Type: mission.NodeTypeAgent, AgentName: "nmap-scanner"},
		},
	}

	def2 := &mission.MissionDefinition{
		Name:        "recon-mission",
		Description: "Reconnaissance mission",
		Version:     "1.0.0",
		TargetRef:   "target-abc",
		Nodes: map[string]*mission.MissionNode{
			"scan": {ID: "scan", Type: mission.NodeTypeAgent, AgentName: "nmap-scanner"},
		},
	}

	// Load both definitions
	_, err := loader.LoadMission(context.Background(), mustProto(t, def1))
	require.NoError(t, err)

	_, err = loader.LoadMission(context.Background(), mustProto(t, def2))
	require.NoError(t, err)

	// Verify same hash was produced for identical content
	require.Len(t, capturedHashes, 2)
	assert.Equal(t, capturedHashes[0], capturedHashes[1], "identical definitions should produce same hash")
}

// TestLoadMission_DifferentDefinitions tests that different definitions produce different hashes
func TestLoadMission_DifferentDefinitions(t *testing.T) {
	var capturedHashes []string

	client := &mockGraphClient{
		queryFunc: func(ctx context.Context, cypher string, params map[string]any) (graph.QueryResult, error) {
			hash, ok := params["hash"].(string)
			require.True(t, ok)
			capturedHashes = append(capturedHashes, hash)

			return graph.QueryResult{
				Records: []map[string]any{
					{"definition_id": "def-123"},
				},
			}, nil
		},
	}

	loader := NewGraphLoader(client, nil)

	// Create two different definitions
	def1 := &mission.MissionDefinition{
		Name:    "recon-mission",
		Version: "1.0.0",
	}

	def2 := &mission.MissionDefinition{
		Name:    "recon-mission",
		Version: "2.0.0", // Different version
	}

	_, err := loader.LoadMission(context.Background(), mustProto(t, def1))
	require.NoError(t, err)

	_, err = loader.LoadMission(context.Background(), mustProto(t, def2))
	require.NoError(t, err)

	// Verify different hashes
	require.Len(t, capturedHashes, 2)
	assert.NotEqual(t, capturedHashes[0], capturedHashes[1], "different definitions should produce different hashes")
}

// TestGraphLoader_CypherQueries verifies exact Cypher query generation
func TestGraphLoader_CypherQueries(t *testing.T) {
	t.Run("uses MERGE by hash for deduplication", func(t *testing.T) {
		client := &mockGraphClient{
			queryFunc: func(ctx context.Context, cypher string, params map[string]any) (graph.QueryResult, error) {
				normalized := strings.Join(strings.Fields(cypher), " ")

				// Must use MERGE by hash
				assert.Contains(t, normalized, "MERGE (md:mission_definition {definition_hash: $hash})")

				return graph.QueryResult{
					Records: []map[string]any{{"definition_id": "test"}},
				}, nil
			},
		}
		loader := NewGraphLoader(client, nil)
		_, _ = loader.LoadMission(context.Background(), mustProto(t, &mission.MissionDefinition{Name: "test"}))
	})

	t.Run("creates DEFINES relationship to Mission node", func(t *testing.T) {
		client := &mockGraphClient{
			queryFunc: func(ctx context.Context, cypher string, params map[string]any) (graph.QueryResult, error) {
				normalized := strings.Join(strings.Fields(cypher), " ")

				// Must link to Mission node
				assert.Contains(t, normalized, "OPTIONAL MATCH (m:mission {name: $name, target_id: $target_ref})")
				assert.Contains(t, normalized, "MERGE (md)-[:DEFINES]->(m)")

				return graph.QueryResult{
					Records: []map[string]any{{"definition_id": "test"}},
				}, nil
			},
		}
		loader := NewGraphLoader(client, nil)
		_, _ = loader.LoadMission(context.Background(), mustProto(t, &mission.MissionDefinition{Name: "test", TargetRef: "target"}))
	})

	t.Run("stores all definition properties", func(t *testing.T) {
		client := &mockGraphClient{
			queryFunc: func(ctx context.Context, cypher string, params map[string]any) (graph.QueryResult, error) {
				normalized := strings.Join(strings.Fields(cypher), " ")

				// Verify all properties are set
				assert.Contains(t, normalized, "md.name = $name")
				assert.Contains(t, normalized, "md.description = $description")
				assert.Contains(t, normalized, "md.version = $version")
				assert.Contains(t, normalized, "md.target_ref = $target_ref")
				assert.Contains(t, normalized, "md.nodes_json = $nodes_json")
				assert.Contains(t, normalized, "md.edges_json = $edges_json")
				assert.Contains(t, normalized, "md.metadata_json = $metadata_json")
				assert.Contains(t, normalized, "md.created_at = timestamp()")

				return graph.QueryResult{
					Records: []map[string]any{{"definition_id": "test"}},
				}, nil
			},
		}
		loader := NewGraphLoader(client, nil)
		_, _ = loader.LoadMission(context.Background(), mustProto(t, &mission.MissionDefinition{Name: "test"}))
	})
}

// TestComputeDefinitionHash tests the hash computation
func TestComputeDefinitionHash(t *testing.T) {
	loader := NewGraphLoader(&mockGraphClient{}, nil)

	t.Run("produces consistent hash for same content", func(t *testing.T) {
		def := &mission.MissionDefinition{
			Name:        "test",
			Description: "desc",
			Version:     "1.0.0",
		}

		hash1, err := loader.computeDefinitionHash(mustProto(t, def))
		require.NoError(t, err)

		hash2, err := loader.computeDefinitionHash(mustProto(t, def))
		require.NoError(t, err)

		assert.Equal(t, hash1, hash2)
	})

	t.Run("produces different hash for different content", func(t *testing.T) {
		def1 := &mission.MissionDefinition{Name: "test1"}
		def2 := &mission.MissionDefinition{Name: "test2"}

		hash1, err := loader.computeDefinitionHash(mustProto(t, def1))
		require.NoError(t, err)

		hash2, err := loader.computeDefinitionHash(mustProto(t, def2))
		require.NoError(t, err)

		assert.NotEqual(t, hash1, hash2)
	})

	t.Run("ignores ID and timestamps in hash", func(t *testing.T) {
		def1 := &mission.MissionDefinition{
			ID:   types.NewID(),
			Name: "test",
		}
		def2 := &mission.MissionDefinition{
			ID:   types.NewID(), // Different ID
			Name: "test",
		}

		hash1, err := loader.computeDefinitionHash(mustProto(t, def1))
		require.NoError(t, err)

		hash2, err := loader.computeDefinitionHash(mustProto(t, def2))
		require.NoError(t, err)

		assert.Equal(t, hash1, hash2, "hash should ignore ID field")
	})

	t.Run("hash is valid hex string", func(t *testing.T) {
		def := &mission.MissionDefinition{Name: "test"}

		hash, err := loader.computeDefinitionHash(mustProto(t, def))
		require.NoError(t, err)

		// SHA256 produces 64 hex characters
		assert.Len(t, hash, 64)
		assert.Regexp(t, "^[0-9a-f]+$", hash)
	})
}
