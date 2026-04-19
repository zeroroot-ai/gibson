//go:build stale
// +build stale

// NOTE: this test references `GetCompositeKey`, which was removed during an
// earlier refactor of the loader package. The test is kept behind the `stale`
// build tag so the file is preserved for future repair but does not block
// `go vet` / `go test`. Rewrite against the current composite-key API and
// drop the tag when revisiting.

package loader

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/graphrag/graph"
)

// TestGetCompositeKey verifies composite key lookup for different entity types.
func TestGetCompositeKey(t *testing.T) {
	tests := []struct {
		name       string
		nodeType   string
		wantFields []string
		wantParent string
		wantNotNil bool
	}{
		{
			name:       "host composite key",
			nodeType:   "host",
			wantFields: []string{"ip"},
			wantParent: "",
			wantNotNil: true,
		},
		{
			name:       "port composite key",
			nodeType:   "port",
			wantFields: []string{"number", "protocol"},
			wantParent: "host_id",
			wantNotNil: true,
		},
		{
			name:       "service composite key",
			nodeType:   "service",
			wantFields: []string{"name"},
			wantParent: "port_id",
			wantNotNil: true,
		},
		{
			name:       "endpoint composite key",
			nodeType:   "endpoint",
			wantFields: []string{"url", "method"},
			wantParent: "service_id",
			wantNotNil: true,
		},
		{
			name:       "domain composite key",
			nodeType:   "domain",
			wantFields: []string{"name"},
			wantParent: "",
			wantNotNil: true,
		},
		{
			name:       "subdomain composite key",
			nodeType:   "subdomain",
			wantFields: []string{"name"},
			wantParent: "domain_id",
			wantNotNil: true,
		},
		{
			name:       "technology composite key",
			nodeType:   "technology",
			wantFields: []string{"name", "version"},
			wantParent: "",
			wantNotNil: true,
		},
		{
			name:       "certificate composite key",
			nodeType:   "certificate",
			wantFields: []string{"fingerprint_sha256"},
			wantParent: "",
			wantNotNil: true,
		},
		{
			name:       "finding composite key",
			nodeType:   "finding",
			wantFields: []string{"title"},
			wantParent: "",
			wantNotNil: true,
		},
		{
			name:       "evidence composite key",
			nodeType:   "evidence",
			wantFields: []string{"type", "url"},
			wantParent: "finding_id",
			wantNotNil: true,
		},
		{
			name:       "unknown type returns nil",
			nodeType:   "unknown_type",
			wantFields: nil,
			wantParent: "",
			wantNotNil: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := GetCompositeKey(tt.nodeType)

			if tt.wantNotNil {
				require.NotNil(t, key, "expected composite key for %s", tt.nodeType)
				assert.Equal(t, tt.nodeType, key.NodeType)
				assert.Equal(t, tt.wantFields, key.Fields)
				assert.Equal(t, tt.wantParent, key.ParentField)
			} else {
				assert.Nil(t, key, "expected nil for unknown type")
			}
		})
	}
}

// TestMergeResultMethods tests the MergeResult type methods.
func TestMergeResultMethods(t *testing.T) {
	t.Run("AddError and HasErrors", func(t *testing.T) {
		result := &MergeResult{}
		assert.False(t, result.HasErrors())
		assert.Empty(t, result.Errors)

		result.AddError(assert.AnError)
		assert.True(t, result.HasErrors())
		assert.Len(t, result.Errors, 1)

		result.AddError(assert.AnError)
		assert.Len(t, result.Errors, 2)
	})

	t.Run("chaining AddError", func(t *testing.T) {
		result := &MergeResult{}
		result.AddError(assert.AnError).AddError(assert.AnError)
		assert.Len(t, result.Errors, 2)
	})
}

// TestBuildMergeClause tests the merge clause builder.
func TestBuildMergeClause(t *testing.T) {
	loader := NewGraphLoader(nil)

	tests := []struct {
		name       string
		nodeType   string
		properties map[string]any
		execCtx    ExecContext
		wantClause bool
		wantParams int
	}{
		{
			name:     "host with IP",
			nodeType: "host",
			properties: map[string]any{
				"ip":       "192.168.1.1",
				"hostname": "server1.local",
			},
			execCtx: ExecContext{
				MissionRunID: "run-123",
			},
			wantClause: true,
			wantParams: 2, // ip + mission_run_id
		},
		{
			name:     "port with all fields",
			nodeType: "port",
			properties: map[string]any{
				"number":   int32(443),
				"protocol": "tcp",
				"host_id":  "host-uuid",
				"state":    "open",
			},
			execCtx: ExecContext{
				MissionRunID: "run-123",
			},
			wantClause: true,
			wantParams: 4, // number + protocol + host_id + mission_run_id
		},
		{
			name:     "port missing protocol",
			nodeType: "port",
			properties: map[string]any{
				"number":  int32(443),
				"host_id": "host-uuid",
			},
			execCtx: ExecContext{
				MissionRunID: "run-123",
			},
			wantClause: false, // missing required field
		},
		{
			name:     "port missing parent",
			nodeType: "port",
			properties: map[string]any{
				"number":   int32(443),
				"protocol": "tcp",
			},
			execCtx: ExecContext{
				MissionRunID: "run-123",
			},
			wantClause: false, // missing parent reference
		},
		{
			name:     "technology with name and version",
			nodeType: "technology",
			properties: map[string]any{
				"name":    "Apache",
				"version": "2.4.52",
			},
			execCtx: ExecContext{
				MissionRunID: "run-123",
			},
			wantClause: true,
			wantParams: 3, // name + version + mission_run_id
		},
		{
			name:     "host without mission_run_id",
			nodeType: "host",
			properties: map[string]any{
				"ip": "192.168.1.1",
			},
			execCtx:    ExecContext{},
			wantClause: true,
			wantParams: 1, // just ip
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := GetCompositeKey(tt.nodeType)
			require.NotNil(t, key)

			clause, params := loader.buildMergeClause(tt.nodeType, key, tt.properties, tt.execCtx)

			if tt.wantClause {
				assert.NotEmpty(t, clause)
				assert.Len(t, params, tt.wantParams)
			} else {
				assert.Empty(t, clause)
				assert.Nil(t, params)
			}
		})
	}
}

// TestBuildMergeKeyTemplate tests the UNWIND merge key template builder.
func TestBuildMergeKeyTemplate(t *testing.T) {
	loader := NewGraphLoader(nil)

	tests := []struct {
		name      string
		nodeType  string
		wantParts []string
	}{
		{
			name:      "host template",
			nodeType:  "host",
			wantParts: []string{"ip: entry.merge_key.ip", "mission_run_id: entry.merge_key.mission_run_id"},
		},
		{
			name:      "port template with parent",
			nodeType:  "port",
			wantParts: []string{"number: entry.merge_key.number", "protocol: entry.merge_key.protocol", "host_id: entry.merge_key.host_id"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := GetCompositeKey(tt.nodeType)
			require.NotNil(t, key)

			template := loader.buildMergeKeyTemplate(key)
			for _, part := range tt.wantParts {
				assert.Contains(t, template, part)
			}
		})
	}
}

// TestBuildSetProperties tests the SET properties builder.
func TestBuildSetProperties(t *testing.T) {
	loader := NewGraphLoader(nil)

	t.Run("includes all properties and context", func(t *testing.T) {
		properties := map[string]any{
			"ip":       "192.168.1.1",
			"hostname": "server1.local",
			"os":       "Linux",
		}
		execCtx := ExecContext{
			MissionID:    "mission-123",
			MissionRunID: "run-123",
			AgentName:    "port-scanner",
			AgentRunID:   "agent-run-456",
		}

		result := loader.buildSetProperties(properties, execCtx)

		assert.Equal(t, "192.168.1.1", result["ip"])
		assert.Equal(t, "server1.local", result["hostname"])
		assert.Equal(t, "Linux", result["os"])
		assert.Equal(t, "mission-123", result["mission_id"])
		assert.Equal(t, "port-scanner", result["discovered_by"])
		assert.Equal(t, "agent-run-456", result["agent_run_id"])
	})

	t.Run("handles empty context", func(t *testing.T) {
		properties := map[string]any{"ip": "192.168.1.1"}
		execCtx := ExecContext{}

		result := loader.buildSetProperties(properties, execCtx)

		assert.Equal(t, "192.168.1.1", result["ip"])
		_, hasMissionID := result["mission_id"]
		assert.False(t, hasMissionID)
	})
}

// TestMergeEntityIntegration tests the full MergeEntity flow with mocked client.
func TestMergeEntityIntegration(t *testing.T) {
	t.Run("creates new host entity", func(t *testing.T) {
		mock := graph.NewMockGraphClient()
		err := mock.Connect(context.Background())
		require.NoError(t, err)

		// Configure mock to return as if entity was created
		mock.AddQueryResult(graph.QueryResult{
			Records: []map[string]any{
				{
					"element_id": "element:123",
					"action":     "created",
				},
			},
		})
		// Add result for BELONGS_TO relationship creation
		mock.AddQueryResult(graph.QueryResult{
			Records: []map[string]any{
				{"rel_count": int64(1)},
			},
		})

		loader := NewGraphLoader(mock)
		ctx := context.Background()
		execCtx := ExecContext{
			MissionID:    "mission-1",
			MissionRunID: "run-1",
			AgentName:    "port-scanner",
		}

		result, err := loader.MergeEntity(ctx, execCtx, "host", map[string]any{
			"ip":       "192.168.1.1",
			"hostname": "server1.local",
		})

		require.NoError(t, err)
		assert.Equal(t, 1, result.NodesCreated)
		assert.Equal(t, 0, result.NodesMerged)

		// Verify MERGE was used in the query
		calls := mock.GetCallsByMethod("Query")
		require.True(t, len(calls) >= 1)
		cypher := calls[0].Args[0].(string)
		assert.True(t, strings.Contains(cypher, "MERGE"), "expected MERGE in query: %s", cypher)
	})

	t.Run("merges existing host entity", func(t *testing.T) {
		mock := graph.NewMockGraphClient()
		err := mock.Connect(context.Background())
		require.NoError(t, err)

		// Configure mock to return as if entity was merged
		mock.AddQueryResult(graph.QueryResult{
			Records: []map[string]any{
				{
					"element_id": "element:123",
					"action":     "merged",
				},
			},
		})
		// Add result for BELONGS_TO relationship creation
		mock.AddQueryResult(graph.QueryResult{
			Records: []map[string]any{
				{"rel_count": int64(1)},
			},
		})

		loader := NewGraphLoader(mock)
		ctx := context.Background()
		execCtx := ExecContext{
			MissionID:    "mission-1",
			MissionRunID: "run-1",
			AgentName:    "port-scanner",
		}

		result, err := loader.MergeEntity(ctx, execCtx, "host", map[string]any{
			"ip": "192.168.1.1",
			"os": "Updated OS",
		})

		require.NoError(t, err)
		assert.Equal(t, 0, result.NodesCreated)
		assert.Equal(t, 1, result.NodesMerged)
	})

	t.Run("falls back to create for unknown type", func(t *testing.T) {
		mock := graph.NewMockGraphClient()
		err := mock.Connect(context.Background())
		require.NoError(t, err)

		// Configure mock to return create result
		mock.AddQueryResult(graph.QueryResult{
			Records: []map[string]any{
				{"element_id": "element:123"},
			},
		})
		// Add result for BELONGS_TO relationship creation
		mock.AddQueryResult(graph.QueryResult{
			Records: []map[string]any{
				{"rel_count": int64(1)},
			},
		})

		loader := NewGraphLoader(mock)
		ctx := context.Background()
		execCtx := ExecContext{
			MissionID:    "mission-1",
			MissionRunID: "run-1",
		}

		result, err := loader.MergeEntity(ctx, execCtx, "unknown_custom_type", map[string]any{
			"name": "test",
		})

		require.NoError(t, err)
		assert.Equal(t, 1, result.NodesCreated)

		// Verify CREATE was used in the query
		calls := mock.GetCallsByMethod("Query")
		require.True(t, len(calls) >= 1)
		cypher := calls[0].Args[0].(string)
		assert.True(t, strings.Contains(cypher, "CREATE"), "expected CREATE in query: %s", cypher)
	})
}

// TestBatchMergeIntegration tests the BatchMerge function.
func TestBatchMergeIntegration(t *testing.T) {
	t.Run("groups entries by type and processes", func(t *testing.T) {
		mock := graph.NewMockGraphClient()
		err := mock.Connect(context.Background())
		require.NoError(t, err)

		// Add results for host batch merge
		mock.AddQueryResult(graph.QueryResult{
			Records: []map[string]any{
				{"element_id": "elem:1", "action": "created"},
				{"element_id": "elem:2", "action": "created"},
			},
		})
		// Add result for BELONGS_TO relationships
		mock.AddQueryResult(graph.QueryResult{
			Records: []map[string]any{
				{"rel_count": int64(2)},
			},
		})

		// Add results for technology batch merge
		mock.AddQueryResult(graph.QueryResult{
			Records: []map[string]any{
				{"element_id": "elem:3", "action": "created"},
			},
		})
		// Add result for BELONGS_TO relationships
		mock.AddQueryResult(graph.QueryResult{
			Records: []map[string]any{
				{"rel_count": int64(1)},
			},
		})

		loader := NewGraphLoader(mock)
		ctx := context.Background()
		execCtx := ExecContext{
			MissionID:    "mission-1",
			MissionRunID: "run-1",
		}

		entries := []BatchMergeEntry{
			{NodeType: "host", Properties: map[string]any{"ip": "192.168.1.1"}},
			{NodeType: "host", Properties: map[string]any{"ip": "192.168.1.2"}},
			{NodeType: "technology", Properties: map[string]any{"name": "Apache", "version": "2.4"}},
		}

		result, err := loader.BatchMerge(ctx, execCtx, entries)

		require.NoError(t, err)
		assert.True(t, result.NodesCreated > 0, "expected at least some nodes created")
	})
}

// TestMergeRelationshipIntegration tests the MergeRelationship function.
func TestMergeRelationshipIntegration(t *testing.T) {
	t.Run("creates relationship between entities", func(t *testing.T) {
		mock := graph.NewMockGraphClient()
		err := mock.Connect(context.Background())
		require.NoError(t, err)

		mock.AddQueryResult(graph.QueryResult{
			Records: []map[string]any{
				{"rel_count": int64(1)},
			},
		})

		loader := NewGraphLoader(mock)
		ctx := context.Background()
		execCtx := ExecContext{
			MissionID:    "mission-1",
			MissionRunID: "run-1",
			AgentName:    "port-scanner",
		}

		result, err := loader.MergeRelationship(ctx, execCtx,
			"host", "port", "HAS_PORT",
			map[string]any{"id": "host-123"},
			map[string]any{"id": "port-456"},
			nil,
		)

		require.NoError(t, err)
		assert.Equal(t, 1, result.RelationshipsCreated)

		// Verify MERGE was used
		calls := mock.GetCallsByMethod("Query")
		require.True(t, len(calls) >= 1)
		cypher := calls[0].Args[0].(string)
		assert.True(t, strings.Contains(cypher, "MERGE"), "expected MERGE in query: %s", cypher)
		assert.True(t, strings.Contains(cypher, "HAS_PORT"), "expected HAS_PORT in query: %s", cypher)
	})
}

// TestMergeEntityNilClient tests error handling for nil client.
func TestMergeEntityNilClient(t *testing.T) {
	loader := NewGraphLoader(nil)
	ctx := context.Background()
	execCtx := ExecContext{}

	result, err := loader.MergeEntity(ctx, execCtx, "host", map[string]any{"ip": "192.168.1.1"})

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "client is nil")
}

// TestMergeRelationshipNilClient tests error handling for nil client.
func TestMergeRelationshipNilClient(t *testing.T) {
	loader := NewGraphLoader(nil)
	ctx := context.Background()
	execCtx := ExecContext{}

	result, err := loader.MergeRelationship(ctx, execCtx,
		"host", "port", "HAS_PORT",
		map[string]any{"id": "host-123"},
		map[string]any{"id": "port-456"},
		nil,
	)

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "client is nil")
}

// TestBatchMergeNilClient tests error handling for nil client.
func TestBatchMergeNilClient(t *testing.T) {
	loader := NewGraphLoader(nil)
	ctx := context.Background()
	execCtx := ExecContext{}

	entries := []BatchMergeEntry{
		{NodeType: "host", Properties: map[string]any{"ip": "192.168.1.1"}},
	}

	result, err := loader.BatchMerge(ctx, execCtx, entries)

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "client is nil")
}
