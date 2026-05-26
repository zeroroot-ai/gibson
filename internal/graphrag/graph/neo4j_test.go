package graph

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/types"
)

func TestGraphClientConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  GraphClientConfig
		wantErr bool
		errCode types.ErrorCode
	}{
		{
			name: "valid config",
			config: GraphClientConfig{
				URI:                     "bolt://localhost:7687",
				Username:                "neo4j",
				Password:                "password",
				ConnectionTimeout:       30 * time.Second,
				MaxTransactionRetryTime: 30 * time.Second,
			},
			wantErr: false,
		},
		{
			name: "empty URI",
			config: GraphClientConfig{
				URI:                     "",
				Username:                "neo4j",
				Password:                "password",
				ConnectionTimeout:       30 * time.Second,
				MaxTransactionRetryTime: 30 * time.Second,
			},
			wantErr: true,
			errCode: ErrCodeGraphInvalidConfig,
		},
		{
			name: "empty username",
			config: GraphClientConfig{
				URI:                     "bolt://localhost:7687",
				Username:                "",
				Password:                "password",
				ConnectionTimeout:       30 * time.Second,
				MaxTransactionRetryTime: 30 * time.Second,
			},
			wantErr: true,
			errCode: ErrCodeGraphInvalidConfig,
		},
		{
			name: "empty password",
			config: GraphClientConfig{
				URI:                     "bolt://localhost:7687",
				Username:                "neo4j",
				Password:                "",
				ConnectionTimeout:       30 * time.Second,
				MaxTransactionRetryTime: 30 * time.Second,
			},
			wantErr: true,
			errCode: ErrCodeGraphInvalidConfig,
		},
		{
			name: "invalid connection timeout",
			config: GraphClientConfig{
				URI:                     "bolt://localhost:7687",
				Username:                "neo4j",
				Password:                "password",
				ConnectionTimeout:       0,
				MaxTransactionRetryTime: 30 * time.Second,
			},
			wantErr: true,
			errCode: ErrCodeGraphInvalidConfig,
		},
		{
			name: "invalid retry timeout",
			config: GraphClientConfig{
				URI:                     "bolt://localhost:7687",
				Username:                "neo4j",
				Password:                "password",
				ConnectionTimeout:       30 * time.Second,
				MaxTransactionRetryTime: -1 * time.Second,
			},
			wantErr: true,
			errCode: ErrCodeGraphInvalidConfig,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()

			if tt.wantErr {
				require.Error(t, err)
				var gibsonErr *types.GibsonError
				if errors.As(err, &gibsonErr) {
					assert.Equal(t, tt.errCode, gibsonErr.Code)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	assert.Equal(t, "bolt://localhost:7687", config.URI)
	assert.Equal(t, "neo4j", config.Username)
	assert.Equal(t, "password", config.Password)
	assert.Equal(t, "", config.Database)
	assert.Equal(t, 50, config.MaxConnectionPoolSize)
	assert.Equal(t, 30*time.Second, config.ConnectionTimeout)
	assert.Equal(t, 30*time.Second, config.MaxTransactionRetryTime)

	// Should be valid
	err := config.Validate()
	require.NoError(t, err)
}

func TestNewNeo4jClient(t *testing.T) {
	t.Run("valid config", func(t *testing.T) {
		config := DefaultConfig()
		client, err := NewNeo4jClient(config)

		require.NoError(t, err)
		require.NotNil(t, client)
		assert.Equal(t, config, client.config)
		assert.Nil(t, client.driver)
	})

	t.Run("invalid config", func(t *testing.T) {
		config := GraphClientConfig{
			URI:      "",
			Username: "neo4j",
			Password: "password",
		}

		client, err := NewNeo4jClient(config)

		require.Error(t, err)
		assert.Nil(t, client)

		var gibsonErr *types.GibsonError
		if errors.As(err, &gibsonErr) {
			assert.Equal(t, ErrCodeGraphInvalidConfig, gibsonErr.Code)
		}
	})
}

func TestQueryResult(t *testing.T) {
	result := QueryResult{
		Records: []map[string]any{
			{"name": "Alice", "age": 30},
			{"name": "Bob", "age": 25},
		},
		Columns: []string{"name", "age"},
		Summary: QuerySummary{
			ExecutionTime:        100 * time.Millisecond,
			NodesCreated:         2,
			NodesDeleted:         0,
			RelationshipsCreated: 1,
			RelationshipsDeleted: 0,
			PropertiesSet:        4,
		},
	}

	assert.Len(t, result.Records, 2)
	assert.Equal(t, []string{"name", "age"}, result.Columns)
	assert.Equal(t, "Alice", result.Records[0]["name"])
	assert.Equal(t, 30, result.Records[0]["age"])
	assert.Equal(t, 100*time.Millisecond, result.Summary.ExecutionTime)
	assert.Equal(t, 2, result.Summary.NodesCreated)
}

// Tests using MockGraphClient to verify Neo4j client behavior without real database

func TestMockGraphClient_Connect(t *testing.T) {
	t.Run("successful connect", func(t *testing.T) {
		mock := NewMockGraphClient()
		ctx := context.Background()

		err := mock.Connect(ctx)

		require.NoError(t, err)
		assert.True(t, mock.IsConnected())
		assert.Equal(t, 1, mock.CallCount())

		calls := mock.GetCallsByMethod("Connect")
		assert.Len(t, calls, 1)
	})

	t.Run("connect error", func(t *testing.T) {
		mock := NewMockGraphClient()
		ctx := context.Background()

		expectedErr := errors.New("connection failed")
		mock.SetConnectError(expectedErr)

		err := mock.Connect(ctx)

		require.Error(t, err)
		assert.Equal(t, expectedErr, err)
		assert.False(t, mock.IsConnected())
	})
}

func TestMockGraphClient_Close(t *testing.T) {
	t.Run("successful close", func(t *testing.T) {
		mock := NewMockGraphClient()
		ctx := context.Background()

		// Connect first
		_ = mock.Connect(ctx)
		assert.True(t, mock.IsConnected())

		err := mock.Close(ctx)

		require.NoError(t, err)
		assert.False(t, mock.IsConnected())

		calls := mock.GetCallsByMethod("Close")
		assert.Len(t, calls, 1)
	})

	t.Run("close error", func(t *testing.T) {
		mock := NewMockGraphClient()
		ctx := context.Background()

		expectedErr := errors.New("close failed")
		mock.SetCloseError(expectedErr)

		err := mock.Close(ctx)

		require.Error(t, err)
		assert.Equal(t, expectedErr, err)
	})
}

func TestMockGraphClient_Health(t *testing.T) {
	t.Run("healthy when connected", func(t *testing.T) {
		mock := NewMockGraphClient()
		ctx := context.Background()

		_ = mock.Connect(ctx)

		status := mock.Health(ctx)

		assert.True(t, status.IsHealthy())
		assert.Equal(t, "mock graph client", status.Message)
	})

	t.Run("unhealthy when not connected", func(t *testing.T) {
		mock := NewMockGraphClient()
		ctx := context.Background()

		status := mock.Health(ctx)

		assert.True(t, status.IsUnhealthy())
		assert.Equal(t, "not connected", status.Message)
	})

	t.Run("custom health status", func(t *testing.T) {
		mock := NewMockGraphClient()
		ctx := context.Background()

		_ = mock.Connect(ctx)
		customStatus := types.Degraded("slow response")
		mock.SetHealthStatus(customStatus)

		status := mock.Health(ctx)

		assert.True(t, status.IsDegraded())
		assert.Equal(t, "slow response", status.Message)
	})
}

func TestMockGraphClient_Query(t *testing.T) {
	t.Run("successful query", func(t *testing.T) {
		mock := NewMockGraphClient()
		ctx := context.Background()

		_ = mock.Connect(ctx)

		expectedResult := QueryResult{
			Records: []map[string]any{
				{"name": "Alice", "age": 30},
			},
			Columns: []string{"name", "age"},
		}
		mock.AddQueryResult(expectedResult)

		result, err := mock.Query(ctx, "MATCH (n:Person) RETURN n", nil)

		require.NoError(t, err)
		assert.Equal(t, expectedResult.Records, result.Records)
		assert.Equal(t, expectedResult.Columns, result.Columns)

		calls := mock.GetCallsByMethod("Query")
		assert.Len(t, calls, 1)
		assert.Equal(t, "MATCH (n:Person) RETURN n", calls[0].Args[0])
	})

	t.Run("query when not connected", func(t *testing.T) {
		mock := NewMockGraphClient()
		ctx := context.Background()

		_, err := mock.Query(ctx, "MATCH (n) RETURN n", nil)

		require.Error(t, err)

		var gibsonErr *types.GibsonError
		if errors.As(err, &gibsonErr) {
			assert.Equal(t, ErrCodeGraphConnectionClosed, gibsonErr.Code)
		}
	})

	t.Run("query error", func(t *testing.T) {
		mock := NewMockGraphClient()
		ctx := context.Background()

		_ = mock.Connect(ctx)

		expectedErr := errors.New("syntax error")
		mock.SetQueryError(expectedErr)

		_, err := mock.Query(ctx, "INVALID QUERY", nil)

		require.Error(t, err)
		assert.Equal(t, expectedErr, err)
	})

	t.Run("multiple query results FIFO", func(t *testing.T) {
		mock := NewMockGraphClient()
		ctx := context.Background()

		_ = mock.Connect(ctx)

		result1 := QueryResult{Records: []map[string]any{{"id": 1}}}
		result2 := QueryResult{Records: []map[string]any{{"id": 2}}}
		mock.SetQueryResults([]QueryResult{result1, result2})

		// First query returns result1
		r1, err := mock.Query(ctx, "QUERY1", nil)
		require.NoError(t, err)
		assert.Equal(t, 1, r1.Records[0]["id"])

		// Second query returns result2
		r2, err := mock.Query(ctx, "QUERY2", nil)
		require.NoError(t, err)
		assert.Equal(t, 2, r2.Records[0]["id"])

		// Third query returns empty result
		r3, err := mock.Query(ctx, "QUERY3", nil)
		require.NoError(t, err)
		assert.Empty(t, r3.Records)
	})
}

func TestMockGraphClient_CreateNode(t *testing.T) {
	t.Run("successful create", func(t *testing.T) {
		mock := NewMockGraphClient()
		ctx := context.Background()

		_ = mock.Connect(ctx)

		labels := []string{"Person", "Employee"}
		props := map[string]any{"name": "Alice", "age": 30}

		nodeID, err := mock.CreateNode(ctx, labels, props)

		require.NoError(t, err)
		assert.NotEmpty(t, nodeID)

		nodes := mock.GetNodes()
		require.Len(t, nodes, 1)

		node := nodes[nodeID]
		assert.Equal(t, labels, node.Labels)
		assert.Equal(t, props, node.Props)

		calls := mock.GetCallsByMethod("CreateNode")
		assert.Len(t, calls, 1)
	})

	t.Run("create when not connected", func(t *testing.T) {
		mock := NewMockGraphClient()
		ctx := context.Background()

		_, err := mock.CreateNode(ctx, []string{"Person"}, map[string]any{})

		require.Error(t, err)

		var gibsonErr *types.GibsonError
		if errors.As(err, &gibsonErr) {
			assert.Equal(t, ErrCodeGraphConnectionClosed, gibsonErr.Code)
		}
	})

	t.Run("create node error", func(t *testing.T) {
		mock := NewMockGraphClient()
		ctx := context.Background()

		_ = mock.Connect(ctx)

		expectedErr := errors.New("constraint violation")
		mock.SetCreateNodeError(expectedErr)

		_, err := mock.CreateNode(ctx, []string{"Person"}, map[string]any{})

		require.Error(t, err)
		assert.Equal(t, expectedErr, err)
	})

	t.Run("multiple nodes get unique IDs", func(t *testing.T) {
		mock := NewMockGraphClient()
		ctx := context.Background()

		_ = mock.Connect(ctx)

		id1, _ := mock.CreateNode(ctx, []string{"Person"}, map[string]any{"name": "Alice"})
		id2, _ := mock.CreateNode(ctx, []string{"Person"}, map[string]any{"name": "Bob"})

		assert.NotEqual(t, id1, id2)

		nodes := mock.GetNodes()
		assert.Len(t, nodes, 2)
	})
}

func TestMockGraphClient_CreateRelationship(t *testing.T) {
	t.Run("successful create", func(t *testing.T) {
		mock := NewMockGraphClient()
		ctx := context.Background()

		_ = mock.Connect(ctx)

		// Create two nodes
		fromID, _ := mock.CreateNode(ctx, []string{"Person"}, map[string]any{"name": "Alice"})
		toID, _ := mock.CreateNode(ctx, []string{"Person"}, map[string]any{"name": "Bob"})

		props := map[string]any{"since": "2020"}
		err := mock.CreateRelationship(ctx, fromID, toID, "KNOWS", props)

		require.NoError(t, err)

		rels := mock.GetRelationships()
		require.Len(t, rels, 1)

		rel := rels[0]
		assert.Equal(t, fromID, rel.FromID)
		assert.Equal(t, toID, rel.ToID)
		assert.Equal(t, "KNOWS", rel.Type)
		assert.Equal(t, props, rel.Props)
	})

	t.Run("create when not connected", func(t *testing.T) {
		mock := NewMockGraphClient()
		ctx := context.Background()

		err := mock.CreateRelationship(ctx, "id1", "id2", "KNOWS", nil)

		require.Error(t, err)

		var gibsonErr *types.GibsonError
		if errors.As(err, &gibsonErr) {
			assert.Equal(t, ErrCodeGraphConnectionClosed, gibsonErr.Code)
		}
	})

	t.Run("create relationship error", func(t *testing.T) {
		mock := NewMockGraphClient()
		ctx := context.Background()

		_ = mock.Connect(ctx)

		expectedErr := errors.New("relationship failed")
		mock.SetCreateRelationshipError(expectedErr)

		fromID, _ := mock.CreateNode(ctx, []string{"Person"}, map[string]any{})
		toID, _ := mock.CreateNode(ctx, []string{"Person"}, map[string]any{})

		err := mock.CreateRelationship(ctx, fromID, toID, "KNOWS", nil)

		require.Error(t, err)
		assert.Equal(t, expectedErr, err)
	})

	t.Run("from node not found", func(t *testing.T) {
		mock := NewMockGraphClient()
		ctx := context.Background()

		_ = mock.Connect(ctx)

		toID, _ := mock.CreateNode(ctx, []string{"Person"}, map[string]any{})

		err := mock.CreateRelationship(ctx, "invalid-id", toID, "KNOWS", nil)

		require.Error(t, err)

		var gibsonErr *types.GibsonError
		if errors.As(err, &gibsonErr) {
			assert.Equal(t, ErrCodeGraphNodeNotFound, gibsonErr.Code)
		}
	})

	t.Run("to node not found", func(t *testing.T) {
		mock := NewMockGraphClient()
		ctx := context.Background()

		_ = mock.Connect(ctx)

		fromID, _ := mock.CreateNode(ctx, []string{"Person"}, map[string]any{})

		err := mock.CreateRelationship(ctx, fromID, "invalid-id", "KNOWS", nil)

		require.Error(t, err)

		var gibsonErr *types.GibsonError
		if errors.As(err, &gibsonErr) {
			assert.Equal(t, ErrCodeGraphNodeNotFound, gibsonErr.Code)
		}
	})
}

func TestMockGraphClient_DeleteNode(t *testing.T) {
	t.Run("successful delete", func(t *testing.T) {
		mock := NewMockGraphClient()
		ctx := context.Background()

		_ = mock.Connect(ctx)

		nodeID, _ := mock.CreateNode(ctx, []string{"Person"}, map[string]any{"name": "Alice"})

		err := mock.DeleteNode(ctx, nodeID)

		require.NoError(t, err)

		nodes := mock.GetNodes()
		assert.Len(t, nodes, 0)
	})

	t.Run("delete when not connected", func(t *testing.T) {
		mock := NewMockGraphClient()
		ctx := context.Background()

		err := mock.DeleteNode(ctx, "node-id")

		require.Error(t, err)

		var gibsonErr *types.GibsonError
		if errors.As(err, &gibsonErr) {
			assert.Equal(t, ErrCodeGraphConnectionClosed, gibsonErr.Code)
		}
	})

	t.Run("delete node error", func(t *testing.T) {
		mock := NewMockGraphClient()
		ctx := context.Background()

		_ = mock.Connect(ctx)

		nodeID, _ := mock.CreateNode(ctx, []string{"Person"}, map[string]any{})

		expectedErr := errors.New("delete failed")
		mock.SetDeleteNodeError(expectedErr)

		err := mock.DeleteNode(ctx, nodeID)

		require.Error(t, err)
		assert.Equal(t, expectedErr, err)
	})

	t.Run("node not found", func(t *testing.T) {
		mock := NewMockGraphClient()
		ctx := context.Background()

		_ = mock.Connect(ctx)

		err := mock.DeleteNode(ctx, "invalid-id")

		require.Error(t, err)

		var gibsonErr *types.GibsonError
		if errors.As(err, &gibsonErr) {
			assert.Equal(t, ErrCodeGraphNodeNotFound, gibsonErr.Code)
		}
	})

	t.Run("deletes associated relationships", func(t *testing.T) {
		mock := NewMockGraphClient()
		ctx := context.Background()

		_ = mock.Connect(ctx)

		// Create nodes and relationship
		id1, _ := mock.CreateNode(ctx, []string{"Person"}, map[string]any{"name": "Alice"})
		id2, _ := mock.CreateNode(ctx, []string{"Person"}, map[string]any{"name": "Bob"})
		_ = mock.CreateRelationship(ctx, id1, id2, "KNOWS", nil)

		assert.Len(t, mock.GetRelationships(), 1)

		// Delete first node
		err := mock.DeleteNode(ctx, id1)

		require.NoError(t, err)
		assert.Len(t, mock.GetNodes(), 1)
		assert.Len(t, mock.GetRelationships(), 0) // Relationship should be deleted
	})
}

func TestMockGraphClient_Reset(t *testing.T) {
	mock := NewMockGraphClient()
	ctx := context.Background()

	// Populate the mock
	_ = mock.Connect(ctx)
	_, _ = mock.CreateNode(ctx, []string{"Person"}, map[string]any{"name": "Alice"})
	mock.SetQueryError(errors.New("test error"))
	mock.SetHealthStatus(types.Degraded("slow"))

	assert.True(t, mock.IsConnected())
	assert.NotEmpty(t, mock.GetNodes())
	assert.Greater(t, mock.CallCount(), 0)

	// Reset
	mock.Reset()

	// Verify everything is cleared
	assert.False(t, mock.IsConnected())
	assert.Empty(t, mock.GetNodes())
	assert.Empty(t, mock.GetRelationships())
	assert.Equal(t, 0, mock.CallCount())

	// Should be able to use after reset
	_ = mock.Connect(ctx)
	status := mock.Health(ctx)
	assert.True(t, status.IsHealthy())
}

func TestMockGraphClient_CallTracking(t *testing.T) {
	mock := NewMockGraphClient()
	ctx := context.Background()

	_ = mock.Connect(ctx)
	_ = mock.Health(ctx)
	_, _ = mock.Query(ctx, "MATCH (n) RETURN n", nil)
	_, _ = mock.CreateNode(ctx, []string{"Person"}, map[string]any{})

	assert.Equal(t, 4, mock.CallCount())

	connectCalls := mock.GetCallsByMethod("Connect")
	assert.Len(t, connectCalls, 1)

	healthCalls := mock.GetCallsByMethod("Health")
	assert.Len(t, healthCalls, 1)

	queryCalls := mock.GetCallsByMethod("Query")
	assert.Len(t, queryCalls, 1)
	assert.Equal(t, "MATCH (n) RETURN n", queryCalls[0].Args[0])

	createCalls := mock.GetCallsByMethod("CreateNode")
	assert.Len(t, createCalls, 1)

	allCalls := mock.GetCalls()
	assert.Len(t, allCalls, 4)

	// Verify timestamps are set
	for _, call := range allCalls {
		assert.False(t, call.Timestamp.IsZero())
	}
}
