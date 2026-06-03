package state

import (
	"context"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIndexManager_EnsureIndex(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	ctx := context.Background()
	client := setupTestRedis(t)
	defer client.Close()

	manager := NewIndexManager(client)

	// Clean up any existing test indexes
	defer func() {
		_ = manager.DropIndex(ctx, "test:idx:sample")
	}()

	t.Run("creates new index", func(t *testing.T) {
		// Drop index if it exists from previous test
		_ = manager.DropIndex(ctx, "test:idx:sample")

		idx := &IndexDefinition{
			Name:   "test:idx:sample",
			Prefix: "test:sample:",
			OnJSON: true,
			Schema: []FieldDefinition{
				{
					Path:   "$.name",
					Alias:  "name",
					Type:   FieldTypeText,
					Weight: 2.0,
				},
				{
					Path:  "$.status",
					Alias: "status",
					Type:  FieldTypeTag,
				},
				{
					Path:     "$.created_at",
					Alias:    "created_at",
					Type:     FieldTypeNumeric,
					Sortable: true,
				},
			},
		}

		err := manager.EnsureIndex(ctx, idx)
		require.NoError(t, err)

		// Verify index exists
		exists, err := manager.IndexExists(ctx, "test:idx:sample")
		require.NoError(t, err)
		assert.True(t, exists)
	})

	t.Run("idempotent - no error when index exists", func(t *testing.T) {
		idx := &IndexDefinition{
			Name:   "test:idx:sample",
			Prefix: "test:sample:",
			OnJSON: true,
			Schema: []FieldDefinition{
				{
					Path:  "$.name",
					Alias: "name",
					Type:  FieldTypeText,
				},
			},
		}

		// Create index first time
		err := manager.EnsureIndex(ctx, idx)
		require.NoError(t, err)

		// Create again - should not error
		err = manager.EnsureIndex(ctx, idx)
		require.NoError(t, err)
	})

	t.Run("creates index with FLAT vector field", func(t *testing.T) {
		// Drop index if it exists
		_ = manager.DropIndex(ctx, "test:idx:vectors")
		defer func() {
			_ = manager.DropIndex(ctx, "test:idx:vectors")
		}()

		idx := &IndexDefinition{
			Name:   "test:idx:vectors",
			Prefix: "test:vector:",
			OnJSON: true,
			Schema: []FieldDefinition{
				{
					Path:  "$.content",
					Alias: "content",
					Type:  FieldTypeText,
				},
				{
					Path:  "$.embedding",
					Alias: "embedding",
					Type:  FieldTypeVector,
					VectorOpts: &VectorOptions{
						Algorithm:      VectorAlgorithmFlat,
						Type:           VectorDataTypeFloat32,
						Dim:            384,
						DistanceMetric: VectorDistanceMetricCosine,
					},
				},
			},
		}

		err := manager.EnsureIndex(ctx, idx)
		require.NoError(t, err)

		// Verify index exists
		exists, err := manager.IndexExists(ctx, "test:idx:vectors")
		require.NoError(t, err)
		assert.True(t, exists)
	})

	t.Run("creates index with HNSW vector field", func(t *testing.T) {
		// Drop index if it exists
		_ = manager.DropIndex(ctx, "test:idx:vectors:hnsw")
		defer func() {
			_ = manager.DropIndex(ctx, "test:idx:vectors:hnsw")
		}()

		idx := &IndexDefinition{
			Name:   "test:idx:vectors:hnsw",
			Prefix: "test:vector:hnsw:",
			OnJSON: true,
			Schema: []FieldDefinition{
				{
					Path:  "$.content",
					Alias: "content",
					Type:  FieldTypeText,
				},
				{
					Path:  "$.embedding",
					Alias: "embedding",
					Type:  FieldTypeVector,
					VectorOpts: &VectorOptions{
						Algorithm:      VectorAlgorithmHNSW,
						Type:           VectorDataTypeFloat32,
						Dim:            384,
						DistanceMetric: VectorDistanceMetricCosine,
						M:              16,
						EfConstruction: 200,
					},
				},
			},
		}

		err := manager.EnsureIndex(ctx, idx)
		require.NoError(t, err)

		// Verify index exists
		exists, err := manager.IndexExists(ctx, "test:idx:vectors:hnsw")
		require.NoError(t, err)
		assert.True(t, exists)
	})

	t.Run("creates index with multi-value tag field", func(t *testing.T) {
		// Drop index if it exists
		_ = manager.DropIndex(ctx, "test:idx:tags")
		defer func() {
			_ = manager.DropIndex(ctx, "test:idx:tags")
		}()

		idx := &IndexDefinition{
			Name:   "test:idx:tags",
			Prefix: "test:tagged:",
			OnJSON: true,
			Schema: []FieldDefinition{
				{
					Path:  "$.name",
					Alias: "name",
					Type:  FieldTypeText,
				},
				{
					Path:      "$.tags[*]",
					Alias:     "tags",
					Type:      FieldTypeTag,
					Separator: ",",
				},
			},
		}

		err := manager.EnsureIndex(ctx, idx)
		require.NoError(t, err)

		// Verify index exists
		exists, err := manager.IndexExists(ctx, "test:idx:tags")
		require.NoError(t, err)
		assert.True(t, exists)
	})
}

func TestIndexManager_DropIndex(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	ctx := context.Background()
	client := setupTestRedis(t)
	defer client.Close()

	manager := NewIndexManager(client)

	t.Run("drops existing index", func(t *testing.T) {
		// Create an index first
		idx := &IndexDefinition{
			Name:   "test:idx:drop",
			Prefix: "test:drop:",
			OnJSON: true,
			Schema: []FieldDefinition{
				{
					Path:  "$.name",
					Alias: "name",
					Type:  FieldTypeText,
				},
			},
		}

		err := manager.EnsureIndex(ctx, idx)
		require.NoError(t, err)

		// Verify it exists
		exists, err := manager.IndexExists(ctx, "test:idx:drop")
		require.NoError(t, err)
		require.True(t, exists)

		// Drop it
		err = manager.DropIndex(ctx, "test:idx:drop")
		require.NoError(t, err)

		// Verify it's gone
		exists, err = manager.IndexExists(ctx, "test:idx:drop")
		require.NoError(t, err)
		assert.False(t, exists)
	})

	t.Run("no error when dropping non-existent index", func(t *testing.T) {
		err := manager.DropIndex(ctx, "test:idx:nonexistent")
		require.NoError(t, err)
	})
}

func TestIndexManager_IndexExists(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	ctx := context.Background()
	client := setupTestRedis(t)
	defer client.Close()

	manager := NewIndexManager(client)

	t.Run("returns true for existing index", func(t *testing.T) {
		// Create an index
		idx := &IndexDefinition{
			Name:   "test:idx:exists",
			Prefix: "test:exists:",
			OnJSON: true,
			Schema: []FieldDefinition{
				{
					Path:  "$.name",
					Alias: "name",
					Type:  FieldTypeText,
				},
			},
		}

		err := manager.EnsureIndex(ctx, idx)
		require.NoError(t, err)
		defer func() {
			_ = manager.DropIndex(ctx, "test:idx:exists")
		}()

		// Check it exists
		exists, err := manager.IndexExists(ctx, "test:idx:exists")
		require.NoError(t, err)
		assert.True(t, exists)
	})

	t.Run("returns false for non-existent index", func(t *testing.T) {
		exists, err := manager.IndexExists(ctx, "test:idx:nonexistent")
		require.NoError(t, err)
		assert.False(t, exists)
	})
}

func TestIndexManager_IndexInfo(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	ctx := context.Background()
	client := setupTestRedis(t)
	defer client.Close()

	manager := NewIndexManager(client)

	// Create a test index with some documents
	idx := &IndexDefinition{
		Name:   "test:idx:info",
		Prefix: "test:info:",
		OnJSON: true,
		Schema: []FieldDefinition{
			{
				Path:   "$.name",
				Alias:  "name",
				Type:   FieldTypeText,
				Weight: 2.0,
			},
			{
				Path:  "$.status",
				Alias: "status",
				Type:  FieldTypeTag,
			},
		},
	}

	err := manager.EnsureIndex(ctx, idx)
	require.NoError(t, err)
	defer func() {
		_ = manager.DropIndex(ctx, "test:idx:info")
	}()

	// Add some test documents
	stateClient := &StateClient{client: client}
	testDoc := map[string]interface{}{
		"name":   "Test Document",
		"status": "active",
	}

	err = stateClient.JSONSet(ctx, "test:info:1", "$", testDoc)
	require.NoError(t, err)
	defer func() {
		_ = stateClient.JSONDel(ctx, "test:info:1", "$")
	}()

	// Wait for indexing to complete
	time.Sleep(100 * time.Millisecond)

	t.Run("retrieves index metadata", func(t *testing.T) {
		info, err := manager.IndexInfo(ctx, "test:idx:info")
		require.NoError(t, err)
		require.NotNil(t, info)

		assert.Equal(t, "test:idx:info", info.IndexName)
		assert.GreaterOrEqual(t, info.NumDocs, int64(0))
		// Other fields may vary, just check they're non-negative
		assert.GreaterOrEqual(t, info.NumTerms, int64(0))
		assert.GreaterOrEqual(t, info.NumRecords, int64(0))
	})

	t.Run("returns error for non-existent index", func(t *testing.T) {
		_, err := manager.IndexInfo(ctx, "test:idx:nonexistent")
		require.Error(t, err)
	})
}

func TestIndexManager_EnsureAllIndexes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	ctx := context.Background()
	client := setupTestRedis(t)
	defer client.Close()

	manager := NewIndexManager(client)

	// Clean up all Gibson indexes before test
	indexes := AllIndexDefinitions()
	for _, idx := range indexes {
		_ = manager.DropIndex(ctx, idx.Name)
	}

	t.Run("creates all Gibson indexes", func(t *testing.T) {
		err := manager.EnsureAllIndexes(ctx)
		require.NoError(t, err)

		// Verify all indexes were created
		for _, idx := range indexes {
			exists, err := manager.IndexExists(ctx, idx.Name)
			require.NoError(t, err, "failed to check existence of %s", idx.Name)
			assert.True(t, exists, "index %s should exist", idx.Name)
		}

		// Clean up
		for _, idx := range indexes {
			_ = manager.DropIndex(ctx, idx.Name)
		}
	})

	t.Run("idempotent - no error when indexes exist", func(t *testing.T) {
		// Create first time
		err := manager.EnsureAllIndexes(ctx)
		require.NoError(t, err)

		// Create again - should not error
		err = manager.EnsureAllIndexes(ctx)
		require.NoError(t, err)

		// Clean up
		for _, idx := range indexes {
			_ = manager.DropIndex(ctx, idx.Name)
		}
	})
}

func TestAllIndexDefinitions(t *testing.T) {
	t.Run("returns all 8 index definitions", func(t *testing.T) {
		indexes := AllIndexDefinitions()
		require.Len(t, indexes, 8)

		// Verify each index is present
		indexNames := make(map[string]bool)
		for _, idx := range indexes {
			indexNames[idx.Name] = true
		}

		assert.True(t, indexNames["gibson:idx:missions"])
		assert.True(t, indexNames["gibson:idx:findings"])
		assert.True(t, indexNames["gibson:idx:memory"])
		assert.True(t, indexNames["gibson:idx:payloads"])
		assert.True(t, indexNames["gibson:idx:credentials"])
		assert.True(t, indexNames["gibson:idx:sessions"])
		assert.True(t, indexNames["gibson:idx:targets"])
		assert.True(t, indexNames["gibson:idx:vectors"])
	})
}

func TestMissionIndex(t *testing.T) {
	t.Run("has correct definition", func(t *testing.T) {
		idx := MissionIndex()

		assert.Equal(t, "gibson:idx:missions", idx.Name)
		assert.Equal(t, "gibson:mission:", idx.Prefix)
		assert.True(t, idx.OnJSON)
		assert.Len(t, idx.Schema, 10) // 8 original + tenant_id (v2) + name_exact (v3, gibson#617)

		// Verify field definitions
		fields := make(map[string]FieldDefinition)
		for _, f := range idx.Schema {
			fields[f.Alias] = f
		}

		// Check name field (weighted text)
		assert.Equal(t, "$.name", fields["name"].Path)
		assert.Equal(t, FieldTypeText, fields["name"].Type)
		assert.Equal(t, 2.0, fields["name"].Weight)

		// Check name_exact field (exact-match TAG on the same path) — gibson#617.
		// FindOrCreateMission de-dups via @name_exact:{...}; the TEXT name field
		// cannot be exact-matched with TAG syntax.
		assert.Equal(t, "$.name", fields["name_exact"].Path)
		assert.Equal(t, FieldTypeTag, fields["name_exact"].Type)

		// Check status field (tag)
		assert.Equal(t, "$.status", fields["status"].Path)
		assert.Equal(t, FieldTypeTag, fields["status"].Type)

		// Check created_at field (sortable numeric)
		assert.Equal(t, "$.created_at", fields["created_at"].Path)
		assert.Equal(t, FieldTypeNumeric, fields["created_at"].Type)
		assert.True(t, fields["created_at"].Sortable)
	})

	t.Run("contains tenant_id as TAG SORTABLE (schema version 2)", func(t *testing.T) {
		idx := MissionIndex()

		fields := make(map[string]FieldDefinition)
		for _, f := range idx.Schema {
			fields[f.Alias] = f
		}

		tenantField, ok := fields["tenant_id"]
		require.True(t, ok, "tenant_id field must be present in gibson:idx:missions schema")
		assert.Equal(t, "$.tenant_id", tenantField.Path)
		assert.Equal(t, FieldTypeTag, tenantField.Type, "tenant_id must be a TAG field")
		assert.True(t, tenantField.Sortable, "tenant_id TAG field must be SORTABLE")
	})

	t.Run("schema version constant matches expected bumped value", func(t *testing.T) {
		assert.Equal(t, 3, MissionIndexSchemaVersion,
			"MissionIndexSchemaVersion must be 3 after name_exact addition (gibson#617)")
		assert.Equal(t, MissionIndexSchemaVersion, MissionIndex().SchemaVersion,
			"MissionIndex().SchemaVersion must equal MissionIndexSchemaVersion constant")
	})
}

func TestFindingIndex(t *testing.T) {
	t.Run("has correct definition", func(t *testing.T) {
		idx := FindingIndex()

		assert.Equal(t, "gibson:idx:findings", idx.Name)
		assert.Equal(t, "gibson:finding:", idx.Prefix)
		assert.True(t, idx.OnJSON)
		assert.Len(t, idx.Schema, 13) // 12 original + tenant_id (schema version 2)

		// Verify weighted text fields
		fields := make(map[string]FieldDefinition)
		for _, f := range idx.Schema {
			fields[f.Alias] = f
		}

		// Check title has highest weight
		assert.Equal(t, 3.0, fields["title"].Weight)

		// Check description has medium weight
		assert.Equal(t, 2.0, fields["description"].Weight)

		// Check sortable fields
		assert.True(t, fields["risk_score"].Sortable)
		assert.True(t, fields["cvss_score"].Sortable)
		assert.True(t, fields["created_at"].Sortable)
	})

	t.Run("contains tenant_id as TAG SORTABLE (schema version 2)", func(t *testing.T) {
		idx := FindingIndex()

		fields := make(map[string]FieldDefinition)
		for _, f := range idx.Schema {
			fields[f.Alias] = f
		}

		tenantField, ok := fields["tenant_id"]
		require.True(t, ok, "tenant_id field must be present in gibson:idx:findings schema")
		assert.Equal(t, "$.tenant_id", tenantField.Path)
		assert.Equal(t, FieldTypeTag, tenantField.Type, "tenant_id must be a TAG field")
		assert.True(t, tenantField.Sortable, "tenant_id TAG field must be SORTABLE")
	})

	t.Run("schema version constant matches expected bumped value", func(t *testing.T) {
		assert.Equal(t, 2, FindingIndexSchemaVersion,
			"FindingIndexSchemaVersion must be 2 after Phase 1 tenant_id addition")
		assert.Equal(t, FindingIndexSchemaVersion, FindingIndex().SchemaVersion,
			"FindingIndex().SchemaVersion must equal FindingIndexSchemaVersion constant")
	})
}

func TestMissionMemoryIndex(t *testing.T) {
	t.Run("has correct definition", func(t *testing.T) {
		idx := MissionMemoryIndex()

		assert.Equal(t, "gibson:idx:memory", idx.Name)
		assert.Equal(t, "gibson:memory:", idx.Prefix)
		assert.True(t, idx.OnJSON)
		assert.Len(t, idx.Schema, 5) // key, value, tenant_id, mission_id, created_at

		// Verify fields
		fields := make(map[string]FieldDefinition)
		for _, f := range idx.Schema {
			fields[f.Alias] = f
		}

		// Check key field (weighted text)
		assert.Equal(t, 2.0, fields["key"].Weight)

		// Check mission_id tag for filtering
		assert.Equal(t, FieldTypeTag, fields["mission_id"].Type)

		// Check tenant_id tag for isolation (pre-existing field in memory index)
		assert.Equal(t, FieldTypeTag, fields["tenant_id"].Type)
	})
}

func TestPayloadIndex(t *testing.T) {
	t.Run("has correct definition", func(t *testing.T) {
		idx := PayloadIndex()

		assert.Equal(t, "gibson:idx:payloads", idx.Name)
		assert.Equal(t, "gibson:payload:", idx.Prefix)
		assert.True(t, idx.OnJSON)
		assert.Len(t, idx.Schema, 9)

		// Verify fields
		fields := make(map[string]FieldDefinition)
		for _, f := range idx.Schema {
			fields[f.Alias] = f
		}

		// Check multi-value tag fields
		assert.Equal(t, "$.categories[*]", fields["categories"].Path)
		assert.Equal(t, FieldTypeTag, fields["categories"].Type)

		assert.Equal(t, "$.tags[*]", fields["tags"].Path)
		assert.Equal(t, FieldTypeTag, fields["tags"].Type)
	})
}

func TestCredentialIndex(t *testing.T) {
	t.Run("has correct definition", func(t *testing.T) {
		idx := CredentialIndex()

		assert.Equal(t, "gibson:idx:credentials", idx.Name)
		assert.Equal(t, "gibson:credential:", idx.Prefix)
		assert.True(t, idx.OnJSON)
		assert.Len(t, idx.Schema, 7)

		// Verify fields
		fields := make(map[string]FieldDefinition)
		for _, f := range idx.Schema {
			fields[f.Alias] = f
		}

		// Check name is sortable tag
		assert.Equal(t, FieldTypeTag, fields["name"].Type)
		assert.True(t, fields["name"].Sortable)

		// Check last_used is sortable
		assert.True(t, fields["last_used"].Sortable)
	})

	t.Run("does not index sensitive fields", func(t *testing.T) {
		idx := CredentialIndex()

		// Verify no encrypted_value, encryption_iv, or key_derivation_salt fields
		for _, f := range idx.Schema {
			assert.NotContains(t, f.Path, "encrypted_value")
			assert.NotContains(t, f.Path, "encryption_iv")
			assert.NotContains(t, f.Path, "key_derivation_salt")
		}
	})
}

func TestSessionIndex(t *testing.T) {
	t.Run("has correct definition", func(t *testing.T) {
		idx := SessionIndex()

		assert.Equal(t, "gibson:idx:sessions", idx.Name)
		assert.Equal(t, "gibson:session:", idx.Prefix)
		assert.True(t, idx.OnJSON)
		assert.Len(t, idx.Schema, 5)

		// Verify fields
		fields := make(map[string]FieldDefinition)
		for _, f := range idx.Schema {
			fields[f.Alias] = f
		}

		// Check tag fields
		assert.Equal(t, FieldTypeTag, fields["status"].Type)
		assert.Equal(t, FieldTypeTag, fields["agent_id"].Type)
		assert.Equal(t, FieldTypeTag, fields["mission_id"].Type)

		// Check sortable timestamp fields
		assert.True(t, fields["created_at"].Sortable)
		assert.True(t, fields["ended_at"].Sortable)
	})
}

func TestTargetIndex(t *testing.T) {
	t.Run("has correct definition", func(t *testing.T) {
		idx := TargetIndex()

		assert.Equal(t, "gibson:idx:targets", idx.Name)
		assert.Equal(t, "gibson:target:", idx.Prefix)
		assert.True(t, idx.OnJSON)
		assert.Len(t, idx.Schema, 7)

		// Verify fields
		fields := make(map[string]FieldDefinition)
		for _, f := range idx.Schema {
			fields[f.Alias] = f
		}

		// Check name is sortable tag
		assert.Equal(t, FieldTypeTag, fields["name"].Type)
		assert.True(t, fields["name"].Sortable)

		// Check sortable timestamp fields
		assert.True(t, fields["created_at"].Sortable)
		assert.True(t, fields["updated_at"].Sortable)
	})
}

func TestVectorIndex(t *testing.T) {
	t.Run("has correct definition with HNSW", func(t *testing.T) {
		idx := VectorIndex()

		assert.Equal(t, "gibson:idx:vectors", idx.Name)
		assert.Equal(t, "gibson:vector:", idx.Prefix)
		assert.True(t, idx.OnJSON)
		assert.Len(t, idx.Schema, 3)

		// Find the embedding field
		var embeddingField *FieldDefinition
		for i := range idx.Schema {
			if idx.Schema[i].Alias == "embedding" {
				embeddingField = &idx.Schema[i]
				break
			}
		}

		require.NotNil(t, embeddingField, "embedding field not found")
		assert.Equal(t, FieldTypeVector, embeddingField.Type)

		// Verify vector options
		require.NotNil(t, embeddingField.VectorOpts)
		assert.Equal(t, VectorAlgorithmHNSW, embeddingField.VectorOpts.Algorithm)
		assert.Equal(t, VectorDataTypeFloat32, embeddingField.VectorOpts.Type)
		assert.Equal(t, 384, embeddingField.VectorOpts.Dim)
		assert.Equal(t, VectorDistanceMetricCosine, embeddingField.VectorOpts.DistanceMetric)
		assert.Equal(t, 16, embeddingField.VectorOpts.M)
		assert.Equal(t, 200, embeddingField.VectorOpts.EfConstruction)
	})
}

func TestIndexDefinition_Validate(t *testing.T) {
	t.Run("valid index passes validation", func(t *testing.T) {
		idx := &IndexDefinition{
			Name:   "test:idx:valid",
			Prefix: "test:valid:",
			OnJSON: true,
			Schema: []FieldDefinition{
				{
					Path:  "$.name",
					Alias: "name",
					Type:  FieldTypeText,
				},
			},
		}

		err := idx.Validate()
		assert.NoError(t, err)
	})

	t.Run("empty name fails validation", func(t *testing.T) {
		idx := &IndexDefinition{
			Name:   "",
			Prefix: "test:valid:",
			OnJSON: true,
			Schema: []FieldDefinition{
				{Path: "$.name", Alias: "name", Type: FieldTypeText},
			},
		}

		err := idx.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "name cannot be empty")
	})

	t.Run("empty prefix fails validation", func(t *testing.T) {
		idx := &IndexDefinition{
			Name:   "test:idx:valid",
			Prefix: "",
			OnJSON: true,
			Schema: []FieldDefinition{
				{Path: "$.name", Alias: "name", Type: FieldTypeText},
			},
		}

		err := idx.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "prefix cannot be empty")
	})

	t.Run("empty schema fails validation", func(t *testing.T) {
		idx := &IndexDefinition{
			Name:   "test:idx:valid",
			Prefix: "test:valid:",
			OnJSON: true,
			Schema: []FieldDefinition{},
		}

		err := idx.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "at least one field")
	})

	t.Run("field with empty path fails validation", func(t *testing.T) {
		idx := &IndexDefinition{
			Name:   "test:idx:valid",
			Prefix: "test:valid:",
			OnJSON: true,
			Schema: []FieldDefinition{
				{Path: "", Alias: "name", Type: FieldTypeText},
			},
		}

		err := idx.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "path cannot be empty")
	})

	t.Run("field with empty alias fails validation", func(t *testing.T) {
		idx := &IndexDefinition{
			Name:   "test:idx:valid",
			Prefix: "test:valid:",
			OnJSON: true,
			Schema: []FieldDefinition{
				{Path: "$.name", Alias: "", Type: FieldTypeText},
			},
		}

		err := idx.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "alias cannot be empty")
	})

	t.Run("vector field without options fails validation", func(t *testing.T) {
		idx := &IndexDefinition{
			Name:   "test:idx:vectors",
			Prefix: "test:vector:",
			OnJSON: true,
			Schema: []FieldDefinition{
				{
					Path:       "$.embedding",
					Alias:      "embedding",
					Type:       FieldTypeVector,
					VectorOpts: nil,
				},
			},
		}

		err := idx.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "VectorOpts required")
	})

	t.Run("vector field with invalid dimension fails validation", func(t *testing.T) {
		idx := &IndexDefinition{
			Name:   "test:idx:vectors",
			Prefix: "test:vector:",
			OnJSON: true,
			Schema: []FieldDefinition{
				{
					Path:  "$.embedding",
					Alias: "embedding",
					Type:  FieldTypeVector,
					VectorOpts: &VectorOptions{
						Algorithm:      VectorAlgorithmFlat,
						Type:           VectorDataTypeFloat32,
						Dim:            0,
						DistanceMetric: VectorDistanceMetricCosine,
					},
				},
			},
		}

		err := idx.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "dimension must be positive")
	})

	t.Run("HNSW without M parameter fails validation", func(t *testing.T) {
		idx := &IndexDefinition{
			Name:   "test:idx:vectors",
			Prefix: "test:vector:",
			OnJSON: true,
			Schema: []FieldDefinition{
				{
					Path:  "$.embedding",
					Alias: "embedding",
					Type:  FieldTypeVector,
					VectorOpts: &VectorOptions{
						Algorithm:      VectorAlgorithmHNSW,
						Type:           VectorDataTypeFloat32,
						Dim:            384,
						DistanceMetric: VectorDistanceMetricCosine,
						M:              0,
						EfConstruction: 200,
					},
				},
			},
		}

		err := idx.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "M parameter must be positive")
	})

	t.Run("HNSW without EfConstruction parameter fails validation", func(t *testing.T) {
		idx := &IndexDefinition{
			Name:   "test:idx:vectors",
			Prefix: "test:vector:",
			OnJSON: true,
			Schema: []FieldDefinition{
				{
					Path:  "$.embedding",
					Alias: "embedding",
					Type:  FieldTypeVector,
					VectorOpts: &VectorOptions{
						Algorithm:      VectorAlgorithmHNSW,
						Type:           VectorDataTypeFloat32,
						Dim:            384,
						DistanceMetric: VectorDistanceMetricCosine,
						M:              16,
						EfConstruction: 0,
					},
				},
			},
		}

		err := idx.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "EF_CONSTRUCTION parameter must be positive")
	})

	t.Run("valid HNSW index passes validation", func(t *testing.T) {
		idx := &IndexDefinition{
			Name:   "test:idx:vectors",
			Prefix: "test:vector:",
			OnJSON: true,
			Schema: []FieldDefinition{
				{
					Path:  "$.embedding",
					Alias: "embedding",
					Type:  FieldTypeVector,
					VectorOpts: &VectorOptions{
						Algorithm:      VectorAlgorithmHNSW,
						Type:           VectorDataTypeFloat32,
						Dim:            384,
						DistanceMetric: VectorDistanceMetricCosine,
						M:              16,
						EfConstruction: 200,
					},
				},
			},
		}

		err := idx.Validate()
		assert.NoError(t, err)
	})
}

// TestSchemaVersionKey tests the Redis key naming convention for schema versions.
func TestSchemaVersionKey(t *testing.T) {
	t.Run("mission index schema version key", func(t *testing.T) {
		key := schemaVersionKey("gibson:idx:missions")
		assert.Equal(t, "gibson:idx:missions:schema_version", key)
	})

	t.Run("finding index schema version key", func(t *testing.T) {
		key := schemaVersionKey("gibson:idx:findings")
		assert.Equal(t, "gibson:idx:findings:schema_version", key)
	})

	t.Run("arbitrary index name produces consistent key", func(t *testing.T) {
		key := schemaVersionKey("test:idx:sample")
		assert.Equal(t, "test:idx:sample:schema_version", key)
	})
}

// TestIndexDefinition_SchemaVersion tests that SchemaVersion is propagated correctly.
func TestIndexDefinition_SchemaVersion(t *testing.T) {
	t.Run("mission index has SchemaVersion set to MissionIndexSchemaVersion", func(t *testing.T) {
		idx := MissionIndex()
		assert.Equal(t, MissionIndexSchemaVersion, idx.SchemaVersion)
	})

	t.Run("finding index has SchemaVersion set to FindingIndexSchemaVersion", func(t *testing.T) {
		idx := FindingIndex()
		assert.Equal(t, FindingIndexSchemaVersion, idx.SchemaVersion)
	})

	t.Run("MissionIndexSchemaVersion is 3", func(t *testing.T) {
		assert.Equal(t, 3, MissionIndexSchemaVersion)
	})

	t.Run("FindingIndexSchemaVersion is 2", func(t *testing.T) {
		assert.Equal(t, 2, FindingIndexSchemaVersion)
	})

	t.Run("indexes with no SchemaVersion default to 0", func(t *testing.T) {
		idx := &IndexDefinition{
			Name:   "test:idx:noversion",
			Prefix: "test:nv:",
			OnJSON: true,
			Schema: []FieldDefinition{
				{Path: "$.name", Alias: "name", Type: FieldTypeText},
			},
		}
		assert.Equal(t, 0, idx.SchemaVersion)
	})
}

// TestIndexManager_WithReindexObserver tests the reindex observer wiring (pure unit, no Redis).
func TestIndexManager_WithReindexObserver(t *testing.T) {
	t.Run("returns the same IndexManager for chaining", func(t *testing.T) {
		mgr := NewIndexManager(nil)
		result := mgr.WithReindexObserver(func(_ string, _ float64) {})
		assert.Same(t, mgr, result, "WithReindexObserver must return the receiver for chaining")
	})

	t.Run("nil observer is accepted and results in no reindexObserver set", func(t *testing.T) {
		mgr := NewIndexManager(nil)
		// Setting a non-nil observer and then replacing with nil should work
		mgr.WithReindexObserver(nil)
		assert.Nil(t, mgr.reindexObserver)
	})

	t.Run("observer is stored on the manager", func(t *testing.T) {
		var called bool
		mgr := NewIndexManager(nil)
		mgr.WithReindexObserver(func(name string, dur float64) {
			called = true
		})
		require.NotNil(t, mgr.reindexObserver)
		mgr.reindexObserver("test", 1.5)
		assert.True(t, called)
	})
}

// TestIndexManager_ReindexObserverInvocation tests that the observer is called with
// correct arguments after a reindex is triggered (integration test — needs Redis).
func TestIndexManager_ReindexObserverInvocation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	ctx := context.Background()
	client := setupTestRedis(t)
	defer client.Close()

	const testIndexName = "test:idx:reindex_observer"
	const testPrefix = "test:reindex_obs:"

	// Track observer invocations
	type observation struct {
		name     string
		duration float64
	}
	var observations []observation

	mgr := NewIndexManager(client)
	mgr.WithReindexObserver(func(name string, dur float64) {
		observations = append(observations, observation{name: name, duration: dur})
	})

	defer func() { _ = mgr.DropIndex(ctx, testIndexName) }()
	_ = mgr.DropIndex(ctx, testIndexName) // clean slate

	idx := &IndexDefinition{
		Name:          testIndexName,
		Prefix:        testPrefix,
		OnJSON:        true,
		SchemaVersion: 1,
		Schema: []FieldDefinition{
			{Path: "$.name", Alias: "name", Type: FieldTypeText},
		},
	}

	t.Run("observer called on fresh index creation", func(t *testing.T) {
		observations = nil
		err := mgr.EnsureIndex(ctx, idx)
		require.NoError(t, err)
		require.Len(t, observations, 1, "observer must be called once on index creation")
		assert.Equal(t, testIndexName, observations[0].name)
		assert.GreaterOrEqual(t, observations[0].duration, 0.0)
	})

	t.Run("observer NOT called when schema version unchanged", func(t *testing.T) {
		observations = nil
		err := mgr.EnsureIndex(ctx, idx) // same version — should skip re-index
		require.NoError(t, err)
		assert.Empty(t, observations, "observer must NOT be called when schema version matches")
	})

	t.Run("observer called once on schema version bump", func(t *testing.T) {
		observations = nil
		// Bump the version — simulates a schema change
		bumpedIdx := &IndexDefinition{
			Name:          testIndexName,
			Prefix:        testPrefix,
			OnJSON:        true,
			SchemaVersion: 2, // bumped
			Schema: []FieldDefinition{
				{Path: "$.name", Alias: "name", Type: FieldTypeText},
				{Path: "$.tenant_id", Alias: "tenant_id", Type: FieldTypeTag, Sortable: true},
			},
		}
		err := mgr.EnsureIndex(ctx, bumpedIdx)
		require.NoError(t, err)
		require.Len(t, observations, 1, "observer must be called exactly once on version bump re-index")
		assert.Equal(t, testIndexName, observations[0].name)
		assert.GreaterOrEqual(t, observations[0].duration, 0.0)
	})

	t.Run("observer NOT called again for same bumped version", func(t *testing.T) {
		observations = nil
		bumpedIdx := &IndexDefinition{
			Name:          testIndexName,
			Prefix:        testPrefix,
			OnJSON:        true,
			SchemaVersion: 2,
			Schema: []FieldDefinition{
				{Path: "$.name", Alias: "name", Type: FieldTypeText},
				{Path: "$.tenant_id", Alias: "tenant_id", Type: FieldTypeTag, Sortable: true},
			},
		}
		err := mgr.EnsureIndex(ctx, bumpedIdx)
		require.NoError(t, err)
		assert.Empty(t, observations, "observer must NOT be called when version already matches")
	})
}

// setupTestRedis creates a Redis client for testing.
// It skips the test if REDIS_URL is not set or connection fails.
func setupTestRedis(t *testing.T) redis.UniversalClient {
	t.Helper()

	cfg := DefaultConfig()
	if cfg.URL == "" {
		cfg.URL = "redis://localhost:6379"
	}

	opts, err := redis.ParseURL(cfg.URL)
	if err != nil {
		t.Skipf("skipping test: invalid Redis URL: %v", err)
	}

	client := redis.NewClient(opts)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		client.Close()
		t.Skipf("skipping test: Redis not available: %v", err)
	}

	return client
}
