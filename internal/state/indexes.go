package state

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// FieldType represents the type of a RediSearch index field.
type FieldType string

const (
	// FieldTypeText represents a full-text searchable TEXT field.
	FieldTypeText FieldType = "TEXT"

	// FieldTypeTag represents a TAG field for exact-match filtering.
	FieldTypeTag FieldType = "TAG"

	// FieldTypeNumeric represents a NUMERIC field for range queries and sorting.
	FieldTypeNumeric FieldType = "NUMERIC"

	// FieldTypeGeo represents a GEO field for geospatial queries.
	FieldTypeGeo FieldType = "GEO"

	// FieldTypeVector represents a VECTOR field for similarity search.
	FieldTypeVector FieldType = "VECTOR"
)

// VectorAlgorithm represents the vector indexing algorithm.
type VectorAlgorithm string

const (
	// VectorAlgorithmFlat uses brute-force KNN search.
	VectorAlgorithmFlat VectorAlgorithm = "FLAT"

	// VectorAlgorithmHNSW uses Hierarchical Navigable Small World graph index.
	VectorAlgorithmHNSW VectorAlgorithm = "HNSW"
)

// VectorDataType represents the data type of vector components.
type VectorDataType string

const (
	// VectorDataTypeFloat32 uses 32-bit floating point numbers.
	VectorDataTypeFloat32 VectorDataType = "FLOAT32"

	// VectorDataTypeFloat64 uses 64-bit floating point numbers.
	VectorDataTypeFloat64 VectorDataType = "FLOAT64"
)

// VectorDistanceMetric represents the distance metric for vector similarity.
type VectorDistanceMetric string

const (
	// VectorDistanceMetricCosine uses cosine similarity.
	VectorDistanceMetricCosine VectorDistanceMetric = "COSINE"

	// VectorDistanceMetricL2 uses Euclidean distance.
	VectorDistanceMetricL2 VectorDistanceMetric = "L2"

	// VectorDistanceMetricIP uses inner product.
	VectorDistanceMetricIP VectorDistanceMetric = "IP"
)

// VectorOptions configures vector field indexing parameters.
type VectorOptions struct {
	// Algorithm specifies the vector indexing algorithm (FLAT or HNSW).
	Algorithm VectorAlgorithm

	// Type specifies the data type of vector components (FLOAT32 or FLOAT64).
	Type VectorDataType

	// Dim specifies the dimensionality of the vectors.
	Dim int

	// DistanceMetric specifies how to calculate vector similarity.
	DistanceMetric VectorDistanceMetric

	// M is the number of bi-directional links per node for HNSW algorithm.
	// Higher values improve recall but increase memory usage and build time.
	// Typical values: 12-48. Default: 16.
	// Only used when Algorithm is HNSW.
	M int

	// EfConstruction is the size of the dynamic candidate list for HNSW construction.
	// Higher values improve index quality but increase build time.
	// Typical values: 100-500. Default: 200.
	// Only used when Algorithm is HNSW.
	EfConstruction int
}

// FieldDefinition defines a single field in a RediSearch index schema.
type FieldDefinition struct {
	// Path is the JSONPath expression for this field (e.g., "$.name").
	Path string

	// Alias is the field name used in queries.
	Alias string

	// Type is the field type (TEXT, TAG, NUMERIC, GEO, VECTOR).
	Type FieldType

	// Sortable indicates if this field can be used in SORTBY clauses.
	Sortable bool

	// NoIndex indicates if this field should not be indexed (only stored).
	NoIndex bool

	// Weight is the importance multiplier for TEXT fields (default: 1.0).
	Weight float64

	// Separator is the character used to split multi-value TAG fields.
	Separator string

	// VectorOpts configures vector field parameters (only for VECTOR type).
	VectorOpts *VectorOptions
}

// IndexDefinition defines a complete RediSearch index.
type IndexDefinition struct {
	// Name is the index name (e.g., "gibson:idx:missions").
	Name string

	// Prefix is the key prefix to index (e.g., "gibson:mission:").
	Prefix string

	// OnJSON indicates if this is a JSON index (vs HASH).
	OnJSON bool

	// Schema is the list of indexed fields.
	Schema []FieldDefinition

	// SchemaVersion is the current schema version for this index.
	// When the daemon starts, it compares this value against the version stored
	// in Redis at key "{Name}:schema_version". If they differ, the index is
	// dropped and re-created online (documents are preserved; RediSearch
	// re-indexes them automatically). Increment this value whenever the Schema
	// changes to trigger a one-time online re-index on next startup.
	//
	// Version history for tenant-isolation work:
	//   0 (implicit) → version key absent, original schema without tenant_id
	//   2             → added tenant_id AS tenant_id TAG SORTABLE (Phase 1)
	SchemaVersion int
}

// Validate checks if the index definition is valid and returns an error if not.
// It verifies:
//   - Name is not empty
//   - Prefix is not empty
//   - Schema has at least one field
//   - Vector fields have valid VectorOptions
//   - HNSW parameters are present when using HNSW algorithm
func (idx *IndexDefinition) Validate() error {
	if idx.Name == "" {
		return fmt.Errorf("index name cannot be empty")
	}

	if idx.Prefix == "" {
		return fmt.Errorf("index prefix cannot be empty")
	}

	if len(idx.Schema) == 0 {
		return fmt.Errorf("index schema must have at least one field")
	}

	// Validate each field
	for i, field := range idx.Schema {
		if field.Path == "" {
			return fmt.Errorf("field %d: path cannot be empty", i)
		}

		if field.Alias == "" {
			return fmt.Errorf("field %d: alias cannot be empty", i)
		}

		// Validate vector fields
		if field.Type == FieldTypeVector {
			if field.VectorOpts == nil {
				return fmt.Errorf("field %q: VectorOpts required for VECTOR type", field.Alias)
			}

			opts := field.VectorOpts

			if opts.Dim <= 0 {
				return fmt.Errorf("field %q: vector dimension must be positive", field.Alias)
			}

			if opts.Algorithm == "" {
				return fmt.Errorf("field %q: vector algorithm must be specified", field.Alias)
			}

			if opts.Type == "" {
				return fmt.Errorf("field %q: vector data type must be specified", field.Alias)
			}

			if opts.DistanceMetric == "" {
				return fmt.Errorf("field %q: vector distance metric must be specified", field.Alias)
			}

			// Validate HNSW parameters
			if opts.Algorithm == VectorAlgorithmHNSW {
				if opts.M <= 0 {
					return fmt.Errorf("field %q: HNSW M parameter must be positive (typical: 12-48)", field.Alias)
				}

				if opts.EfConstruction <= 0 {
					return fmt.Errorf("field %q: HNSW EF_CONSTRUCTION parameter must be positive (typical: 100-500)", field.Alias)
				}
			}
		}
	}

	return nil
}

// IndexInfo contains metadata about a RediSearch index.
type IndexInfo struct {
	// IndexName is the name of the index.
	IndexName string

	// NumDocs is the number of documents in the index.
	NumDocs int64

	// NumTerms is the number of distinct terms indexed.
	NumTerms int64

	// NumRecords is the total number of records (fields) indexed.
	NumRecords int64

	// MaxDocID is the highest internal document ID.
	MaxDocID int64

	// InvertedSzMB is the size of the inverted index in MB.
	InvertedSzMB float64

	// OffsetVectorsSzMB is the size of offset vectors in MB.
	OffsetVectorsSzMB float64

	// DocTableSizeMB is the size of the document table in MB.
	DocTableSizeMB float64

	// SortableValuesSizeMB is the size of sortable values in MB.
	SortableValuesSizeMB float64

	// KeyTableSizeMB is the size of the key table in MB.
	KeyTableSizeMB float64
}

// IndexManager manages RediSearch indexes for Gibson entities.
type IndexManager struct {
	client redis.UniversalClient

	// reindexObserver is called once per index re-index with the index name and
	// elapsed duration in seconds. Set via WithReindexObserver to wire in
	// the gibson_redisearch_reindex_duration_seconds metric without importing
	// the observability package into the state package.
	reindexObserver func(indexName string, durationSeconds float64)
}

// NewIndexManager creates a new IndexManager with the given Redis client.
func NewIndexManager(client redis.UniversalClient) *IndexManager {
	return &IndexManager{
		client: client,
	}
}

// WithReindexObserver attaches a callback that is invoked once per online re-index
// with the index name and elapsed duration in seconds. Wire this to
// gibson_redisearch_reindex_duration_seconds{index} in the daemon startup path.
func (m *IndexManager) WithReindexObserver(fn func(indexName string, durationSeconds float64)) *IndexManager {
	m.reindexObserver = fn
	return m
}

// schemaVersionKey returns the Redis key that stores the current schema version
// for the given index. Stored as a plain string (integer value).
//
//	"gibson:idx:missions:schema_version"
func schemaVersionKey(indexName string) string {
	return indexName + ":schema_version"
}

// EnsureIndex creates or updates a RediSearch index, performing an online re-index
// when the schema version has changed.
//
// Schema-version behaviour:
//   - The expected version is stored in IndexDefinition.SchemaVersion.
//   - The persisted version is held at Redis key "{Name}:schema_version".
//   - If the index does not exist: FT.CREATE it and record the version.
//   - If the index exists and versions match: run reindexMissingKeys (idempotent).
//   - If the index exists and versions differ: drop the index (documents are
//     preserved), re-create it with the new schema, re-index existing keys,
//     then store the new version. The re-index duration is reported via
//     the optional reindexObserver to surface gibson_redisearch_reindex_duration_seconds.
//
// Example:
//
//	idx := &IndexDefinition{
//	    Name:          "gibson:idx:missions",
//	    Prefix:        "gibson:mission:",
//	    OnJSON:        true,
//	    SchemaVersion: 2,
//	    Schema: []FieldDefinition{
//	        {Path: "$.name", Alias: "name", Type: FieldTypeText, Weight: 2.0},
//	        {Path: "$.status", Alias: "status", Type: FieldTypeTag},
//	        {Path: "$.tenant_id", Alias: "tenant_id", Type: FieldTypeTag, Sortable: true},
//	    },
//	}
//	err := manager.EnsureIndex(ctx, idx)
func (m *IndexManager) EnsureIndex(ctx context.Context, def *IndexDefinition) error {
	// Validate the index definition first
	if err := def.Validate(); err != nil {
		return fmt.Errorf("invalid index definition: %w", err)
	}

	// Check if index already exists
	exists, err := m.IndexExists(ctx, def.Name)
	if err != nil {
		return fmt.Errorf("failed to check index existence: %w", err)
	}

	if exists {
		// Index exists — check whether the schema version matches.
		versionKey := schemaVersionKey(def.Name)
		storedVersionStr, err := m.client.Get(ctx, versionKey).Result()
		if err != nil && err != redis.Nil {
			return fmt.Errorf("failed to read schema version for %q: %w", def.Name, err)
		}

		storedVersion := 0
		if storedVersionStr != "" {
			if _, scanErr := fmt.Sscanf(storedVersionStr, "%d", &storedVersion); scanErr != nil {
				storedVersion = 0
			}
		}

		if storedVersion == def.SchemaVersion {
			// Schema unchanged — just repair any missing keys.
			_ = m.reindexMissingKeys(ctx, def)
			// Note: errors are intentionally ignored here. If reindexing fails,
			// keys will be indexed when they are next modified.
			return nil
		}

		// Schema version mismatch: drop the index and fall through to re-create.
		// FT.DROPINDEX by default does NOT delete documents — only the index
		// structure is removed. Existing data is preserved and will be re-indexed
		// once the new index is created.
		if dropErr := m.DropIndex(ctx, def.Name); dropErr != nil {
			return fmt.Errorf("failed to drop stale index %q for re-creation: %w", def.Name, dropErr)
		}
	}

	// Track that we're creating a new index - we'll need to reindex existing keys
	needsReindex := true
	_ = needsReindex // used below after index creation

	// Build FT.CREATE command arguments
	args := []interface{}{"FT.CREATE", def.Name}

	// Add ON JSON or ON HASH
	if def.OnJSON {
		args = append(args, "ON", "JSON")
	} else {
		args = append(args, "ON", "HASH")
	}

	// Add PREFIX
	args = append(args, "PREFIX", "1", def.Prefix)

	// Add SCHEMA
	args = append(args, "SCHEMA")

	// Add field definitions
	for _, field := range def.Schema {
		// Add JSONPath and field alias
		args = append(args, field.Path, "AS", field.Alias)

		// Add field type
		args = append(args, string(field.Type))

		// Add type-specific options
		switch field.Type {
		case FieldTypeText:
			if field.Weight > 0 {
				args = append(args, "WEIGHT", field.Weight)
			}
			if field.NoIndex {
				args = append(args, "NOINDEX")
			}
			if field.Sortable {
				args = append(args, "SORTABLE")
			}

		case FieldTypeTag:
			if field.Separator != "" {
				args = append(args, "SEPARATOR", field.Separator)
			}
			if field.Sortable {
				args = append(args, "SORTABLE")
			}

		case FieldTypeNumeric:
			if field.Sortable {
				args = append(args, "SORTABLE")
			}

		case FieldTypeVector:
			if field.VectorOpts == nil {
				return fmt.Errorf("VectorOpts required for VECTOR field %q", field.Alias)
			}

			opts := field.VectorOpts

			// Build VECTOR algorithm parameters
			// Base params: TYPE, DIM, DISTANCE_METRIC (3 key-value pairs)
			// HNSW params: M, EF_CONSTRUCTION (2 additional key-value pairs)
			vectorParams := []interface{}{
				"TYPE", string(opts.Type),
				"DIM", opts.Dim,
				"DISTANCE_METRIC", string(opts.DistanceMetric),
			}

			// Add HNSW-specific parameters if using HNSW algorithm
			if opts.Algorithm == VectorAlgorithmHNSW {
				if opts.M > 0 {
					vectorParams = append(vectorParams, "M", opts.M)
				}
				if opts.EfConstruction > 0 {
					vectorParams = append(vectorParams, "EF_CONSTRUCTION", opts.EfConstruction)
				}
			}

			// Calculate parameter count (number of key-value pairs)
			paramCount := len(vectorParams) / 2

			// Append: algorithm, param_count, then all params
			args = append(args, string(opts.Algorithm), paramCount*2)
			args = append(args, vectorParams...)
		}
	}

	// Execute FT.CREATE command
	result := m.client.Do(ctx, args...)
	if err := result.Err(); err != nil {
		return fmt.Errorf("FT.CREATE failed for index %q: %w", def.Name, err)
	}

	// Reindex existing keys that match the prefix.
	// RediSearch only indexes keys that are created/modified AFTER the index exists.
	// We need to "touch" existing keys to trigger indexing.
	if needsReindex {
		reindexStart := time.Now()

		if err := m.reindexExistingKeys(ctx, def); err != nil {
			// Log but don't fail - the index is created, just some keys might not be indexed
			// They'll get indexed when next modified
			return fmt.Errorf("index created but failed to reindex existing keys: %w", err)
		}

		// Record re-index duration via the optional observer so callers can emit
		// gibson_redisearch_reindex_duration_seconds{index=<name>}.
		if m.reindexObserver != nil {
			m.reindexObserver(def.Name, time.Since(reindexStart).Seconds())
		}
	}

	// Persist the schema version so future startups skip this re-index.
	versionKey := schemaVersionKey(def.Name)
	if err := m.client.Set(ctx, versionKey, fmt.Sprintf("%d", def.SchemaVersion), 0).Err(); err != nil {
		// Non-fatal: if we fail to store the version the re-index will run again
		// on the next startup, which is safe.
		_ = err
	}

	return nil
}

// reindexMissingKeys checks if there are keys matching the prefix that aren't indexed,
// and reindexes them if needed. This handles:
// - Keys that existed before the index was created
// - Keys that failed to index due to schema mismatches
func (m *IndexManager) reindexMissingKeys(ctx context.Context, def *IndexDefinition) error {
	// Get index info to see how many docs are indexed
	info, err := m.IndexInfo(ctx, def.Name)
	if err != nil {
		return fmt.Errorf("failed to get index info for %s: %w", def.Name, err)
	}

	// Count keys matching the prefix (excluding secondary index keys)
	pattern := def.Prefix + "*"
	var keyCount int64
	var cursor uint64

	for {
		keys, nextCursor, err := m.client.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			return fmt.Errorf("SCAN failed for pattern %s: %w", pattern, err)
		}

		for _, key := range keys {
			// Skip secondary index keys (e.g., by_status, by_target, :runs suffix)
			if !strings.Contains(key, ":by_") && !strings.HasSuffix(key, ":runs") {
				keyCount++
			}
		}

		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}

	// If there are more keys than indexed docs, reindex
	if keyCount > info.NumDocs {
		if err := m.reindexExistingKeys(ctx, def); err != nil {
			return fmt.Errorf("failed to reindex existing keys for %s: %w", def.Name, err)
		}
	}

	return nil
}

// reindexExistingKeys scans for existing keys matching the index prefix and
// triggers reindexing by reading, transforming, and re-writing each key.
// This is necessary because RediSearch only indexes keys created/modified after
// the index exists.
//
// For JSON keys, this function also transforms any string timestamp fields
// (created_at, updated_at, started_at, completed_at) to numeric Unix timestamps
// to ensure compatibility with RediSearch NUMERIC field indexing.
func (m *IndexManager) reindexExistingKeys(ctx context.Context, def *IndexDefinition) error {
	// Use SCAN to find all keys matching the prefix
	pattern := def.Prefix + "*"
	var cursor uint64
	var reindexed int
	var errors int

	for {
		// Scan for keys matching the prefix
		keys, nextCursor, err := m.client.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			return fmt.Errorf("SCAN failed: %w", err)
		}

		// Reindex each key by reading, transforming, and re-writing it
		for _, key := range keys {
			// Skip secondary index keys
			if strings.Contains(key, ":by_") || strings.HasSuffix(key, ":runs") {
				continue
			}

			if def.OnJSON {
				// For JSON keys, read the entire document
				data, err := m.client.Do(ctx, "JSON.GET", key).Result()
				if err != nil {
					// Key might have been deleted, skip it
					continue
				}

				dataStr, ok := data.(string)
				if !ok {
					continue
				}

				// Transform the JSON to fix any string timestamps
				transformedData, wasTransformed := transformJSONTimestamps(dataStr)

				// Re-set the data to trigger indexing
				_, err = m.client.Do(ctx, "JSON.SET", key, "$", transformedData).Result()
				if err != nil {
					errors++
					continue
				}

				if wasTransformed {
					reindexed++
				} else {
					reindexed++
				}
			} else {
				// For HASH keys, use HGETALL and HSET
				data, err := m.client.HGetAll(ctx, key).Result()
				if err != nil || len(data) == 0 {
					continue
				}

				// Re-set all fields to trigger indexing
				args := make([]interface{}, 0, len(data)*2)
				for k, v := range data {
					args = append(args, k, v)
				}
				if len(args) > 0 {
					_, err = m.client.HSet(ctx, key, args...).Result()
					if err != nil {
						errors++
						continue
					}
					reindexed++
				}
			}
		}

		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}

	return nil
}

// transformJSONTimestamps parses JSON and converts any string timestamp fields
// to numeric Unix millisecond values. This fixes documents that were created with
// string timestamps which are incompatible with RediSearch NUMERIC fields.
//
// The following fields are transformed if they are strings:
// - created_at
// - updated_at
// - started_at
// - completed_at
// - checkpoint_at
// - ended_at
// - last_used
//
// Returns the transformed JSON string and a boolean indicating if any transformation occurred.
func transformJSONTimestamps(jsonStr string) (string, bool) {
	// Parse the JSON into a map
	var doc map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &doc); err != nil {
		// If we can't parse it, return as-is
		return jsonStr, false
	}

	timestampFields := []string{
		"created_at",
		"updated_at",
		"started_at",
		"completed_at",
		"checkpoint_at",
		"ended_at",
		"last_used",
	}

	transformed := false
	for _, field := range timestampFields {
		if val, exists := doc[field]; exists {
			// Check if it's a string (ISO timestamp format)
			if strVal, ok := val.(string); ok && strVal != "" {
				// Try to parse as RFC3339
				if t, err := time.Parse(time.RFC3339, strVal); err == nil {
					// Convert to Unix milliseconds
					doc[field] = t.UnixMilli()
					transformed = true
				} else if t, err := time.Parse(time.RFC3339Nano, strVal); err == nil {
					doc[field] = t.UnixMilli()
					transformed = true
				}
			}
		}
	}

	if !transformed {
		return jsonStr, false
	}

	// Re-serialize the document
	result, err := json.Marshal(doc)
	if err != nil {
		return jsonStr, false
	}

	return string(result), true
}

// DropIndex removes a RediSearch index.
// This does not delete the indexed documents, only the index structure.
//
// Example:
//
//	err := manager.DropIndex(ctx, "gibson:idx:missions")
func (m *IndexManager) DropIndex(ctx context.Context, name string) error {
	// Execute FT.DROPINDEX command
	result := m.client.Do(ctx, "FT.DROPINDEX", name)
	if err := result.Err(); err != nil {
		// Ignore "Unknown Index name" errors
		if strings.Contains(err.Error(), "Unknown Index name") {
			return nil
		}
		return fmt.Errorf("FT.DROPINDEX failed for index %q: %w", name, err)
	}

	return nil
}

// IndexExists checks if a RediSearch index exists.
//
// Example:
//
//	exists, err := manager.IndexExists(ctx, "gibson:idx:missions")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	if !exists {
//	    log.Println("Index not found")
//	}
func (m *IndexManager) IndexExists(ctx context.Context, name string) (bool, error) {
	// Use FT._LIST to get all indexes
	result := m.client.Do(ctx, "FT._LIST")
	if err := result.Err(); err != nil {
		return false, fmt.Errorf("FT._LIST failed: %w", err)
	}

	// Parse the list of index names
	indexes, err := result.Slice()
	if err != nil {
		return false, fmt.Errorf("failed to parse FT._LIST result: %w", err)
	}

	// Check if our index is in the list
	for _, idx := range indexes {
		if indexName, ok := idx.(string); ok && indexName == name {
			return true, nil
		}
	}

	return false, nil
}

// IndexInfo retrieves metadata about a RediSearch index.
//
// Example:
//
//	info, err := manager.IndexInfo(ctx, "gibson:idx:missions")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	log.Printf("Index has %d documents\n", info.NumDocs)
func (m *IndexManager) IndexInfo(ctx context.Context, name string) (*IndexInfo, error) {
	// Execute FT.INFO command
	result := m.client.Do(ctx, "FT.INFO", name)
	if err := result.Err(); err != nil {
		return nil, fmt.Errorf("FT.INFO failed for index %q: %w", name, err)
	}

	// Parse the result as key-value pairs
	vals, err := result.Slice()
	if err != nil {
		return nil, fmt.Errorf("failed to parse FT.INFO result: %w", err)
	}

	info := &IndexInfo{IndexName: name}

	// FT.INFO returns alternating key-value pairs
	for i := 0; i < len(vals)-1; i += 2 {
		key, ok := vals[i].(string)
		if !ok {
			continue
		}

		switch key {
		case "num_docs":
			if val, err := parseInteger(vals[i+1]); err == nil {
				info.NumDocs = val
			}
		case "num_terms":
			if val, err := parseInteger(vals[i+1]); err == nil {
				info.NumTerms = val
			}
		case "num_records":
			if val, err := parseInteger(vals[i+1]); err == nil {
				info.NumRecords = val
			}
		case "max_doc_id":
			if val, err := parseInteger(vals[i+1]); err == nil {
				info.MaxDocID = val
			}
		case "inverted_sz_mb":
			if val, err := parseFloat(vals[i+1]); err == nil {
				info.InvertedSzMB = val
			}
		case "offset_vectors_sz_mb":
			if val, err := parseFloat(vals[i+1]); err == nil {
				info.OffsetVectorsSzMB = val
			}
		case "doc_table_size_mb":
			if val, err := parseFloat(vals[i+1]); err == nil {
				info.DocTableSizeMB = val
			}
		case "sortable_values_size_mb":
			if val, err := parseFloat(vals[i+1]); err == nil {
				info.SortableValuesSizeMB = val
			}
		case "key_table_size_mb":
			if val, err := parseFloat(vals[i+1]); err == nil {
				info.KeyTableSizeMB = val
			}
		}
	}

	return info, nil
}

// EnsureAllIndexes creates all predefined Gibson indexes if they don't exist.
// This should be called during daemon startup to initialize the search infrastructure.
//
// Example:
//
//	if err := manager.EnsureAllIndexes(ctx); err != nil {
//	    log.Fatalf("failed to create indexes: %v", err)
//	}
func (m *IndexManager) EnsureAllIndexes(ctx context.Context) error {
	// Get all index definitions
	indexes := AllIndexDefinitions()

	// Create each index
	for _, idx := range indexes {
		if err := m.EnsureIndex(ctx, idx); err != nil {
			return fmt.Errorf("failed to ensure index %q: %w", idx.Name, err)
		}
	}

	return nil
}

// parseIndexInfoValue parses a value from FT.INFO response.
// Values can be strings, integers, or floats.
func parseIndexInfoValue(val interface{}) (string, error) {
	switch v := val.(type) {
	case string:
		return v, nil
	case int64:
		return strconv.FormatInt(v, 10), nil
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64), nil
	default:
		return "", fmt.Errorf("unexpected type: %T", val)
	}
}

// parseInteger parses an integer value from Redis response.
// Redis can return integers as int64, string, or other types.
func parseInteger(val interface{}) (int64, error) {
	switch v := val.(type) {
	case int64:
		return v, nil
	case int:
		return int64(v), nil
	case string:
		return strconv.ParseInt(v, 10, 64)
	default:
		return 0, fmt.Errorf("cannot parse integer from type %T", val)
	}
}

// parseFloat parses a float value from Redis response.
// Redis can return floats as float64, string, or other types.
func parseFloat(val interface{}) (float64, error) {
	switch v := val.(type) {
	case float64:
		return v, nil
	case float32:
		return float64(v), nil
	case string:
		return strconv.ParseFloat(v, 64)
	case int64:
		return float64(v), nil
	case int:
		return float64(v), nil
	default:
		return 0, fmt.Errorf("cannot parse float from type %T", val)
	}
}
