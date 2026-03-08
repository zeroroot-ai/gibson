package state

import (
	"context"
	"fmt"
	"strconv"
	"strings"

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
}

// NewIndexManager creates a new IndexManager with the given Redis client.
func NewIndexManager(client redis.UniversalClient) *IndexManager {
	return &IndexManager{
		client: client,
	}
}

// EnsureIndex creates a RediSearch index if it doesn't already exist.
// This operation is idempotent - no error is returned if the index already exists.
//
// Example:
//
//	idx := &IndexDefinition{
//	    Name:   "gibson:idx:missions",
//	    Prefix: "gibson:mission:",
//	    OnJSON: true,
//	    Schema: []FieldDefinition{
//	        {Path: "$.name", Alias: "name", Type: FieldTypeText, Weight: 2.0},
//	        {Path: "$.status", Alias: "status", Type: FieldTypeTag},
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
		return nil // Index already exists, nothing to do
	}

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

	return nil
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
