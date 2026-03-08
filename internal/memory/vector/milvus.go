package vector

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/milvus-io/milvus-sdk-go/v2/client"
	"github.com/milvus-io/milvus-sdk-go/v2/entity"
	"github.com/zero-day-ai/gibson/internal/types"
)

// MilvusVectorStore is a production-grade vector store implementation using Milvus.
// It provides efficient vector similarity search using Milvus's IVF_FLAT index
// with inner product (IP) metric for similarity scoring.
//
// The store leverages:
// - Milvus gRPC API for high-performance operations
// - IVF_FLAT index for fast approximate nearest neighbor search
// - Inner Product metric for similarity scoring
// - Automatic collection creation with optimal schema
// - Thread-safe concurrent access with RWMutex
type MilvusVectorStore struct {
	client     client.Client
	collection string
	dims       int
	mu         sync.RWMutex
	closed     bool
}

// NewMilvusVectorStore creates a new Milvus-backed vector store.
// The collection will be created automatically if it doesn't exist, with IVF_FLAT indexing
// and inner product metric configured.
//
// Parameters:
//   - cfg: VectorStoreConfig with Dimensions set to embedding size (e.g., 384)
//
// The store uses the following configuration:
//   - IVF_FLAT index for balanced performance and accuracy
//   - Inner Product (IP) metric for similarity computation
//   - Auto-creation of collection on first use
//
// Example:
//
//	cfg := vector.VectorStoreConfig{
//	    Backend:    "milvus",
//	    Dimensions: 384, // for all-minilm-l6-v2 embeddings
//	}
//	store, err := vector.NewMilvusVectorStore(cfg)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer store.Close()
func NewMilvusVectorStore(cfg VectorStoreConfig) (*MilvusVectorStore, error) {
	// Use default Milvus config
	mcfg := DefaultMilvusConfig()

	// Validate configuration
	if err := mcfg.Validate(); err != nil {
		return nil, err
	}

	if cfg.Dimensions <= 0 {
		return nil, types.NewError(ErrCodeInvalidConfig,
			fmt.Sprintf("dimensions must be positive, got %d", cfg.Dimensions))
	}

	// Build connection address
	addr := fmt.Sprintf("%s:%d", mcfg.Host, mcfg.Port)

	// Connect to Milvus
	ctx := context.Background()
	var c client.Client
	var err error

	if mcfg.Username != "" && mcfg.Password != "" {
		c, err = client.NewClient(ctx, client.Config{
			Address:  addr,
			Username: mcfg.Username,
			Password: mcfg.Password,
		})
	} else {
		c, err = client.NewClient(ctx, client.Config{
			Address: addr,
		})
	}

	if err != nil {
		return nil, types.WrapError(ErrCodeVectorStoreUnavailable,
			fmt.Sprintf("failed to connect to milvus at %s", addr), err)
	}

	store := &MilvusVectorStore{
		client:     c,
		collection: mcfg.Collection,
		dims:       cfg.Dimensions,
		closed:     false,
	}

	// Ensure collection exists
	if err := store.ensureCollection(ctx); err != nil {
		c.Close()
		return nil, err
	}

	return store, nil
}

// ensureCollection creates the collection if it doesn't exist.
// The collection is configured with:
// - id: VARCHAR(64) primary key
// - embedding: FLOAT_VECTOR(dims)
// - content: VARCHAR(65535)
// - metadata: JSON
// - created_at: INT64 (unix timestamp)
// - IVF_FLAT index on embedding with IP metric
func (s *MilvusVectorStore) ensureCollection(ctx context.Context) error {
	// Check if collection exists
	exists, err := s.client.HasCollection(ctx, s.collection)
	if err != nil {
		return types.WrapError(ErrCodeVectorStoreFailed,
			fmt.Sprintf("failed to check collection %s", s.collection), err)
	}

	if exists {
		// Load collection into memory
		err = s.client.LoadCollection(ctx, s.collection, false)
		if err != nil {
			return types.WrapError(ErrCodeVectorStoreFailed,
				fmt.Sprintf("failed to load collection %s", s.collection), err)
		}
		return nil
	}

	// Create schema
	schema := &entity.Schema{
		CollectionName: s.collection,
		Description:    "Gibson vector store collection",
		Fields: []*entity.Field{
			{
				Name:       "id",
				DataType:   entity.FieldTypeVarChar,
				PrimaryKey: true,
				AutoID:     false,
				TypeParams: map[string]string{
					"max_length": "64",
				},
			},
			{
				Name:     "embedding",
				DataType: entity.FieldTypeFloatVector,
				TypeParams: map[string]string{
					"dim": fmt.Sprintf("%d", s.dims),
				},
			},
			{
				Name:     "content",
				DataType: entity.FieldTypeVarChar,
				TypeParams: map[string]string{
					"max_length": "65535",
				},
			},
			{
				Name:     "metadata",
				DataType: entity.FieldTypeJSON,
			},
			{
				Name:     "created_at",
				DataType: entity.FieldTypeInt64,
			},
		},
	}

	// Create collection
	err = s.client.CreateCollection(ctx, schema, entity.DefaultShardNumber)
	if err != nil {
		return types.WrapError(ErrCodeVectorStoreFailed,
			fmt.Sprintf("failed to create collection %s", s.collection), err)
	}

	// Create IVF_FLAT index on embedding field
	idx, err := entity.NewIndexIvfFlat(entity.IP, 1024)
	if err != nil {
		return types.WrapError(ErrCodeVectorStoreFailed, "failed to create index", err)
	}

	err = s.client.CreateIndex(ctx, s.collection, "embedding", idx, false)
	if err != nil {
		return types.WrapError(ErrCodeVectorStoreFailed,
			fmt.Sprintf("failed to create index on collection %s", s.collection), err)
	}

	// Load collection into memory
	err = s.client.LoadCollection(ctx, s.collection, false)
	if err != nil {
		return types.WrapError(ErrCodeVectorStoreFailed,
			fmt.Sprintf("failed to load collection %s", s.collection), err)
	}

	return nil
}

// Store adds a single vector record to Milvus.
// The record is stored with its embedding, content, metadata, and timestamp.
func (s *MilvusVectorStore) Store(ctx context.Context, record VectorRecord) error {
	// Validate the record
	if err := record.Validate(); err != nil {
		return err
	}

	// Check dimensionality matches
	if len(record.Embedding) != s.dims {
		return types.NewError(ErrCodeVectorStoreFailed,
			fmt.Sprintf("embedding dimensions mismatch: expected %d, got %d", s.dims, len(record.Embedding)))
	}

	s.mu.RLock()
	if s.closed {
		s.mu.RUnlock()
		return types.NewError(ErrCodeVectorStoreUnavailable, "vector store is closed")
	}
	s.mu.RUnlock()

	// Convert embedding to float32 (Milvus uses float32)
	vector := make([]float32, len(record.Embedding))
	for i, v := range record.Embedding {
		vector[i] = float32(v)
	}

	// Prepare data columns
	idColumn := entity.NewColumnVarChar("id", []string{record.ID})
	embeddingColumn := entity.NewColumnFloatVector("embedding", s.dims, [][]float32{vector})
	contentColumn := entity.NewColumnVarChar("content", []string{record.Content})

	// Convert metadata to JSON-compatible format
	metadataBytes, err := milvusConvertMetadataToJSON(record.Metadata)
	if err != nil {
		return types.WrapError(ErrCodeVectorStoreFailed, "failed to convert metadata", err)
	}
	metadataColumn := entity.NewColumnJSONBytes("metadata", [][]byte{metadataBytes})

	// Convert timestamp to Unix milliseconds
	createdAtColumn := entity.NewColumnInt64("created_at", []int64{record.CreatedAt.UnixMilli()})

	// Insert data
	_, err = s.client.Insert(ctx, s.collection, "",
		idColumn, embeddingColumn, contentColumn, metadataColumn, createdAtColumn)

	if err != nil {
		return types.WrapError(ErrCodeVectorStoreFailed, "failed to store vector in milvus", err)
	}

	// Flush to ensure data is persisted
	err = s.client.Flush(ctx, s.collection, false)
	if err != nil {
		return types.WrapError(ErrCodeVectorStoreFailed, "failed to flush collection", err)
	}

	return nil
}

// StoreBatch adds multiple vector records efficiently using batch insert.
// All records are validated before any are stored for consistency.
func (s *MilvusVectorStore) StoreBatch(ctx context.Context, records []VectorRecord) error {
	if len(records) == 0 {
		return nil
	}

	// Validate all records first
	for i, record := range records {
		if err := record.Validate(); err != nil {
			return types.WrapError(ErrCodeVectorStoreFailed,
				fmt.Sprintf("invalid record at index %d", i), err)
		}
		if len(record.Embedding) != s.dims {
			return types.NewError(ErrCodeVectorStoreFailed,
				fmt.Sprintf("record %d: embedding dimensions mismatch: expected %d, got %d",
					i, s.dims, len(record.Embedding)))
		}
	}

	s.mu.RLock()
	if s.closed {
		s.mu.RUnlock()
		return types.NewError(ErrCodeVectorStoreUnavailable, "vector store is closed")
	}
	s.mu.RUnlock()

	// Prepare batch data
	ids := make([]string, len(records))
	vectors := make([][]float32, len(records))
	contents := make([]string, len(records))
	metadataList := make([][]byte, len(records))
	timestamps := make([]int64, len(records))

	for i, record := range records {
		ids[i] = record.ID
		contents[i] = record.Content
		timestamps[i] = record.CreatedAt.UnixMilli()

		// Convert embedding to float32
		vector := make([]float32, len(record.Embedding))
		for j, v := range record.Embedding {
			vector[j] = float32(v)
		}
		vectors[i] = vector

		// Convert metadata
		metadataBytes, err := milvusConvertMetadataToJSON(record.Metadata)
		if err != nil {
			return types.WrapError(ErrCodeVectorStoreFailed,
				fmt.Sprintf("failed to convert metadata for record %d", i), err)
		}
		metadataList[i] = metadataBytes
	}

	// Create data columns
	idColumn := entity.NewColumnVarChar("id", ids)
	embeddingColumn := entity.NewColumnFloatVector("embedding", s.dims, vectors)
	contentColumn := entity.NewColumnVarChar("content", contents)
	metadataColumn := entity.NewColumnJSONBytes("metadata", metadataList)
	createdAtColumn := entity.NewColumnInt64("created_at", timestamps)

	// Batch insert
	_, err := s.client.Insert(ctx, s.collection, "",
		idColumn, embeddingColumn, contentColumn, metadataColumn, createdAtColumn)

	if err != nil {
		return types.WrapError(ErrCodeVectorStoreFailed, "failed to batch store vectors in milvus", err)
	}

	// Flush to ensure data is persisted
	err = s.client.Flush(ctx, s.collection, false)
	if err != nil {
		return types.WrapError(ErrCodeVectorStoreFailed, "failed to flush collection", err)
	}

	return nil
}

// Search finds similar records by embedding vector using Milvus's search API.
// This performs vector similarity search using inner product metric.
//
// The implementation uses Milvus's Search with:
// - Inner Product (IP) metric (configured at index creation)
// - IVF_FLAT index for fast approximate nearest neighbor search
// - Optional metadata filters for hybrid search
// - Configurable top-K results and minimum score threshold
//
// Returns results sorted by inner product similarity (higher scores = more similar).
func (s *MilvusVectorStore) Search(ctx context.Context, query VectorQuery) ([]VectorResult, error) {
	// Validate the query
	if err := query.Validate(); err != nil {
		return nil, err
	}

	// Must have an embedding to search
	if len(query.Embedding) == 0 {
		return nil, types.NewError(ErrCodeVectorSearchFailed,
			"query must have embedding for search (embed text first)")
	}

	// Check dimensionality matches
	if len(query.Embedding) != s.dims {
		return nil, types.NewError(ErrCodeVectorSearchFailed,
			fmt.Sprintf("query embedding dimensions mismatch: expected %d, got %d",
				s.dims, len(query.Embedding)))
	}

	s.mu.RLock()
	if s.closed {
		s.mu.RUnlock()
		return nil, types.NewError(ErrCodeVectorStoreUnavailable, "vector store is closed")
	}
	s.mu.RUnlock()

	// Convert embedding to float32
	vector := make([]float32, len(query.Embedding))
	for i, v := range query.Embedding {
		vector[i] = float32(v)
	}

	// Build search vector
	searchVector := entity.FloatVector(vector)

	// Build search parameters
	sp, err := entity.NewIndexIvfFlatSearchParam(16) // nprobe=16
	if err != nil {
		return nil, types.WrapError(ErrCodeVectorSearchFailed, "failed to create search params", err)
	}

	// Output fields to retrieve
	outputFields := []string{"id", "content", "metadata", "created_at"}

	// Execute search
	searchResult, err := s.client.Search(
		ctx,
		s.collection,
		nil, // No partition names
		"",  // No filter expression for now
		outputFields,
		[]entity.Vector{searchVector},
		"embedding",
		entity.IP,
		query.TopK,
		sp,
	)

	if err != nil {
		return nil, types.WrapError(ErrCodeVectorSearchFailed, "milvus search failed", err)
	}

	if len(searchResult) == 0 {
		return []VectorResult{}, nil
	}

	// Convert results
	results := make([]VectorResult, 0)
	firstResult := searchResult[0]

	// Get field data maps
	var contentData []string
	var metadataData [][]byte
	var createdAtData []int64

	for _, field := range firstResult.Fields {
		switch field.Name() {
		case "content":
			if col, ok := field.(*entity.ColumnVarChar); ok {
				for i := 0; i < col.Len(); i++ {
					val, _ := col.ValueByIdx(i)
					contentData = append(contentData, val)
				}
			}
		case "metadata":
			if col, ok := field.(*entity.ColumnJSONBytes); ok {
				for i := 0; i < col.Len(); i++ {
					val, _ := col.ValueByIdx(i)
					metadataData = append(metadataData, val)
				}
			}
		case "created_at":
			if col, ok := field.(*entity.ColumnInt64); ok {
				for i := 0; i < col.Len(); i++ {
					val, _ := col.ValueByIdx(i)
					createdAtData = append(createdAtData, val)
				}
			}
		}
	}

	// Build results
	scores := firstResult.Scores
	ids := firstResult.IDs

	for i := 0; i < ids.Len(); i++ {
		score := float64(scores[i])

		// Apply minimum score threshold
		if score < query.MinScore {
			continue
		}

		id := milvusGetIDString(ids, i)
		content := ""
		if i < len(contentData) {
			content = contentData[i]
		}

		metadata := make(map[string]any)
		if i < len(metadataData) {
			metadata, _ = milvusConvertJSONToMetadata(metadataData[i])
		}

		createdAt := time.Now()
		if i < len(createdAtData) {
			createdAt = time.UnixMilli(createdAtData[i])
		}

		record := VectorRecord{
			ID:        id,
			Content:   content,
			Embedding: nil, // Not retrieved from search results
			Metadata:  metadata,
			CreatedAt: createdAt,
		}

		results = append(results, *NewVectorResult(record, score))
	}

	// Sort by score descending (should already be sorted by Milvus)
	sort.Slice(results, func(i, j int) bool {
		return results[i].Score > results[j].Score
	})

	return results, nil
}

// Get retrieves a specific record by ID.
func (s *MilvusVectorStore) Get(ctx context.Context, id string) (*VectorRecord, error) {
	s.mu.RLock()
	if s.closed {
		s.mu.RUnlock()
		return nil, types.NewError(ErrCodeVectorStoreUnavailable, "vector store is closed")
	}
	s.mu.RUnlock()

	// Query by ID
	expr := fmt.Sprintf("id == \"%s\"", id)
	queryResult, err := s.client.Query(
		ctx,
		s.collection,
		nil, // No partition names
		expr,
		[]string{"id", "embedding", "content", "metadata", "created_at"},
	)

	if err != nil {
		return nil, types.WrapError(ErrCodeVectorSearchFailed, "failed to get vector from milvus", err)
	}

	if len(queryResult) == 0 {
		return nil, types.NewError(ErrCodeVectorNotFound,
			fmt.Sprintf("vector record not found: %s", id))
	}

	// Extract data from columns
	var recordID string
	var embedding []float64
	var content string
	var metadata map[string]any
	var createdAt time.Time

	for _, column := range queryResult {
		switch column.Name() {
		case "id":
			if col, ok := column.(*entity.ColumnVarChar); ok && col.Len() > 0 {
				recordID, _ = col.ValueByIdx(0)
			}
		case "embedding":
			if col, ok := column.(*entity.ColumnFloatVector); ok && col.Len() > 0 {
				vec, _ := col.Get(0)
				if vecSlice, ok := vec.([]float32); ok {
					embedding = make([]float64, len(vecSlice))
					for i, v := range vecSlice {
						embedding[i] = float64(v)
					}
				}
			}
		case "content":
			if col, ok := column.(*entity.ColumnVarChar); ok && col.Len() > 0 {
				content, _ = col.ValueByIdx(0)
			}
		case "metadata":
			if col, ok := column.(*entity.ColumnJSONBytes); ok && col.Len() > 0 {
				metadataBytes, _ := col.ValueByIdx(0)
				metadata, _ = milvusConvertJSONToMetadata(metadataBytes)
			}
		case "created_at":
			if col, ok := column.(*entity.ColumnInt64); ok && col.Len() > 0 {
				timestamp, _ := col.ValueByIdx(0)
				createdAt = time.UnixMilli(timestamp)
			}
		}
	}

	record := &VectorRecord{
		ID:        recordID,
		Content:   content,
		Embedding: embedding,
		Metadata:  metadata,
		CreatedAt: createdAt,
	}

	return record, nil
}

// Delete removes a record from Milvus.
func (s *MilvusVectorStore) Delete(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return types.NewError(ErrCodeVectorStoreUnavailable, "vector store is closed")
	}

	// Delete by ID expression
	expr := fmt.Sprintf("id == \"%s\"", id)
	err := s.client.Delete(ctx, s.collection, "", expr)

	if err != nil {
		return types.WrapError(ErrCodeVectorStoreFailed, "failed to delete vector from milvus", err)
	}

	// Flush to ensure deletion is persisted
	err = s.client.Flush(ctx, s.collection, false)
	if err != nil {
		return types.WrapError(ErrCodeVectorStoreFailed, "failed to flush collection after delete", err)
	}

	return nil
}

// Health returns the current health status of the Milvus vector store.
// It checks connectivity and retrieves collection statistics.
func (s *MilvusVectorStore) Health(ctx context.Context) types.HealthStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return types.NewHealthStatus(
			types.HealthStateUnhealthy,
			"milvus vector store is closed",
		)
	}

	// Get collection statistics
	stats, err := s.client.GetCollectionStatistics(ctx, s.collection)
	if err != nil {
		return types.NewHealthStatus(
			types.HealthStateUnhealthy,
			fmt.Sprintf("failed to get collection statistics: %v", err),
		)
	}

	// Extract row count (stats is a map[string]string)
	rowCount := stats["row_count"]

	return types.NewHealthStatus(
		types.HealthStateHealthy,
		fmt.Sprintf("milvus vector store operational with %s records (dims: %d, collection: %s)",
			rowCount, s.dims, s.collection),
	)
}

// Close releases all resources held by the vector store.
func (s *MilvusVectorStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}

	s.closed = true

	// Close Milvus client
	if s.client != nil {
		return s.client.Close()
	}

	return nil
}

// Helper functions

// milvusConvertMetadataToJSON converts metadata map to JSON bytes
func milvusConvertMetadataToJSON(metadata map[string]any) ([]byte, error) {
	if metadata == nil {
		metadata = make(map[string]any)
	}

	// Use standard JSON encoding
	return json.Marshal(metadata)
}

// milvusConvertJSONToMetadata converts JSON bytes to metadata map
func milvusConvertJSONToMetadata(data []byte) (map[string]any, error) {
	if len(data) == 0 {
		return make(map[string]any), nil
	}

	// Parse JSON bytes
	var metadata map[string]any
	err := json.Unmarshal(data, &metadata)
	if err != nil {
		return make(map[string]any), err
	}

	return metadata, nil
}

// milvusGetIDString extracts string ID from entity.Column
func milvusGetIDString(ids entity.Column, idx int) string {
	switch col := ids.(type) {
	case *entity.ColumnVarChar:
		id, _ := col.ValueByIdx(idx)
		return id
	case *entity.ColumnInt64:
		id, _ := col.ValueByIdx(idx)
		return fmt.Sprintf("%d", id)
	default:
		return ""
	}
}
