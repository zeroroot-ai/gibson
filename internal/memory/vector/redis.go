package vector

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"sync"

	"github.com/zero-day-ai/gibson/internal/state"
	"github.com/zero-day-ai/gibson/internal/types"
)

// RedisVectorStore is a persistent vector store implementation using Redis with RediSearch.
// It provides efficient vector similarity search using RediSearch's VECTOR field type
// with KNN (K-Nearest Neighbors) capabilities. This implementation is thread-safe
// and suitable for production workloads requiring distributed vector search.
//
// The store leverages:
// - RedisJSON for document storage
// - RediSearch VECTOR field with FLAT algorithm for KNN search
// - COSINE distance metric for similarity scoring
// - Hybrid search combining full-text and vector queries
type RedisVectorStore struct {
	mu     sync.RWMutex
	client *state.StateClient
	dims   int
	closed bool
}

// NewRedisVectorStore creates a new persistent vector store using Redis with RediSearch.
// The vector index must already be created via state.EnsureIndexes() for search to work.
//
// Parameters:
//   - client: StateClient with RediSearch and RedisJSON modules enabled
//   - dims: Embedding dimensions (must match index definition, e.g., 384 for all-minilm-l6-v2)
//
// The store uses the following key naming convention:
//   - Vector documents: "gibson:vector:{id}"
//
// Example:
//
//	client, err := state.NewStateClient(cfg)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer client.Close()
//
//	// Ensure indexes are created
//	if err := client.EnsureIndexes(ctx); err != nil {
//	    log.Fatal(err)
//	}
//
//	// Create vector store
//	store := vector.NewRedisVectorStore(client, 384)
func NewRedisVectorStore(client *state.StateClient, dims int) *RedisVectorStore {
	return &RedisVectorStore{
		client: client,
		dims:   dims,
		closed: false,
	}
}

// Store adds a single vector record to Redis using JSON.SET.
// The embedding is stored as a float64 array in the JSON document.
func (s *RedisVectorStore) Store(ctx context.Context, record VectorRecord) error {
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

	// Build Redis key
	key := fmt.Sprintf("gibson:vector:%s", record.ID)

	// Store entire record as JSON document
	// RedisJSON will automatically handle the embedding array
	if err := s.client.JSONSet(ctx, key, "$", record); err != nil {
		return types.WrapError(ErrCodeVectorStoreFailed, "failed to store vector document", err)
	}

	return nil
}

// StoreBatch adds multiple vector records efficiently using pipelining.
// All records are validated before any are stored for atomicity.
func (s *RedisVectorStore) StoreBatch(ctx context.Context, records []VectorRecord) error {
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

	// Use Redis pipeline for efficient batch operations
	pipe := s.client.Client().Pipeline()

	for _, record := range records {
		key := fmt.Sprintf("gibson:vector:%s", record.ID)

		// Marshal record to JSON
		jsonData, err := json.Marshal(record)
		if err != nil {
			return types.WrapError(ErrCodeVectorStoreFailed,
				fmt.Sprintf("failed to marshal record %s", record.ID), err)
		}

		// Pipeline JSON.SET commands
		pipe.Do(ctx, "JSON.SET", key, "$", string(jsonData))
	}

	// Execute pipeline
	if _, err := pipe.Exec(ctx); err != nil {
		return types.WrapError(ErrCodeVectorStoreFailed, "failed to execute batch pipeline", err)
	}

	return nil
}

// Search finds similar records by embedding vector using RediSearch KNN.
// This performs vector similarity search using the FT.SEARCH command with KNN syntax.
//
// Search modes:
//  1. Pure vector search: Finds top-K most similar vectors by cosine similarity
//  2. Hybrid search: Combines full-text query on content with KNN vector search
//
// The implementation uses RediSearch DIALECT 2 for KNN query syntax:
//
//	FT.SEARCH gibson:idx:vectors
//	  "*=>[KNN {topK} @embedding $query_vec AS score]"
//	  PARAMS 2 query_vec <binary_blob>
//	  SORTBY score
//	  RETURN 3 content metadata score
//	  DIALECT 2
//
// Returns results sorted by cosine similarity (higher scores = more similar).
func (s *RedisVectorStore) Search(ctx context.Context, query VectorQuery) ([]VectorResult, error) {
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

	// Convert embedding to binary blob (FLOAT32 encoding for RediSearch)
	vectorBlob := embeddingToFloat32Bytes(query.Embedding)

	// Build KNN query string
	// Format: "*=>[KNN {topK} @embedding $query_vec AS score]"
	knnQuery := fmt.Sprintf("*=>[KNN %d @embedding $query_vec AS score]", query.TopK)

	// If hybrid search with text query on content, combine queries
	if query.Text != "" {
		// Escape special characters in text query
		escapedText := state.EscapeQuery(query.Text)
		knnQuery = fmt.Sprintf("@content:(%s) %s", escapedText, knnQuery)
	}

	// Build FT.SEARCH command with KNN parameters
	args := []interface{}{
		"FT.SEARCH",
		"gibson:idx:vectors",
		knnQuery,
		"PARAMS", "2",
		"query_vec", vectorBlob,
		"SORTBY", "score",
		"RETURN", "3", "$", "score", "__score",
		"DIALECT", "2",
	}

	// Execute search
	result := s.client.Client().Do(ctx, args...)
	if err := result.Err(); err != nil {
		return nil, types.WrapError(ErrCodeVectorSearchFailed, "FT.SEARCH with KNN failed", err)
	}

	rawResult, err := result.Result()
	if err != nil {
		return nil, types.WrapError(ErrCodeVectorSearchFailed, "failed to get search result", err)
	}

	results := make([]VectorResult, 0)

	// Handle RESP3 map format (Redis 7+ with go-redis/v9 default RESP3)
	if resultMap, ok := rawResult.(map[interface{}]interface{}); ok {
		totalVal, _ := resultMap["total_results"]
		total, _ := totalVal.(int64)
		if total == 0 {
			return []VectorResult{}, nil
		}

		resultsVal, _ := resultMap["results"]
		resultsList, _ := resultsVal.([]interface{})
		for _, r := range resultsList {
			docMap, ok := r.(map[interface{}]interface{})
			if !ok {
				continue
			}

			docIDVal, _ := docMap["id"]
			docID, _ := docIDVal.(string)
			vectorID := docID
			if len(docID) > 14 && docID[:14] == "gibson:vector:" {
				vectorID = docID[14:]
			}

			var record VectorRecord
			var score float64
			var foundJSON bool

			attrsVal, _ := docMap["extra_attributes"]
			if attrMap, ok := attrsVal.(map[interface{}]interface{}); ok {
				for k, v := range attrMap {
					fieldName, ok := k.(string)
					if !ok {
						continue
					}
					switch fieldName {
					case "$":
						if jsonStr, ok := v.(string); ok {
							if err := json.Unmarshal([]byte(jsonStr), &record); err == nil {
								record.ID = vectorID
								foundJSON = true
							}
						}
					case "__score", "score":
						if s, ok := v.(string); ok {
							fmt.Sscanf(s, "%f", &score)
						} else if f, ok := v.(float64); ok {
							score = f
						}
					}
				}
			}

			if !foundJSON || !matchesFilters(record, query.Filters) {
				continue
			}
			if score >= query.MinScore {
				results = append(results, *NewVectorResult(record, score))
			}
		}
	} else {
		// RESP2 slice format
		vals, ok := rawResult.([]interface{})
		if !ok || len(vals) == 0 {
			return []VectorResult{}, nil
		}

		total, ok := vals[0].(int64)
		if !ok || total == 0 {
			return []VectorResult{}, nil
		}

		for i := 1; i < len(vals); i += 2 {
			if i+1 >= len(vals) {
				break
			}

			docID, ok := vals[i].(string)
			if !ok {
				continue
			}
			vectorID := docID
			if len(docID) > 14 && docID[:14] == "gibson:vector:" {
				vectorID = docID[14:]
			}

			fields, ok := vals[i+1].([]interface{})
			if !ok {
				continue
			}

			var record VectorRecord
			var score float64
			var foundJSON bool

			for j := 0; j < len(fields)-1; j += 2 {
				fieldName, ok := fields[j].(string)
				if !ok {
					continue
				}
				switch fieldName {
				case "$":
					if jsonStr, ok := fields[j+1].(string); ok {
						if err := json.Unmarshal([]byte(jsonStr), &record); err == nil {
							record.ID = vectorID
							foundJSON = true
						}
					}
				case "__score", "score":
					if s, ok := fields[j+1].(string); ok {
						fmt.Sscanf(s, "%f", &score)
					} else if f, ok := fields[j+1].(float64); ok {
						score = f
					}
				}
			}

			if !foundJSON || !matchesFilters(record, query.Filters) {
				continue
			}
			if score >= query.MinScore {
				results = append(results, *NewVectorResult(record, score))
			}
		}
	}

	// Sort by score descending (RediSearch should already sort, but ensure it)
	sort.Slice(results, func(i, j int) bool {
		return results[i].Score > results[j].Score
	})

	// Limit to top-k (should already be limited by KNN, but ensure it)
	if len(results) > query.TopK {
		results = results[:query.TopK]
	}

	return results, nil
}

// Get retrieves a specific record by ID using JSON.GET.
func (s *RedisVectorStore) Get(ctx context.Context, id string) (*VectorRecord, error) {
	s.mu.RLock()
	if s.closed {
		s.mu.RUnlock()
		return nil, types.NewError(ErrCodeVectorStoreUnavailable, "vector store is closed")
	}
	s.mu.RUnlock()

	key := fmt.Sprintf("gibson:vector:%s", id)

	var record VectorRecord
	if err := s.client.JSONGet(ctx, key, "$", &record); err != nil {
		if err == state.ErrNotFound {
			return nil, nil
		}
		return nil, types.WrapError(ErrCodeVectorSearchFailed, "failed to get vector document", err)
	}

	return &record, nil
}

// Delete removes a record from Redis using JSON.DEL.
func (s *RedisVectorStore) Delete(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return types.NewError(ErrCodeVectorStoreUnavailable, "vector store is closed")
	}

	key := fmt.Sprintf("gibson:vector:%s", id)

	if err := s.client.JSONDel(ctx, key, "$"); err != nil {
		return types.WrapError(ErrCodeVectorStoreFailed, "failed to delete vector document", err)
	}

	return nil
}

// Health returns the current health status of the Redis vector store.
// It checks Redis connectivity and counts the number of vector documents.
func (s *RedisVectorStore) Health(ctx context.Context) types.HealthStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return types.NewHealthStatus(
			types.HealthStateUnhealthy,
			"redis vector store is closed",
		)
	}

	// Check Redis connectivity via state client
	if err := s.client.Health(ctx); err != nil {
		return types.NewHealthStatus(
			types.HealthStateUnhealthy,
			fmt.Sprintf("redis connection failed: %v", err),
		)
	}

	// Count vector documents using SCAN (pattern: gibson:vector:*)
	var count int64
	iter := s.client.Client().Scan(ctx, 0, "gibson:vector:*", 0).Iterator()
	for iter.Next(ctx) {
		count++
	}
	if err := iter.Err(); err != nil {
		return types.NewHealthStatus(
			types.HealthStateDegraded,
			fmt.Sprintf("failed to count vector documents: %v", err),
		)
	}

	return types.NewHealthStatus(
		types.HealthStateHealthy,
		fmt.Sprintf("redis vector store operational with %d records (dims: %d)", count, s.dims),
	)
}

// Close releases all resources held by the vector store.
// Note: This does NOT close the underlying StateClient, as it may be shared.
// The caller is responsible for closing the StateClient separately.
func (s *RedisVectorStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.closed = true
	return nil
}

// embeddingToFloat32Bytes converts a float64 embedding to FLOAT32 binary format
// for RediSearch VECTOR field. RediSearch expects little-endian FLOAT32 encoding.
//
// Binary format: [float32, float32, ..., float32]
// Each float32 is 4 bytes in little-endian byte order.
func embeddingToFloat32Bytes(embedding []float64) []byte {
	bytes := make([]byte, len(embedding)*4)

	for i, val := range embedding {
		// Convert float64 to float32
		float32Val := float32(val)

		// Encode as little-endian bytes
		bits := math.Float32bits(float32Val)
		offset := i * 4
		binary.LittleEndian.PutUint32(bytes[offset:offset+4], bits)
	}

	return bytes
}
