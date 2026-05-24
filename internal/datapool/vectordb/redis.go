package vectordb

import (
	"context"
	"encoding/binary"
	"fmt"
	"math"
	"strings"

	"github.com/redis/go-redis/v9"
)

// RedisConfig holds connection parameters for the Redis VSS adapter.
// Connection details (addr, password) mirror the RedisCredentials payload
// at tenant/<id>/infra/redis; the per-tenant index name is supplied via
// the collection argument to For().
type RedisConfig struct {
	// Addr is the Redis host:port.
	Addr string

	// Password is the Redis AUTH password.
	Password string

	// DB is the Redis logical database index.
	DB int
}

// redisDriver is the Redis VSS (RediSearch FT.*) implementation of Driver.
// It holds a single *redis.Client shared across all tenant Client instances.
// The struct is safe for concurrent use.
type redisDriver struct {
	client *redis.Client
}

// NewRedisVSSDriver creates a Driver backed by Redis VSS (RediSearch FT.*
// commands). The driver holds one connection shared across all tenant Clients
// and must be closed when the process shuts down.
//
// The provisioner (tenant-operator) creates per-tenant indexes with:
//
//	FT.CREATE vector_idx:tenant_<id> ON HASH PREFIX 1 vec:tenant_<id>:
//	  SCHEMA embedding VECTOR HNSW 6 DIM 1536 DISTANCE_METRIC COSINE TYPE FLOAT32
//
// For() verifies that the named index exists before returning a Client;
// a missing index results in an error whose message contains "not found".
func NewRedisVSSDriver(cfg RedisConfig) (Driver, error) {
	if cfg.Addr == "" {
		return nil, fmt.Errorf("vectordb: redis: addr is required")
	}
	client := redis.NewClient(&redis.Options{
		Addr:     cfg.Addr,
		Password: cfg.Password,
		DB:       cfg.DB,
	})
	return &redisDriver{client: client}, nil
}

// For returns a Client scoped to the named RediSearch index (collection).
//
// collection is the full index name as stored by the tenant-operator, e.g.
// "vector_idx:tenant_acme". The key prefix for hash documents is derived
// automatically (see deriveKeyPrefix).
//
// Returns an error whose message contains "not found" if the index does not
// exist; vector_per_tenant.go translates this to *NotProvisionedError.
func (d *redisDriver) For(ctx context.Context, collection string) (Client, error) {
	if collection == "" {
		return nil, fmt.Errorf("vectordb: redis: collection (index name) is required")
	}
	// Verify the index exists before handing a Client to the caller.
	if err := d.client.Do(ctx, "FT.INFO", collection).Err(); err != nil {
		msg := err.Error()
		// RediSearch returns "ERR no such index" (v1/v2) or "Unknown Index name"
		// depending on the server version; match both.
		if strings.Contains(msg, "no such index") || strings.Contains(strings.ToLower(msg), "unknown index") {
			return nil, fmt.Errorf("vectordb: redis: index %q not found", collection)
		}
		return nil, fmt.Errorf("vectordb: redis: FT.INFO %q: %w", collection, err)
	}
	return &redisClient{
		client:     d.client,
		collection: collection,
		keyPrefix:  deriveKeyPrefix(collection),
	}, nil
}

// Close shuts down the underlying Redis connection.
func (d *redisDriver) Close() error {
	return d.client.Close()
}

// deriveKeyPrefix converts a RediSearch index name to the hash key prefix
// used for document keys.  The provisioner always creates indexes whose name
// follows the pattern "vector_idx:<tenant_suffix>" and whose PREFIX clause
// points to "vec:<tenant_suffix>:".
//
// Examples:
//
//	"vector_idx:tenant_acme"  → "vec:tenant_acme:"
//	"vector_idx:tenant_abc"   → "vec:tenant_abc:"
func deriveKeyPrefix(indexName string) string {
	suffix := strings.TrimPrefix(indexName, "vector_idx:")
	return "vec:" + suffix + ":"
}

// redisClient is a vectordb.Client scoped to a single RediSearch index.
type redisClient struct {
	client     *redis.Client
	collection string
	keyPrefix  string
}

// float32sToBytes encodes a []float32 as little-endian bytes for the Redis VSS
// VECTOR field format.  Redis Stack requires vectors as raw little-endian
// IEEE 754 float32 bytes.
func float32sToBytes(fs []float32) []byte {
	buf := make([]byte, len(fs)*4)
	for i, f := range fs {
		binary.LittleEndian.PutUint32(buf[i*4:], math.Float32bits(f))
	}
	return buf
}

// Upsert inserts or overwrites points in the tenant's RediSearch hash set.
// Each point is stored as a Redis HASH at key "<keyPrefix><id>" with fields:
//   - embedding: raw FLOAT32 bytes (little-endian)
//   - one field per Payload entry (string-serialised)
//
// The pipeline is submitted in a single round-trip; if any HSET fails the
// error is returned and the pipeline result is partial.
func (c *redisClient) Upsert(ctx context.Context, points []Point) error {
	if len(points) == 0 {
		return nil
	}
	pipe := c.client.Pipeline()
	for _, p := range points {
		key := c.keyPrefix + p.ID
		// Pre-allocate: embedding field + 2 slots per payload entry.
		fields := make([]interface{}, 0, 2+len(p.Payload)*2)
		fields = append(fields, "embedding", float32sToBytes(p.Vector))
		for k, v := range p.Payload {
			fields = append(fields, k, fmt.Sprintf("%v", v))
		}
		pipe.HSet(ctx, key, fields...)
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("vectordb: redis: Upsert pipeline: %w", err)
	}
	return nil
}

// Search performs a k-nearest-neighbour search using RediSearch's VECTOR KNN
// query syntax.  filter may be nil (no payload pre-filter).
//
// The query dialect is 2 (required for vector similarity); PARAMS passes the
// query vector as a named parameter "$vec".  Results are returned in ascending
// score order (lower cosine distance = higher similarity for COSINE metric).
func (c *redisClient) Search(ctx context.Context, vector []float32, k uint64, filter *Filter) ([]SearchResult, error) {
	query := buildKNNQuery(k, filter)
	res, err := c.client.Do(ctx,
		"FT.SEARCH", c.collection, query,
		"PARAMS", "2", "vec", float32sToBytes(vector),
		"RETURN", "2", "score", "__score",
		"SORTBY", "score",
		"DIALECT", "2",
		"LIMIT", "0", fmt.Sprintf("%d", k),
	).Result()
	if err != nil {
		return nil, fmt.Errorf("vectordb: redis: Search: %w", err)
	}
	return parseSearchResults(res, c.keyPrefix)
}

// buildKNNQuery constructs the FT.SEARCH query string.
// With filter:  "(@field:{value})=>[KNN k @embedding $vec AS score]"
// Without:      "(*)=>[KNN k @embedding $vec AS score]"
func buildKNNQuery(k uint64, filter *Filter) string {
	var preFilter string
	if filter != nil && len(filter.Must) > 0 {
		parts := make([]string, 0, len(filter.Must))
		for _, cond := range filter.Must {
			parts = append(parts, fmt.Sprintf("(@%s:{%v})", cond.Key, cond.Value))
		}
		preFilter = strings.Join(parts, " ")
	} else {
		preFilter = "*"
	}
	return fmt.Sprintf("(%s)=>[KNN %d @embedding $vec AS score]", preFilter, k)
}

// parseSearchResults decodes the raw FT.SEARCH reply into []SearchResult.
//
// go-redis v9 with Redis Stack 7.x returns FT.SEARCH results in RESP3 format
// as a map[interface{}]interface{} with the following structure:
//
//	{
//	  "total_results": int64,
//	  "results": []interface{}{
//	    map[interface{}]interface{}{
//	      "id":               string,        // full hash key, e.g. "vec:tenant_acme:uuid"
//	      "extra_attributes": map[interface{}]interface{}{
//	        "score": string,                 // KNN distance as a decimal string
//	        ...other RETURN fields...
//	      },
//	      "values": []interface{},
//	    },
//	    ...
//	  },
//	  "attributes": []interface{},
//	  "format":     string,
//	  "warning":    []interface{},
//	}
//
// The key prefix is stripped from the "id" field to recover the Point ID.
func parseSearchResults(raw interface{}, keyPrefix string) ([]SearchResult, error) {
	top, ok := raw.(map[interface{}]interface{})
	if !ok {
		// Unexpected format — return empty rather than panic.
		return nil, nil
	}
	rawResults, _ := top["results"]
	arr, ok := rawResults.([]interface{})
	if !ok || len(arr) == 0 {
		return nil, nil
	}

	results := make([]SearchResult, 0, len(arr))
	for _, item := range arr {
		rm, ok := item.(map[interface{}]interface{})
		if !ok {
			continue
		}
		id, _ := rm["id"].(string)
		id = strings.TrimPrefix(id, keyPrefix)

		var score float32
		payload := make(map[string]any)

		if ea, ok := rm["extra_attributes"].(map[interface{}]interface{}); ok {
			for k, v := range ea {
				fieldName, _ := k.(string)
				fieldVal := fmt.Sprintf("%v", v)
				switch fieldName {
				case "score", "__score":
					if _, err := fmt.Sscanf(fieldVal, "%f", &score); err != nil {
						score = 0
					}
				default:
					payload[fieldName] = fieldVal
				}
			}
		}

		results = append(results, SearchResult{ID: id, Score: score, Payload: payload})
	}
	return results, nil
}

// Delete removes points by ID from the tenant's hash set.
// IDs that do not exist are silently ignored (Redis DEL is idempotent).
func (c *redisClient) Delete(ctx context.Context, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	keys := make([]string, len(ids))
	for i, id := range ids {
		keys[i] = c.keyPrefix + id
	}
	if err := c.client.Del(ctx, keys...).Err(); err != nil {
		return fmt.Errorf("vectordb: redis: Delete: %w", err)
	}
	return nil
}
