package state

import (
	"context"
	"fmt"
	"strings"

	"github.com/redis/go-redis/v9"
)

// StateClient provides a unified Redis client for all Gibson state operations.
// It wraps redis.UniversalClient to support standalone, cluster, and sentinel modes.
type StateClient struct {
	client redis.UniversalClient
	config *Config
}

// NewStateClient creates a new StateClient with the given configuration.
// It establishes a connection to Redis, tests connectivity, and detects
// required modules (RediSearch, RedisJSON).
//
// Returns ErrConnectionFailed if the connection cannot be established.
// Returns ErrModuleNotAvailable if required modules are not loaded.
//
// Example:
//
//	cfg := state.DefaultConfig()
//	cfg.URL = "redis://localhost:6379"
//
//	client, err := state.NewStateClient(cfg)
//	if err != nil {
//	    log.Fatalf("failed to create client: %v", err)
//	}
//	defer client.Close()
func NewStateClient(cfg *Config) (*StateClient, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	// Apply defaults to ensure all fields are set
	cfg.ApplyDefaults()

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	// Create the appropriate client based on configuration
	var client redis.UniversalClient

	if cfg.ClusterMode {
		// Cluster mode
		client = redis.NewClusterClient(&redis.ClusterOptions{
			Addrs:           cfg.ClusterAddrs,
			Password:        cfg.Password,
			PoolSize:        cfg.PoolSize,
			MinIdleConns:    cfg.MinIdleConns,
			MaxRetries:      cfg.MaxRetries,
			DialTimeout:     cfg.DialTimeout,
			ReadTimeout:     cfg.ReadTimeout,
			WriteTimeout:    cfg.WriteTimeout,
			PoolTimeout:     cfg.PoolTimeout,
			ConnMaxLifetime: cfg.MaxConnAge,
			ConnMaxIdleTime: cfg.IdleTimeout,
			TLSConfig:       cfg.TLSConfig,
		})
	} else if cfg.SentinelMaster != "" {
		// Sentinel mode
		client = redis.NewFailoverClient(&redis.FailoverOptions{
			MasterName:       cfg.SentinelMaster,
			SentinelAddrs:    cfg.SentinelAddrs,
			SentinelPassword: cfg.SentinelPassword,
			Password:         cfg.Password,
			DB:               cfg.Database,
			PoolSize:         cfg.PoolSize,
			MinIdleConns:     cfg.MinIdleConns,
			MaxRetries:       cfg.MaxRetries,
			DialTimeout:      cfg.DialTimeout,
			ReadTimeout:      cfg.ReadTimeout,
			WriteTimeout:     cfg.WriteTimeout,
			PoolTimeout:      cfg.PoolTimeout,
			ConnMaxLifetime:  cfg.MaxConnAge,
			ConnMaxIdleTime:  cfg.IdleTimeout,
			TLSConfig:        cfg.TLSConfig,
		})
	} else {
		// Standalone mode
		opts, err := redis.ParseURL(cfg.URL)
		if err != nil {
			return nil, NewConnectionError("parse", cfg.URL, err)
		}

		// Override with config values
		if cfg.Password != "" {
			opts.Password = cfg.Password
		}
		opts.DB = cfg.Database
		opts.PoolSize = cfg.PoolSize
		opts.MinIdleConns = cfg.MinIdleConns
		opts.MaxRetries = cfg.MaxRetries
		opts.DialTimeout = cfg.DialTimeout
		opts.ReadTimeout = cfg.ReadTimeout
		opts.WriteTimeout = cfg.WriteTimeout
		opts.PoolTimeout = cfg.PoolTimeout
		opts.ConnMaxLifetime = cfg.MaxConnAge
		opts.ConnMaxIdleTime = cfg.IdleTimeout
		opts.TLSConfig = cfg.TLSConfig

		client = redis.NewClient(opts)
	}

	// Test the connection
	ctx, cancel := context.WithTimeout(context.Background(), cfg.DialTimeout)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		client.Close()
		return nil, NewConnectionError("ping", cfg.URL, fmt.Errorf("%w: %v", ErrConnectionFailed, err))
	}

	sc := &StateClient{
		client: client,
		config: cfg,
	}

	// Check module availability
	if err := sc.Health(ctx); err != nil {
		client.Close()
		return nil, err
	}

	return sc, nil
}

// NewStateClientFromRedis wraps an already-established redis.UniversalClient in a
// StateClient without opening a new connection or running the connectivity /
// module-availability probe NewStateClient performs.
//
// It exists for the per-tenant data-plane: the datapool hands out a
// *redis.Client bound to a tenant's dedicated logical DB (Conn.Redis), and code
// that needs the StateClient JSON / index helpers against THAT tenant's keyspace
// (e.g. the re-embed job, gibson#809/#940) wraps it here. The returned client
// borrows the underlying connection — it does NOT own it, so Close() on the
// wrapper would close the shared pool; callers that wrap a pooled client must
// NOT call Close on the wrapper (the pool owns the lifecycle).
//
// client must be non-nil and already connected. config may be nil; a nil config
// yields DefaultConfig() so Config() never returns a zero value.
func NewStateClientFromRedis(client redis.UniversalClient, config *Config) *StateClient {
	if config == nil {
		config = DefaultConfig()
		config.ApplyDefaults()
	}
	return &StateClient{
		client: client,
		config: config,
	}
}

// Health checks the Redis connection and verifies required modules are loaded.
// It performs the following checks:
//  1. Ping to ensure connectivity
//  2. MODULE LIST to detect RediSearch
//  3. MODULE LIST to detect RedisJSON
//
// Returns ErrConnectionFailed if ping fails.
// Returns ErrModuleNotAvailable if required modules are missing.
func (c *StateClient) Health(ctx context.Context) error {
	// Check basic connectivity
	if err := c.client.Ping(ctx).Err(); err != nil {
		return NewConnectionError("ping", "", fmt.Errorf("%w: %v", ErrConnectionFailed, err))
	}

	// Check for required modules
	modules, err := c.client.Do(ctx, "MODULE", "LIST").Result()
	if err != nil {
		// MODULE LIST command may not be supported in all Redis versions
		// Treat this as a warning rather than a fatal error
		return nil
	}

	// Parse module list - handle both RESP2 ([]interface{}) and RESP3 (maps) formats
	moduleList, ok := modules.([]interface{})
	if !ok {
		// Unexpected response format, skip module check
		return nil
	}

	hasSearch := false
	hasJSON := false

	for _, mod := range moduleList {
		// Try RESP3 format first (map[interface{}]interface{})
		if modMap, ok := mod.(map[interface{}]interface{}); ok {
			if name, exists := modMap["name"]; exists {
				if nameStr, ok := name.(string); ok {
					nameLower := strings.ToLower(nameStr)
					if nameLower == "search" || nameLower == "ft" {
						hasSearch = true
					}
					if nameLower == "rejson" || nameLower == "json" {
						hasJSON = true
					}
				}
			}
			continue
		}

		// Fallback to RESP2 format ([]interface{})
		modInfo, ok := mod.([]interface{})
		if !ok || len(modInfo) < 2 {
			continue
		}

		// Module info is typically: ["name", "modulename", "ver", version]
		for i := 0; i < len(modInfo); i += 2 {
			if i+1 >= len(modInfo) {
				break
			}

			key, keyOk := modInfo[i].(string)
			val, valOk := modInfo[i+1].(string)
			if !keyOk || !valOk {
				continue
			}

			if key == "name" {
				valLower := strings.ToLower(val)
				if valLower == "search" || valLower == "ft" {
					hasSearch = true
				}
				if valLower == "rejson" || valLower == "json" {
					hasJSON = true
				}
			}
		}
	}

	// Check for required modules
	if !hasSearch {
		return NewModuleError("search", ErrModuleNotAvailable)
	}

	if !hasJSON {
		return NewModuleError("ReJSON", ErrModuleNotAvailable)
	}

	return nil
}

// Close closes the Redis connection and releases all resources.
// It should be called when the StateClient is no longer needed.
func (c *StateClient) Close() error {
	if c.client == nil {
		return nil
	}
	return c.client.Close()
}

// Client returns the underlying redis.UniversalClient for advanced operations.
// This provides direct access to Redis commands not wrapped by StateClient.
//
// Example:
//
//	rdb := client.Client()
//	rdb.Set(ctx, "key", "value", 0)
//	val, err := rdb.Get(ctx, "key").Result()
func (c *StateClient) Client() redis.UniversalClient {
	return c.client
}

// Config returns a copy of the client's configuration.
// This is useful for debugging and logging purposes.
func (c *StateClient) Config() Config {
	if c.config == nil {
		return Config{}
	}
	// Return a copy to prevent external modification
	return *c.config
}

// EnsureIndexes creates all RediSearch indexes for Gibson entities.
// This should be called during daemon startup to initialize the search infrastructure.
// The operation is idempotent - existing indexes are not recreated.
//
// Returns an error if index creation fails.
//
// Example:
//
//	client, err := state.NewStateClient(cfg)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer client.Close()
//
//	if err := client.EnsureIndexes(ctx); err != nil {
//	    log.Fatalf("failed to create indexes: %v", err)
//	}
func (c *StateClient) EnsureIndexes(ctx context.Context) error {
	return c.EnsureIndexesWithObserver(ctx, nil)
}

// EnsureIndexesWithObserver creates all RediSearch indexes and, for each index that
// undergoes an online re-index, calls reindexObserver(indexName, durationSeconds).
// Pass nil for reindexObserver to silence the callback.
//
// Callers in the daemon startup path should wire this to the
// gibson_redisearch_reindex_duration_seconds histogram:
//
//	meter := provider.Meter("gibson")
//	hist, _ := meter.Float64Histogram("gibson_redisearch_reindex_duration_seconds")
//	client.EnsureIndexesWithObserver(ctx, func(name string, secs float64) {
//	    hist.Record(ctx, secs, metric.WithAttributes(attribute.String("index", name)))
//	})
func (c *StateClient) EnsureIndexesWithObserver(
	ctx context.Context,
	reindexObserver func(indexName string, durationSeconds float64),
) error {
	manager := NewIndexManager(c.client).WithReindexObserver(reindexObserver)
	return manager.EnsureAllIndexes(ctx)
}
