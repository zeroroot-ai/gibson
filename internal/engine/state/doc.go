// Package state provides unified Redis-based state management for Gibson.
//
// This package replaces the SQLite-based storage with Redis Stack,
// leveraging RedisJSON for document storage, RediSearch for full-text
// search and filtering, and Redis Streams for event logging.
//
// # Architecture
//
// The state package is built around the StateClient, which wraps a
// redis.UniversalClient to support standalone, cluster, and sentinel
// deployment modes. All Gibson components access Redis through this
// unified client.
//
// Key features:
//   - RedisJSON for structured document storage
//   - RediSearch for full-text search and secondary indexes
//   - Redis Streams for event logs and real-time subscriptions
//   - Cluster and Sentinel support via UniversalClient
//   - Health checks with module availability detection
//   - Configurable connection pooling and timeouts
//
// # Usage
//
// Create a StateClient with configuration:
//
//	cfg := &state.Config{
//	    URL:            "redis://localhost:6379",
//	    Password:       "",
//	    Database:       0,
//	    PoolSize:       10,
//	    ConnectTimeout: 5 * time.Second,
//	}
//	cfg.ApplyDefaults()
//
//	client, err := state.NewStateClient(cfg)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer client.Close()
//
// Check health and module availability:
//
//	if err := client.Health(ctx); err != nil {
//	    log.Fatal("Redis not healthy:", err)
//	}
//
// # Module Requirements
//
// The state package requires Redis Stack with:
//   - RedisJSON (JSON.* commands) for document storage
//   - RediSearch (FT.* commands) for full-text search
//
// The Health() method verifies both modules are available.
//
// # Key Naming Conventions
//
// All Redis keys follow a consistent naming pattern:
//   - Documents: gibson:{type}:{id} (e.g., gibson:mission:abc123)
//   - Indexes: gibson:idx:{type} (e.g., gibson:idx:missions)
//   - Streams: gibson:stream:{type}:{id} (e.g., gibson:stream:mission:abc123:events)
//   - Sets: gibson:{type}:by_{field}:{value} (e.g., gibson:mission:by_status:running)
//   - Counters: gibson:counter:{type}:{name} (e.g., gibson:counter:mission:test:run)
//
// # Error Handling
//
// The package defines standard errors:
//   - ErrNotFound: Document/key not found (wraps redis.Nil)
//   - ErrModuleNotAvailable: Required Redis module missing
//   - ErrConnectionFailed: Redis connection failed
//
// Use IsNotFound() to check for not-found errors consistently.
package state
