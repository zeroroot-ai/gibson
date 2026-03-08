# Redis Prompt Store Implementation

This document describes the Redis-based storage implementation for Gibson prompts with hot-reload capability.

## Overview

The Redis Prompt Store replaces the filesystem-based `~/.gibson/prompts/` directory with a Redis-backed storage system that provides:

- **Persistent storage** of prompts using RedisJSON
- **Hot reload** capability via Redis Pub/Sub
- **Concurrent access** with proper synchronization
- **Type-safe operations** with Go structs

## Architecture

### Key Components

1. **RedisPromptStore** - Main storage implementation
2. **PromptStore Interface** - Contract for prompt storage operations
3. **PromptChangeEvent** - Event notification for changes
4. **StateClient** - Underlying Redis client with JSON support

### Key Naming Convention

Prompts are stored in Redis with the following key pattern:

```
gibson:prompt:{name}
```

Example: `gibson:prompt:greeting`

### Pub/Sub Channel

Change notifications are published to:

```
gibson:prompts:changes
```

## Interface

### PromptStore Interface

```go
type PromptStore interface {
    Save(ctx context.Context, prompt *Prompt) error
    Get(ctx context.Context, name string) (*Prompt, error)
    List(ctx context.Context) ([]*Prompt, error)
    Delete(ctx context.Context, name string) error
    Exists(ctx context.Context, name string) (bool, error)
    Watch(ctx context.Context) (<-chan PromptChangeEvent, error)
}
```

### PromptChangeEvent

```go
type PromptChangeEvent struct {
    Type      ChangeType // "update" or "delete"
    Name      string
    Version   string
    Timestamp time.Time
}
```

## Redis Operations

### Save Operation

1. Validates prompt using `Prompt.Validate()`
2. Uses prompt name (or ID if name is empty) as key
3. Stores prompt as JSON document using `JSON.SET`
4. Publishes update event to pub/sub channel

**Redis Commands:**
```
JSON.SET gibson:prompt:{name} $ {json_data}
PUBLISH gibson:prompts:changes {event_json}
```

### Get Operation

1. Retrieves prompt by name using `JSON.GET`
2. Unmarshals JSON into Prompt struct
3. Returns `ErrPromptNotFound` if key doesn't exist

**Redis Commands:**
```
JSON.GET gibson:prompt:{name} $
```

### List Operation

1. Scans for all keys matching pattern `gibson:prompt:*`
2. Retrieves all prompts using `JSON.MGET` for efficiency
3. Unmarshals each result into Prompt struct
4. Returns empty slice if no prompts found

**Redis Commands:**
```
SCAN 0 MATCH gibson:prompt:* COUNT 100
JSON.MGET gibson:prompt:key1 gibson:prompt:key2 ... $
```

### Delete Operation

1. Checks if prompt exists using `EXISTS`
2. Deletes prompt using `JSON.DEL`
3. Publishes delete event to pub/sub channel
4. Returns `ErrPromptNotFound` if doesn't exist

**Redis Commands:**
```
EXISTS gibson:prompt:{name}
JSON.DEL gibson:prompt:{name} $
PUBLISH gibson:prompts:changes {event_json}
```

### Exists Operation

1. Checks key existence using `EXISTS`
2. Returns boolean result

**Redis Commands:**
```
EXISTS gibson:prompt:{name}
```

### Watch Operation

1. Subscribes to `gibson:prompts:changes` channel
2. Spawns goroutine to read from subscription
3. Unmarshals events and sends to output channel
4. Closes channel when context is cancelled
5. Supports concurrent watchers

**Redis Commands:**
```
SUBSCRIBE gibson:prompts:changes
```

## Hot Reload Implementation

The hot reload mechanism works as follows:

1. **Publisher**: When a prompt is saved or deleted, an event is published to the pub/sub channel
2. **Subscribers**: Applications call `Watch()` to receive change notifications
3. **Event Processing**: Subscribers receive events and can reload prompts automatically
4. **Graceful Shutdown**: Context cancellation cleanly closes subscriptions

### Example Hot Reload Pattern

```go
// Start watching for changes
ctx := context.Background()
eventCh, err := store.Watch(ctx)
if err != nil {
    return err
}

// Handle events
go func() {
    for event := range eventCh {
        switch event.Type {
        case ChangeTypeUpdate:
            // Reload the prompt
            prompt, err := store.Get(context.Background(), event.Name)
            if err == nil {
                registry.Register(*prompt)
            }
        case ChangeTypeDelete:
            // Remove from registry
            registry.Unregister(event.Name)
        }
    }
}()
```

## Error Handling

The implementation uses Gibson's error pattern:

- **Validation errors**: Return wrapped validation errors from `Prompt.Validate()`
- **Not found errors**: Return `NewPromptNotFoundError(name)`
- **Redis errors**: Wrap with descriptive context
- **Notification failures**: Don't fail save/delete operations, but return error message

## Concurrency

- **Thread-safe**: All operations are safe for concurrent use
- **Multiple watchers**: Supports multiple concurrent `Watch()` subscriptions
- **Non-blocking events**: Event channels are buffered (size 10) to prevent blocking
- **Context support**: All operations support context cancellation

## Testing

The implementation includes comprehensive tests:

### Unit Tests (`redis_store_test.go`)

- Save and Get operations
- Validation error handling
- List operations (empty and populated)
- Delete operations
- Exists checks
- Watch with events
- Context cancellation
- Complex prompt data
- Multiple updates

### Example Tests (`redis_store_example_test.go`)

- Save example
- Get example
- List example
- Watch example with hot reload
- Delete example
- Exists example

### Running Tests

Tests require a local Redis instance with RedisJSON module:

```bash
# Run all Redis store tests
go test -v ./internal/prompt -run TestRedisPromptStore

# Skip if Redis not available
go test -v ./internal/prompt -short
```

## Usage Example

```go
// Create StateClient
cfg := state.DefaultConfig()
cfg.URL = "redis://localhost:6379"
client, err := state.NewStateClient(cfg)
if err != nil {
    log.Fatal(err)
}
defer client.Close()

// Create store
store := prompt.NewRedisPromptStore(client)

// Save a prompt
p := &prompt.Prompt{
    ID:       "greeting",
    Name:     "greeting",
    Position: prompt.PositionSystem,
    Content:  "Hello {{.name}}!",
}
err = store.Save(context.Background(), p)

// Get a prompt
p, err = store.Get(context.Background(), "greeting")

// List all prompts
prompts, err := store.List(context.Background())

// Watch for changes
eventCh, err := store.Watch(context.Background())
for event := range eventCh {
    fmt.Printf("Change: %s %s\n", event.Type, event.Name)
}
```

## Migration from Filesystem

To migrate from filesystem-based prompts:

1. Load prompts from `~/.gibson/prompts/` using existing YAML loader
2. Save each prompt to Redis using `store.Save()`
3. Update daemon to use `RedisPromptStore` instead of filesystem
4. Set up hot reload watcher in daemon initialization

## Performance Considerations

- **JSON.MGET**: Used for bulk retrieval in `List()` operation
- **Buffered channels**: Watch uses buffered channel (size 10) to prevent blocking
- **Context timeouts**: All operations support context with timeout
- **Connection pooling**: Inherits from StateClient configuration

## Future Enhancements

- **Versioning**: Add version tracking to PromptChangeEvent
- **Namespaces**: Support multiple prompt namespaces
- **TTL support**: Optional expiration for temporary prompts
- **Batch operations**: Bulk save/delete operations
- **Search**: Integration with RediSearch for prompt discovery
- **Compression**: Optional compression for large prompts
