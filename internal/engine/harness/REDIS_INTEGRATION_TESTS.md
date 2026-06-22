# Redis Integration Tests

This document describes the Redis integration tests for the Gibson harness Redis tool execution system.

## Overview

The file `redis_integration_test.go` contains comprehensive integration tests for the Redis-only tool execution architecture. These tests validate:

1. Tool registration workflow (SADD tools:available, HSET tool:<name>:meta)
2. Work item push/pop flow
3. Pub/sub result delivery
4. Worker count management
5. Heartbeat mechanism
6. Full proxy execution flow
7. "No workers" error handling
8. RedisToolRegistry functionality

## Prerequisites

- **Redis Server**: Tests require a running Redis instance
- **Connection**: By default, connects to `redis://localhost:6379`
- **Environment Variable**: Set `REDIS_URL` to override the default Redis URL

## Running the Tests

### With Redis Available

If you have Redis running locally on port 6379:

```bash
# Run all Redis integration tests
go test -v -tags=integration -run TestRedisIntegration ./internal/harness

# Run a specific test
go test -v -tags=integration -run TestRedisIntegration_ToolRegistration ./internal/harness
```

### Without Redis

Tests will automatically skip if Redis is not available:

```bash
$ go test -v -tags=integration -run TestRedisIntegration ./internal/harness
=== RUN   TestRedisIntegration_ToolRegistration
--- SKIP: TestRedisIntegration_ToolRegistration (0.00s)
    redis_integration_test.go:45: Redis not available at redis://localhost:6379: failed to connect to Redis: dial tcp [::1]:6379: connect: connection refused
```

### Using Docker

Start a temporary Redis instance for testing:

```bash
# Start Redis in Docker
docker run -d --name redis-test -p 6379:6379 redis:7

# Run tests
go test -v -tags=integration -run TestRedisIntegration ./internal/harness

# Stop and remove Redis
docker stop redis-test && docker rm redis-test
```

### Using Custom Redis URL

```bash
export REDIS_URL="redis://my-redis-host:6380"
go test -v -tags=integration -run TestRedisIntegration ./internal/harness
```

## Test Coverage

### TestRedisIntegration_ToolRegistration
- Registers a tool in Redis
- Verifies tool metadata in `tools:available` set
- Validates `tool:<name>:meta` hash contents
- Tests `ListTools()` functionality

### TestRedisIntegration_PushPopWorkflow
- Creates and validates a WorkItem
- Pushes work to Redis queue
- Pops work from queue (simulating a worker)
- Verifies all work item fields are preserved
- Checks work item age calculation

### TestRedisIntegration_PubSubResultDelivery
- Subscribes to a results channel before publishing
- Publishes a Result to the channel
- Verifies result delivery via pub/sub
- Validates all result fields
- Tests result duration calculation

### TestRedisIntegration_WorkerCount
- Tests initial worker count (0)
- Increments worker count multiple times
- Decrements worker count
- Verifies count accuracy at each step

### TestRedisIntegration_Heartbeat
- Sends heartbeat for a tool
- Verifies heartbeat doesn't error
- Note: TTL expiration not tested (requires 30+ second wait)

### TestRedisIntegration_ProxyExecution
- Registers a tool with metadata
- Creates a RedisToolProxy instance
- Spawns a simulated worker goroutine
- Executes tool via proxy
- Worker pops work, processes, and publishes result
- Verifies end-to-end execution flow
- Tests all proxy methods (Name, Version, Description, Tags, etc.)

### TestRedisIntegration_NoWorkersError
- Registers a tool with zero workers
- Checks health status (should be unhealthy)
- Attempts to execute tool
- Verifies timeout error when no workers available
- Tests "no workers available" error path

### TestRedisIntegration_RedisToolRegistry
- Tests RedisToolRegistry.Refresh()
- Verifies tool discovery and registration
- Tests Get(), List(), GetMetadata()
- Validates health checks with/without workers
- Tests worker count and heartbeat integration
- Verifies GetHealthStatus() output format
- Tests registry.Count() and Close()

## Test Structure

All tests follow this pattern:

1. **Setup**: Connect to Redis (or skip if unavailable)
2. **Test**: Execute test-specific logic with unique key prefixes
3. **Cleanup**: Close Redis client (keys remain for manual inspection)

### Key Naming Convention

Tests use predictable, unique tool names to avoid conflicts:

- `test-tool-registration-<uuid>`
- `test-tool-pushpop-<uuid>`
- `test-tool-proxy-<uuid>`
- etc.

This allows multiple test runs without manual cleanup, though a Redis FLUSHDB may be needed occasionally.

## Debugging

### Enable Debug Logging

Tests use `slog` with text output to stdout. Increase verbosity:

```go
logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
    Level: slog.LevelDebug,
}))
```

### Inspect Redis State

During or after test runs:

```bash
# List all tools
redis-cli SMEMBERS tools:available

# View tool metadata
redis-cli HGETALL tool:test-tool-registration-abc123:meta

# Check worker count
redis-cli GET tool:test-tool-registration-abc123:workers

# Check health key TTL
redis-cli TTL tool:test-tool-registration-abc123:health

# List queue contents
redis-cli LRANGE tool:test-tool-pushpop-abc123:queue 0 -1
```

## Integration with CI/CD

### GitHub Actions Example

```yaml
name: Integration Tests

on: [push, pull_request]

jobs:
  redis-integration:
    runs-on: ubuntu-latest

    services:
      redis:
        image: redis:7
        ports:
          - 6379:6379
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5

    steps:
      - uses: actions/checkout@v3

      - name: Set up Go
        uses: actions/setup-go@v4
        with:
          go-version: '1.21'

      - name: Run Redis Integration Tests
        run: |
          go test -v -tags=integration -run TestRedisIntegration ./internal/harness
```

## Known Limitations

1. **No Automatic Cleanup**: Tests don't automatically clean up Redis keys. Use `FLUSHDB` manually if needed.
2. **No TTL Testing**: Heartbeat TTL expiration isn't tested due to 30+ second wait time.
3. **Local Only**: Tests assume Redis is accessible; doesn't test Redis Cluster or Sentinel configurations.
4. **No Authentication**: Tests don't cover Redis AUTH or TLS connections (though SDK supports them).

## Future Enhancements

- [ ] Add tests for batch execution (multiple work items per job)
- [ ] Test Redis connection failure recovery
- [ ] Test concurrent proxy execution
- [ ] Test tool metadata updates and registry refresh
- [ ] Test queue depth monitoring
- [ ] Add performance/benchmark tests
- [ ] Test error result propagation
- [ ] Test trace context propagation with real OpenTelemetry
