# Checkpoint Integration Tests

Comprehensive integration tests for Gibson's checkpointing system using real Redis Stack.

## Test Files

### redis_test.go
Tests for `RedisCheckpointStore` with real Redis operations:

- **TestRedisStore_SaveAndLoad**: Basic checkpoint save and load operations
- **TestRedisStore_ThreadIsolation**: Thread-level isolation of checkpoints
- **TestRedisStore_ListByThread**: Checkpoint listing with pagination and sorting
- **TestRedisStore_GetLatestByThread**: Latest checkpoint retrieval
- **TestRedisStore_DeleteCheckpoint**: Individual checkpoint deletion (documents limitation)
- **TestRedisStore_DeleteByThread**: Bulk deletion of all thread checkpoints
- **TestRedisStore_TTLExpiration**: TTL-based checkpoint expiration (requires time)
- **TestRedisStore_ConcurrentAccess**: Concurrent checkpoint creation (50 goroutines)

### blob_store_test.go
Tests for `RedisBlobStore` for large object storage:

- **TestBlobStore_StoreAndRetrieve**: Basic blob storage and retrieval
- **TestBlobStore_DeleteBlob**: Individual blob deletion
- **TestBlobStore_DeleteByThread**: Bulk deletion of all thread blobs
- **TestBlobStore_LargeBlob**: Large blob handling (1MB test)
- **TestBlobStore_TTL**: TTL-based blob expiration
- **TestBlobStore_ShouldStoreAsBlob**: Threshold detection logic
- **TestBlobStore_ThreadIsolation**: Thread-level blob isolation
- **TestBlobStore_EmptyData**: Edge case handling (empty/nil data)

### thread_test.go
Tests for `ThreadManager` thread lifecycle management:

- **TestThreadManager_CreateThread**: Primary thread creation
- **TestThreadManager_CreateBranchThread**: Branch thread creation with checkpoint
- **TestThreadManager_ListThreads**: Thread listing for a mission
- **TestThreadManager_SubgraphThreadID**: Hierarchical thread ID generation
- **TestThreadManager_ThreadStatusTransitions**: Thread status updates and terminal states
- **TestThreadManager_DeleteThread**: Thread deletion with checkpoint cleanup
- **TestThreadManager_ThreadMetadata**: Thread metadata handling
- **TestThreadManager_MultiMissionIsolation**: Mission-level thread isolation

### retention_test.go
Tests for `CheckpointPolicy` retention rules:

- **TestRetention_FinalOnly**: `RetentionFinalOnly` mode (keep only final checkpoint)
- **TestRetention_All**: `RetentionAll` mode (keep all checkpoints)
- **TestRetention_ErrorOnly**: `RetentionErrorOnly` mode (keep all for failures, final for success)
- **TestRetention_MaxCount**: `MaxCount` limit enforcement
- **TestRetention_TTLCleanup**: TTL-based cleanup of old checkpoints
- **TestRetention_RunningMissionProtection**: Running missions protected from retention
- **TestRetention_LabeledMode**: `RetentionLabeled` mode (keep labeled + final)
- **TestRetention_ShouldCheckpoint**: Checkpoint decision logic and rate limiting
- **TestRetention_AutoCheckpointDisabled**: Explicit-only checkpointing mode

## Running Tests

### With Docker (Automatic)

Tests automatically start a Redis Stack container using testcontainers:

```bash
# Run all checkpoint integration tests
go test -v ./tests/integration/checkpoint

# Run specific test
go test -v ./tests/integration/checkpoint -run TestRedisStore_SaveAndLoad

# Run with race detection
go test -v -race ./tests/integration/checkpoint

# Skip long-running tests (TTL expiration tests)
go test -v -short ./tests/integration/checkpoint

# Run with coverage
go test -v -coverprofile=coverage.out ./tests/integration/checkpoint
go tool cover -html=coverage.out
```

### With External Redis

If you have Redis Stack running externally:

```bash
export REDIS_URL="redis://localhost:6379"
go test -v ./tests/integration/checkpoint
```

### Requirements

- Docker installed (for automatic testcontainer mode)
- OR Redis Stack 7+ running externally
- Go 1.21+
- testcontainers-go package

## Test Infrastructure

### Container Management

- Uses `testcontainers-go` to start Redis Stack container automatically
- Container includes Redis with RedisJSON and RediSearch modules
- Gracefully skips tests if Docker is unavailable
- Automatic cleanup on test completion

### Key Isolation

Each test uses unique key prefixes to prevent interference:
- Pattern: `gibson:test:checkpoint:*`
- Tests clean up keys after completion using cursor-based SCAN
- Thread-level and mission-level isolation verified

### Test Helpers

Common helper functions in each test file:

- `setupRedis(t)`: Start Redis container and return client + cleanup function
- `createTestStore(t, client)`: Create `RedisCheckpointStore` for testing
- `createTestBlobStore(t, stateClient)`: Create `RedisBlobStore` for testing
- `createTestThreadManager(t, stateClient)`: Create `DefaultThreadManager` for testing
- `createTestPolicy(t, stateClient, config)`: Create `DefaultCheckpointPolicy` for testing
- `createTestCheckpoints(count, missionID, threadID)`: Generate test checkpoints
- `waitForExpiration(t, store, threadID, checkpointID, timeout)`: Wait for TTL expiration
- `cleanupKeys(ctx, client, pattern)`: Delete all keys matching pattern

## Test Coverage

### Checkpoint Store Operations
- ✅ Save checkpoint with metadata
- ✅ Load checkpoint with checksum verification
- ✅ List checkpoints with pagination (limit, offset)
- ✅ List checkpoints with sorting (ascending/descending)
- ✅ Get latest checkpoint for thread
- ✅ Delete individual checkpoint (limitation documented)
- ✅ Delete all checkpoints for thread
- ✅ Thread-level isolation
- ✅ TTL expiration
- ✅ Concurrent access (50 goroutines)

### Blob Store Operations
- ✅ Store and retrieve blobs
- ✅ Delete individual blob
- ✅ Delete all blobs for thread
- ✅ Large blob handling (1MB+)
- ✅ TTL expiration
- ✅ Threshold detection
- ✅ Thread-level isolation
- ✅ Edge cases (empty/nil data)

### Thread Management
- ✅ Create primary thread
- ✅ Create branch thread from checkpoint
- ✅ List threads for mission
- ✅ Generate hierarchical subgraph thread IDs
- ✅ Parse thread IDs
- ✅ Update thread status
- ✅ Thread status transitions
- ✅ Terminal state protection
- ✅ Delete thread with checkpoint cleanup
- ✅ Thread metadata
- ✅ Mission-level thread isolation

### Retention Policies
- ✅ RetentionFinalOnly mode
- ✅ RetentionAll mode
- ✅ RetentionErrorOnly mode
- ✅ RetentionLabeled mode
- ✅ MaxCount enforcement
- ✅ TTL-based cleanup
- ✅ Running mission protection
- ✅ Checkpoint decision logic
- ✅ Rate limiting
- ✅ Auto-checkpoint on/off

## Known Limitations

### DeleteCheckpoint by ID Alone

The current `RedisCheckpointStore` implementation requires a thread ID for efficient checkpoint deletion. The `DeleteCheckpoint(ctx, checkpointID)` method returns an error indicating that a reverse index is required.

This is by design for performance reasons - without a reverse index, we would need to scan all threads to find which one contains the checkpoint.

**Workarounds:**
- Use `DeleteThreadCheckpoints(ctx, threadID)` to delete all checkpoints for a thread
- Maintain a reverse index if individual checkpoint deletion by ID is required

## Performance Characteristics

### Checkpoint Operations
- Save: O(1) write + O(log N) sorted set insert
- Load latest: O(1) read
- List with pagination: O(log N + M) where M is limit
- Delete thread: O(N) where N is checkpoint count

### Blob Operations
- Store: O(1) write
- Retrieve: O(1) read
- Delete by thread: O(N) where N is blob count (uses SCAN)

### Thread Operations
- Create: O(1) write + O(log N) sorted set insert
- List: O(N) where N is thread count for mission
- Update: O(1) read + O(1) write

## Debugging

### View Redis Data

Connect to the test Redis container:
```bash
docker ps  # Find the container ID
docker exec -it <container-id> redis-cli

# View all test keys
KEYS gibson:test:checkpoint:*

# View checkpoint data
JSON.GET gibson:test:checkpoint:checkpoint:<thread>:<id>

# View sorted set index
ZRANGE gibson:test:checkpoint:checkpoint:index:<thread> 0 -1 WITHSCORES
```

### Test Logs

Tests use `t.Logf()` for debugging output. Run with `-v` to see logs:
```bash
go test -v ./tests/integration/checkpoint -run TestRedisStore_SaveAndLoad
```

### Race Detection

Run with race detector to find concurrency issues:
```bash
go test -v -race ./tests/integration/checkpoint
```

## CI/CD Integration

Tests are designed to be CI/CD friendly:

- Skip gracefully if Docker is unavailable
- Use `-short` flag to skip long-running tests
- Clean up resources automatically
- No external dependencies beyond Docker
- Fast execution (< 30s without -short flag)

### GitHub Actions Example

```yaml
- name: Run Checkpoint Integration Tests
  run: |
    go test -v -race ./tests/integration/checkpoint
  timeout-minutes: 5
```

## Future Enhancements

- [ ] Add cluster mode tests (Redis Cluster)
- [ ] Add failover tests (Redis Sentinel)
- [ ] Add hybrid blob storage tests (Redis + S3)
- [ ] Add checkpoint compression tests
- [ ] Add checkpoint encryption tests
- [ ] Add checkpoint versioning/migration tests
- [ ] Add stress tests (1000+ checkpoints per thread)
- [ ] Add benchmark tests for performance regression
