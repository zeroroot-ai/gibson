# Redis Lua Scripts

This document describes the Lua scripts used for atomic operations in the Gibson state package.

## Overview

All scripts are pre-compiled using `redis.NewScript()` and cached for performance. They use EVALSHA to avoid sending the script content on every execution.

## Scripts

### IncrementAndGetRunNumberScript

**Purpose**: Atomically increment and return a mission's run counter.

**Keys**:
- `KEYS[1]`: Counter key (e.g., `gibson:mission:run_counter:<mission_id>`)

**Arguments**: None

**Returns**: `int64` - The next run number (starting at 1)

**Usage**:
```go
runNumber, err := client.IncrementAndGetRunNumber(ctx, "mission-abc123")
```

**Thread Safety**: Fully atomic, safe for concurrent access.

**Error Handling**: Returns error if Redis command fails.

---

### CascadeDeleteMissionScript

**Purpose**: Atomically delete a mission and all related data structures using cursor-based iteration to avoid blocking on large datasets.

**Keys** (must be provided in this exact order):
- `KEYS[1]`: Mission document key (`gibson:mission:<id>`)
- `KEYS[2]`: Runs sorted set key (`gibson:mission:runs:<id>`)
- `KEYS[3]`: Events stream key (`gibson:events:<id>`)
- `KEYS[4]`: Memory index set key (`gibson:memory:idx:<id>`)
- `KEYS[5]`: Findings set key (`gibson:mission:findings:<id>`)

**Arguments**:
- `ARGV[1]`: Mission ID (used to construct run and memory keys)

**Returns**: `1` on success

**Usage**:
```go
err := client.CascadeDeleteMission(ctx, "mission-abc123")
```

**What Gets Deleted**:
1. Mission JSON document
2. All mission runs (from sorted set and their documents) - uses ZSCAN cursor iteration
3. Event stream
4. All memory entries (documents indexed by memory set) - uses SSCAN cursor iteration
5. Findings association set

**Performance Characteristics**:
- Uses ZSCAN with COUNT 100 to iterate runs without blocking
- Uses SSCAN with COUNT 100 to iterate memory entries without blocking
- Handles large datasets (thousands of runs/memory entries) gracefully
- No Redis server blocking even with large missions

**Thread Safety**: Fully atomic, ensures consistent deletion.

**Error Handling**: Returns error if any Redis command fails. Deletion stops at first error.

---

## Script Design Principles

### Cluster Compatibility
All scripts use `KEYS[]` array for key access to ensure Redis Cluster compatibility. Never use:
- `redis.call('KEYS', pattern)` - Not cluster-safe
- Hardcoded key names in script - Use KEYS[] array

### Error Handling
Scripts use `redis.call()` which throws errors and stops execution on failure. This ensures atomicity - partial operations are not committed.

### Idempotency
Scripts are designed to be idempotent where possible:
- `IncrementAndGetRunNumber`: Safe to retry if client doesn't receive response
- `CascadeDeleteMission`: Safe to call on non-existent mission

### Large Dataset Handling
Scripts that iterate over collections use cursor-based iteration to avoid blocking:
- `CascadeDeleteMission`: Uses ZSCAN/SSCAN with COUNT 100
- This prevents Redis server blocking even with thousands of items
- Each iteration processes a small batch, allowing other operations to interleave

### Performance
- Scripts are compiled once at package initialization
- EVALSHA is used automatically by go-redis
- Minimal round trips - single command per operation
- Efficient Lua: uses local variables, avoids table construction when possible

## Testing

Run integration tests with a Redis instance:
```bash
go test -v -run TestIncrementAndGetRunNumber
go test -v -run TestCascadeDeleteMission
```

Run unit tests (no Redis needed):
```bash
go test -v -run TestMissionKeys
```

## Examples

See `scripts_example_test.go` for complete examples of:
- Getting unique run numbers
- Cascade deleting missions
- Finding or creating missions atomically
- Running custom scripts
- Batching operations with pipelines
