package state

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// Lua scripts for atomic operations.
// These are compiled once and cached using EVALSHA for performance.
var (
	// IncrementAndGetRunNumberScript atomically increments and returns a mission run counter.
	// KEYS[1] = counter key (e.g., "gibson:mission:run_counter:<mission_id>")
	// Returns: next run number
	IncrementAndGetRunNumberScript = redis.NewScript(`
local key = KEYS[1]
local current = redis.call('GET', key)
if not current then
    current = 0
end
local next = tonumber(current) + 1
redis.call('SET', key, next)
return next
`)

	// CreateCredentialScript atomically creates a credential with name uniqueness check.
	// This prevents race conditions where two creates with the same name both succeed.
	// KEYS[1] = credential document key (e.g., "gibson:credential:<id>")
	// KEYS[2] = name lookup key (e.g., "gibson:credential:by_name:<name>")
	// ARGV[1] = credential JSON document
	// ARGV[2] = credential ID
	// Returns: "OK" on success, "EXISTS" if name already taken, error message on failure
	CreateCredentialScript = redis.NewScript(`
local doc_key = KEYS[1]
local name_key = KEYS[2]
local doc_json = ARGV[1]
local cred_id = ARGV[2]

-- Check if name lookup already exists
local existing = redis.call('GET', name_key)
if existing then
    return "EXISTS"
end

-- Atomically create both document and name lookup
redis.call('JSON.SET', doc_key, '$', doc_json)
redis.call('SET', name_key, cred_id)

return "OK"
`)

	// CascadeDeleteMissionScript atomically deletes a mission and all related data.
	// Uses SSCAN/ZSCAN cursor-based iteration to avoid blocking on large datasets.
	// KEYS[1] = mission key (e.g., "gibson:mission:<id>")
	// KEYS[2] = runs sorted set key (e.g., "gibson:mission:runs:<id>")
	// KEYS[3] = events stream key (e.g., "gibson:events:<id>")
	// KEYS[4] = memory index set key (e.g., "gibson:memory:idx:<id>")
	// KEYS[5] = findings set key (e.g., "gibson:mission:findings:<id>")
	// ARGV[1] = mission_id
	// Returns: 1 on success
	CascadeDeleteMissionScript = redis.NewScript(`
local mission_id = ARGV[1]
local mission_key = KEYS[1]
local runs_key = KEYS[2]
local events_stream = KEYS[3]
local memory_idx = KEYS[4]
local findings_set = KEYS[5]

-- Delete mission document
redis.call('JSON.DEL', mission_key)

-- Delete all runs using ZSCAN cursor-based iteration (handles large sorted sets)
local cursor = "0"
repeat
    local result = redis.call('ZSCAN', runs_key, cursor, 'COUNT', 100)
    cursor = result[1]
    local members = result[2]

    -- members is an array of [member, score, member, score, ...]
    -- we only want the members (odd indices in Lua, which are even indices in 0-based)
    for i = 1, #members, 2 do
        local run_id = members[i]
        redis.call('JSON.DEL', 'gibson:mission_run:' .. run_id)
    end
until cursor == "0"

-- Delete runs sorted set
redis.call('DEL', runs_key)

-- Delete event stream
redis.call('DEL', events_stream)

-- Delete memory entries using SSCAN cursor-based iteration (handles large sets)
cursor = "0"
repeat
    local result = redis.call('SSCAN', memory_idx, cursor, 'COUNT', 100)
    cursor = result[1]
    local members = result[2]

    for _, mem_key in ipairs(members) do
        redis.call('JSON.DEL', 'gibson:memory:' .. mission_id .. ':' .. mem_key)
    end
until cursor == "0"

-- Delete memory index set
redis.call('DEL', memory_idx)

-- Clear findings association
redis.call('DEL', findings_set)

return 1
`)
)

// RunScript executes a Lua script with the given keys and arguments.
// It uses EVALSHA for performance, falling back to EVAL if the script is not cached.
//
// Parameters:
//   - ctx: context for cancellation and timeout
//   - script: compiled redis.Script to execute
//   - keys: list of Redis keys accessed by the script (KEYS[] in Lua)
//   - args: variadic arguments passed to the script (ARGV[] in Lua)
//
// Returns:
//   - result: the script's return value (type depends on script)
//   - error: execution error, if any
//
// Example:
//
//	result, err := client.RunScript(ctx,
//	    IncrementAndGetRunNumberScript,
//	    []string{"gibson:mission:run_counter:abc123"},
//	)
//	if err != nil {
//	    return fmt.Errorf("failed to increment run number: %w", err)
//	}
//	runNumber := result.(int64)
func (c *StateClient) RunScript(ctx context.Context, script *redis.Script, keys []string, args ...interface{}) (interface{}, error) {
	if script == nil {
		return nil, fmt.Errorf("script cannot be nil")
	}

	result, err := script.Run(ctx, c.client, keys, args...).Result()
	if err != nil {
		return nil, fmt.Errorf("script execution failed: %w", err)
	}

	return result, nil
}

// Pipeline returns a Redis pipeline for batching non-atomic operations.
// Pipeline commands are buffered and executed together, improving performance
// for multiple independent operations.
//
// Note: Pipeline is NOT atomic. For atomic operations, use Lua scripts.
//
// Example:
//
//	pipe := client.Pipeline(ctx)
//	pipe.Set(ctx, "key1", "value1", 0)
//	pipe.Set(ctx, "key2", "value2", 0)
//	_, err := pipe.Exec(ctx)
func (c *StateClient) Pipeline(ctx context.Context) redis.Pipeliner {
	return c.client.Pipeline()
}

// IncrementAndGetRunNumber atomically increments and returns the next run number for a mission.
// This ensures unique, sequential run numbers even with concurrent operations.
//
// Parameters:
//   - ctx: context for cancellation and timeout
//   - missionID: the mission identifier
//
// Returns:
//   - runNumber: the next sequential run number (starts at 1)
//   - error: execution error, if any
//
// Example:
//
//	runNumber, err := client.IncrementAndGetRunNumber(ctx, "mission-abc123")
//	if err != nil {
//	    return fmt.Errorf("failed to get run number: %w", err)
//	}
//	fmt.Printf("Starting run #%d\n", runNumber)
func (c *StateClient) IncrementAndGetRunNumber(ctx context.Context, missionID string) (int64, error) {
	if missionID == "" {
		return 0, fmt.Errorf("missionID cannot be empty")
	}

	counterKey := fmt.Sprintf("gibson:mission:run_counter:%s", missionID)
	result, err := c.RunScript(ctx, IncrementAndGetRunNumberScript, []string{counterKey})
	if err != nil {
		return 0, fmt.Errorf("failed to increment run number for mission %s: %w", missionID, err)
	}

	runNumber, ok := result.(int64)
	if !ok {
		return 0, fmt.Errorf("unexpected script return type: %T", result)
	}

	return runNumber, nil
}

// CascadeDeleteMission atomically deletes a mission and all associated data.
// This includes:
//   - Mission document
//   - All mission runs
//   - Event stream
//   - Memory entries
//   - Findings associations
//
// Parameters:
//   - ctx: context for cancellation and timeout
//   - missionID: the mission identifier
//
// Returns:
//   - error: execution error, if any
//
// Example:
//
//	err := client.CascadeDeleteMission(ctx, "mission-abc123")
//	if err != nil {
//	    return fmt.Errorf("failed to delete mission: %w", err)
//	}
func (c *StateClient) CascadeDeleteMission(ctx context.Context, missionID string) error {
	if missionID == "" {
		return fmt.Errorf("missionID cannot be empty")
	}

	keys := missionKeys(missionID)
	_, err := c.RunScript(ctx, CascadeDeleteMissionScript, keys, missionID)
	if err != nil {
		return fmt.Errorf("failed to cascade delete mission %s: %w", missionID, err)
	}

	return nil
}

// FindOrCreateMissionResult represents the result of FindOrCreateMission operation.
type FindOrCreateMissionResult struct {
	// Created indicates whether a new mission was created (true) or found (false)
	Created bool
	// Key is the Redis key of the mission
	Key string
	// JSON is the mission document as JSON string
	JSON string
}

// FindOrCreateMission finds an existing mission by name or creates a new one.
// This uses application-level distributed locking to prevent duplicate creation.
//
// Implementation uses Redis distributed lock pattern:
//  1. SETNX to acquire lock on mission name
//  2. Double-check with FT.SEARCH after acquiring lock
//  3. Create if not found
//  4. DEL to release lock
//
// This approach is necessary because FT.SEARCH doesn't participate in Lua script
// atomicity, which can cause race conditions where concurrent creates both succeed.
//
// Parameters:
//   - ctx: context for cancellation and timeout
//   - name: mission name to search for
//   - missionJSON: JSON string of mission document to create if not found
//   - newID: ID to use for new mission if creation is needed
//
// Returns:
//   - result: contains Created flag, Key, and JSON
//   - error: execution error, if any
//
// Example:
//
//	missionData := `{"name":"test-mission","status":"pending"}`
//	result, err := client.FindOrCreateMission(ctx, "test-mission", missionData, "mission-123")
//	if err != nil {
//	    return fmt.Errorf("failed: %w", err)
//	}
//	if result.Created {
//	    fmt.Println("Created new mission")
//	} else {
//	    fmt.Println("Found existing mission")
//	}
func (c *StateClient) FindOrCreateMission(ctx context.Context, name, missionJSON, newID string) (*FindOrCreateMissionResult, error) {
	if name == "" {
		return nil, fmt.Errorf("name cannot be empty")
	}
	if missionJSON == "" {
		return nil, fmt.Errorf("missionJSON cannot be empty")
	}
	if newID == "" {
		return nil, fmt.Errorf("newID cannot be empty")
	}

	indexName := "gibson:idx:missions"
	lockKey := fmt.Sprintf("gibson:lock:mission:name:%s", name)
	const lockTTL = 10 // seconds

	// Step 1: Try to acquire distributed lock using SETNX
	// This prevents multiple concurrent creates for the same mission name
	acquired, err := c.client.SetNX(ctx, lockKey, "1", lockTTL).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to acquire lock: %w", err)
	}

	if !acquired {
		// Lock already held by another process, wait briefly and retry search
		// This handles the case where another goroutine is creating the mission
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(100 * time.Millisecond):
			// Continue to search after brief wait
		}
	}

	// Ensure lock is released when we're done
	defer func() {
		// Use background context for cleanup to ensure lock is released
		// even if original context is cancelled
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()
		c.client.Del(cleanupCtx, lockKey)
	}()

	// Step 2: Double-check pattern - search for existing mission after acquiring lock
	// This handles both initial search and retry-after-lock scenarios.
	//
	// Match against name_exact (TAG), NOT name (TEXT). TAG syntax `{...}` is an
	// exact whole-value match; the TEXT `name` field tokenizes and silently
	// misses names containing numeric/timestamp segments, producing duplicate
	// missions. See gibson#617 and MissionIndexSchemaVersion 3.
	escapedName := EscapeTag(name)
	searchQuery := fmt.Sprintf("@name_exact:{%s}", escapedName)

	searchResult, err := c.client.Do(ctx, "FT.SEARCH", indexName, searchQuery, "LIMIT", 0, 1).Result()
	if err != nil && err != redis.Nil {
		return nil, fmt.Errorf("search failed: %w", err)
	}

	// Parse search results — handle both RESP2 ([]interface{}) and RESP3 (map) formats
	if searchResult != nil {
		var foundCount int64
		var existingKey string

		switch v := searchResult.(type) {
		case []interface{}:
			// RESP2: [total, key, fields, ...]
			if len(v) >= 2 {
				if c, ok := v[0].(int64); ok {
					foundCount = c
				}
				if foundCount > 0 {
					if k, ok := v[1].(string); ok {
						existingKey = k
					}
				}
			}
		case map[interface{}]interface{}:
			// RESP3: {"total_results": N, "results": [{...}]}
			if totalVal, ok := v["total_results"]; ok {
				if c, err := parseInteger(totalVal); err == nil {
					foundCount = c
				}
			}
			if foundCount > 0 {
				if resultsVal, ok := v["results"]; ok {
					if results, ok := resultsVal.([]interface{}); ok && len(results) > 0 {
						if docMap, ok := results[0].(map[interface{}]interface{}); ok {
							if idVal, ok := docMap["id"]; ok {
								if k, ok := idVal.(string); ok {
									existingKey = k
								}
							}
						}
					}
				}
			}
		}

		if foundCount > 0 && existingKey != "" {
			// Get the full JSON document
			existingJSON, err := c.client.Do(ctx, "JSON.GET", existingKey, "$").Result()
			if err != nil {
				return nil, fmt.Errorf("failed to get existing mission JSON: %w", err)
			}

			jsonStr, ok := existingJSON.(string)
			if !ok {
				return nil, fmt.Errorf("unexpected JSON type: %T", existingJSON)
			}

			return &FindOrCreateMissionResult{
				Created: false,
				Key:     existingKey,
				JSON:    jsonStr,
			}, nil
		}
	}

	// Step 3: Create new mission - not found after lock acquisition
	newKey := fmt.Sprintf("gibson:mission:%s", newID)
	err = c.client.Do(ctx, "JSON.SET", newKey, "$", missionJSON).Err()
	if err != nil {
		return nil, fmt.Errorf("failed to create mission: %w", err)
	}

	return &FindOrCreateMissionResult{
		Created: true,
		Key:     newKey,
		JSON:    missionJSON,
	}, nil
}

// CreateCredentialAtomic atomically creates a credential with name uniqueness enforcement.
// This uses a Lua script to prevent race conditions where two concurrent creates
// with the same name could both succeed.
//
// Parameters:
//   - ctx: context for cancellation and timeout
//   - credID: credential ID
//   - name: credential name (must be unique)
//   - credentialJSON: JSON string of credential document
//
// Returns:
//   - error: ErrAlreadyExists if name is taken, other errors on failure
//
// Example:
//
//	err := client.CreateCredentialAtomic(ctx, "cred-123", "my-api-key", credJSON)
//	if err != nil {
//	    if errors.Is(err, state.ErrAlreadyExists) {
//	        fmt.Println("Credential name already taken")
//	    }
//	}
func (c *StateClient) CreateCredentialAtomic(ctx context.Context, credID, name, credentialJSON string) error {
	if credID == "" {
		return fmt.Errorf("credID cannot be empty")
	}
	if name == "" {
		return fmt.Errorf("name cannot be empty")
	}
	if credentialJSON == "" {
		return fmt.Errorf("credentialJSON cannot be empty")
	}

	docKey := fmt.Sprintf("gibson:credential:%s", credID)
	nameKey := fmt.Sprintf("gibson:credential:by_name:%s", name)

	result, err := c.RunScript(ctx, CreateCredentialScript, []string{docKey, nameKey}, credentialJSON, credID)
	if err != nil {
		return fmt.Errorf("failed to create credential: %w", err)
	}

	resultStr, ok := result.(string)
	if !ok {
		return fmt.Errorf("unexpected script return type: %T", result)
	}

	if resultStr == "EXISTS" {
		return fmt.Errorf("%w: credential with name %q already exists", ErrAlreadyExists, name)
	}

	if resultStr != "OK" {
		return fmt.Errorf("unexpected script result: %s", resultStr)
	}

	return nil
}

// missionKeys returns all Redis keys associated with a mission for cascade deletion.
// These keys must be passed to CascadeDeleteMissionScript in the correct order.
//
// Returns a slice of keys:
//   - [0] mission document key
//   - [1] runs sorted set key
//   - [2] events stream key
//   - [3] memory index set key
//   - [4] findings set key
func missionKeys(missionID string) []string {
	return []string{
		fmt.Sprintf("gibson:mission:%s", missionID),
		fmt.Sprintf("gibson:mission:runs:%s", missionID),
		fmt.Sprintf("gibson:events:%s", missionID),
		fmt.Sprintf("gibson:memory:idx:%s", missionID),
		fmt.Sprintf("gibson:mission:findings:%s", missionID),
	}
}
