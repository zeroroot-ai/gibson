// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package state

import (
	"context"
	"fmt"

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
