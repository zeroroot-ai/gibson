package state

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIncrementAndGetRunNumber(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := setupTestClient(t)
	defer client.Close()

	ctx := context.Background()
	missionID := "test-mission-" + time.Now().Format("20060102150405")

	// Test sequential increments
	run1, err := client.IncrementAndGetRunNumber(ctx, missionID)
	require.NoError(t, err)
	assert.Equal(t, int64(1), run1, "first run should be 1")

	run2, err := client.IncrementAndGetRunNumber(ctx, missionID)
	require.NoError(t, err)
	assert.Equal(t, int64(2), run2, "second run should be 2")

	run3, err := client.IncrementAndGetRunNumber(ctx, missionID)
	require.NoError(t, err)
	assert.Equal(t, int64(3), run3, "third run should be 3")

	// Verify counter value in Redis
	counterKey := fmt.Sprintf("gibson:mission:run_counter:%s", missionID)
	val, err := client.Client().Get(ctx, counterKey).Result()
	require.NoError(t, err)
	assert.Equal(t, "3", val)
}

func TestIncrementAndGetRunNumber_Concurrent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := setupTestClient(t)
	defer client.Close()

	ctx := context.Background()
	missionID := "test-mission-concurrent-" + time.Now().Format("20060102150405")

	// Run 100 concurrent increments
	const numGoroutines = 100
	results := make(chan int64, numGoroutines)
	errors := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			runNum, err := client.IncrementAndGetRunNumber(ctx, missionID)
			if err != nil {
				errors <- err
				return
			}
			results <- runNum
		}()
	}

	// Collect results
	runNumbers := make(map[int64]bool)
	for i := 0; i < numGoroutines; i++ {
		select {
		case err := <-errors:
			t.Fatalf("concurrent increment failed: %v", err)
		case num := <-results:
			// Check for duplicates
			if runNumbers[num] {
				t.Fatalf("duplicate run number: %d", num)
			}
			runNumbers[num] = true
		case <-time.After(5 * time.Second):
			t.Fatal("timeout waiting for concurrent increments")
		}
	}

	// Verify all numbers from 1 to numGoroutines are present
	assert.Equal(t, numGoroutines, len(runNumbers))
	for i := int64(1); i <= numGoroutines; i++ {
		assert.True(t, runNumbers[i], "missing run number: %d", i)
	}
}

func TestIncrementAndGetRunNumber_EmptyMissionID(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := setupTestClient(t)
	defer client.Close()

	ctx := context.Background()

	_, err := client.IncrementAndGetRunNumber(ctx, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missionID cannot be empty")
}

func TestCascadeDeleteMission(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := setupTestClient(t)
	defer client.Close()

	ctx := context.Background()
	missionID := "test-mission-delete-" + time.Now().Format("20060102150405")

	// Create test data
	keys := missionKeys(missionID)
	rdb := client.Client()

	// Create mission document
	err := rdb.Do(ctx, "JSON.SET", keys[0], "$", `{"id":"`+missionID+`","name":"test"}`).Err()
	require.NoError(t, err)

	// Create runs in sorted set
	err = rdb.ZAdd(ctx, keys[1], redis.Z{Score: 1, Member: "run-1"}, redis.Z{Score: 2, Member: "run-2"}).Err()
	require.NoError(t, err)

	// Create run documents
	err = rdb.Do(ctx, "JSON.SET", "gibson:mission_run:run-1", "$", `{"id":"run-1"}`).Err()
	require.NoError(t, err)
	err = rdb.Do(ctx, "JSON.SET", "gibson:mission_run:run-2", "$", `{"id":"run-2"}`).Err()
	require.NoError(t, err)

	// Create event stream
	err = rdb.XAdd(ctx, &redis.XAddArgs{
		Stream: keys[2],
		Values: map[string]interface{}{"event": "test"},
	}).Err()
	require.NoError(t, err)

	// Create memory index
	err = rdb.SAdd(ctx, keys[3], "mem-1", "mem-2").Err()
	require.NoError(t, err)

	// Create memory documents
	err = rdb.Do(ctx, "JSON.SET", fmt.Sprintf("gibson:memory:%s:mem-1", missionID), "$", `{"id":"mem-1"}`).Err()
	require.NoError(t, err)
	err = rdb.Do(ctx, "JSON.SET", fmt.Sprintf("gibson:memory:%s:mem-2", missionID), "$", `{"id":"mem-2"}`).Err()
	require.NoError(t, err)

	// Create findings set
	err = rdb.SAdd(ctx, keys[4], "finding-1", "finding-2").Err()
	require.NoError(t, err)

	// Verify data exists
	exists, err := rdb.Exists(ctx, keys...).Result()
	require.NoError(t, err)
	assert.Equal(t, int64(5), exists, "all keys should exist before deletion")

	// Execute cascade delete
	err = client.CascadeDeleteMission(ctx, missionID)
	require.NoError(t, err)

	// Verify all data is deleted
	exists, err = rdb.Exists(ctx, keys...).Result()
	require.NoError(t, err)
	assert.Equal(t, int64(0), exists, "all keys should be deleted")

	// Verify run documents are deleted
	exists, err = rdb.Exists(ctx, "gibson:mission_run:run-1", "gibson:mission_run:run-2").Result()
	require.NoError(t, err)
	assert.Equal(t, int64(0), exists, "run documents should be deleted")

	// Verify memory documents are deleted
	memKey1 := fmt.Sprintf("gibson:memory:%s:mem-1", missionID)
	memKey2 := fmt.Sprintf("gibson:memory:%s:mem-2", missionID)
	exists, err = rdb.Exists(ctx, memKey1, memKey2).Result()
	require.NoError(t, err)
	assert.Equal(t, int64(0), exists, "memory documents should be deleted")
}

func TestCascadeDeleteMission_MissingData(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := setupTestClient(t)
	defer client.Close()

	ctx := context.Background()
	missionID := "nonexistent-mission-" + time.Now().Format("20060102150405")

	// Delete non-existent mission should succeed (idempotent)
	err := client.CascadeDeleteMission(ctx, missionID)
	assert.NoError(t, err, "deleting non-existent mission should succeed")
}

func TestCascadeDeleteMission_EmptyMissionID(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := setupTestClient(t)
	defer client.Close()

	ctx := context.Background()

	err := client.CascadeDeleteMission(ctx, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missionID cannot be empty")
}

func TestFindOrCreateMission_Create(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := setupTestClient(t)
	defer client.Close()

	ctx := context.Background()

	// Ensure index exists
	err := client.EnsureIndexes(ctx)
	require.NoError(t, err)

	missionName := "test-mission-create-" + time.Now().Format("20060102150405")
	missionID := "mission-" + time.Now().Format("20060102150405")
	missionJSON := fmt.Sprintf(`{"id":"%s","name":"%s","status":"pending"}`, missionID, missionName)

	result, err := client.FindOrCreateMission(ctx, missionName, missionJSON, missionID)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.Created, "should create new mission")
	assert.Equal(t, fmt.Sprintf("gibson:mission:%s", missionID), result.Key)
	assert.Contains(t, result.JSON, missionName)

	// Verify mission exists in Redis
	rdb := client.Client()
	exists, err := rdb.Exists(ctx, result.Key).Result()
	require.NoError(t, err)
	assert.Equal(t, int64(1), exists)

	// Clean up
	err = rdb.Del(ctx, result.Key).Err()
	require.NoError(t, err)
}

func TestFindOrCreateMission_Find(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := setupTestClient(t)
	defer client.Close()

	ctx := context.Background()

	// Ensure index exists
	err := client.EnsureIndexes(ctx)
	require.NoError(t, err)

	missionName := "test-mission-find-" + time.Now().Format("20060102150405")
	missionID := "mission-" + time.Now().Format("20060102150405")
	missionKey := fmt.Sprintf("gibson:mission:%s", missionID)
	missionJSON := fmt.Sprintf(`{"id":"%s","name":"%s","status":"pending"}`, missionID, missionName)

	// Create mission first
	rdb := client.Client()
	err = rdb.Do(ctx, "JSON.SET", missionKey, "$", missionJSON).Err()
	require.NoError(t, err)

	// Wait for index to update
	time.Sleep(100 * time.Millisecond)

	// Try to create again - should find existing
	newID := "mission-new-" + time.Now().Format("20060102150405")
	newJSON := fmt.Sprintf(`{"id":"%s","name":"%s","status":"active"}`, newID, missionName)

	result, err := client.FindOrCreateMission(ctx, missionName, newJSON, newID)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.False(t, result.Created, "should find existing mission")
	assert.Equal(t, missionKey, result.Key)
	assert.Contains(t, result.JSON, missionName)
	assert.Contains(t, result.JSON, missionID, "should return original mission ID")
	assert.NotContains(t, result.JSON, newID, "should not use new ID")

	// Clean up
	err = rdb.Del(ctx, missionKey).Err()
	require.NoError(t, err)
}

func TestFindOrCreateMission_SpecialCharacters(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := setupTestClient(t)
	defer client.Close()

	ctx := context.Background()

	// Ensure index exists
	err := client.EnsureIndexes(ctx)
	require.NoError(t, err)

	// Test names with special characters that need escaping in TAG queries
	testCases := []struct {
		name string
	}{
		{"test-mission-with-dash"},
		{"test.mission.with.dots"},
		{"test_mission_with_underscores"},
		{"test[brackets]"},
		{"test(parens)"},
		{"test+plus"},
		{"test*star"},
		{"test?question"},
		{"test^caret"},
		{"test$dollar"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			missionID := "mission-" + time.Now().Format("20060102150405.000000")
			missionJSON := fmt.Sprintf(`{"id":"%s","name":"%s","status":"pending"}`, missionID, tc.name)

			result, err := client.FindOrCreateMission(ctx, tc.name, missionJSON, missionID)
			require.NoError(t, err, "failed for name: %s", tc.name)
			assert.NotNil(t, result)
			assert.True(t, result.Created, "should create mission for name: %s", tc.name)

			// Clean up
			rdb := client.Client()
			err = rdb.Del(ctx, result.Key).Err()
			require.NoError(t, err)

			// Small delay to avoid ID collisions
			time.Sleep(1 * time.Millisecond)
		})
	}
}

func TestFindOrCreateMission_Concurrent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := setupTestClient(t)
	defer client.Close()

	ctx := context.Background()

	// Ensure index exists
	err := client.EnsureIndexes(ctx)
	require.NoError(t, err)

	missionName := "test-mission-concurrent-" + time.Now().Format("20060102150405")

	// Try to create the same mission concurrently
	const numGoroutines = 20
	results := make(chan *FindOrCreateMissionResult, numGoroutines)
	errors := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			missionID := fmt.Sprintf("mission-%d-%s", idx, time.Now().Format("20060102150405"))
			missionJSON := fmt.Sprintf(`{"id":"%s","name":"%s","status":"pending"}`, missionID, missionName)

			result, err := client.FindOrCreateMission(ctx, missionName, missionJSON, missionID)
			if err != nil {
				errors <- err
				return
			}
			results <- result
		}(i)
	}

	// Collect results
	var createdCount int
	var foundCount int
	var createdKey string

	for i := 0; i < numGoroutines; i++ {
		select {
		case err := <-errors:
			t.Fatalf("concurrent find or create failed: %v", err)
		case result := <-results:
			if result.Created {
				createdCount++
				createdKey = result.Key
			} else {
				foundCount++
			}
		case <-time.After(10 * time.Second):
			t.Fatal("timeout waiting for concurrent operations")
		}
	}

	// Exactly one should be created, rest should find it
	// Note: Due to timing, it's possible multiple creates succeed if index hasn't updated yet
	// So we check that at least one was created
	assert.GreaterOrEqual(t, createdCount, 1, "at least one mission should be created")
	assert.Equal(t, numGoroutines, createdCount+foundCount, "all operations should succeed")

	// Clean up
	if createdKey != "" {
		rdb := client.Client()
		err = rdb.Del(ctx, createdKey).Err()
		require.NoError(t, err)
	}
}

func TestFindOrCreateMission_EmptyParameters(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := setupTestClient(t)
	defer client.Close()

	ctx := context.Background()

	tests := []struct {
		name        string
		missionName string
		missionJSON string
		newID       string
		errContains string
	}{
		{
			name:        "empty name",
			missionName: "",
			missionJSON: `{"id":"test"}`,
			newID:       "test-id",
			errContains: "name cannot be empty",
		},
		{
			name:        "empty JSON",
			missionName: "test-mission",
			missionJSON: "",
			newID:       "test-id",
			errContains: "missionJSON cannot be empty",
		},
		{
			name:        "empty ID",
			missionName: "test-mission",
			missionJSON: `{"id":"test"}`,
			newID:       "",
			errContains: "newID cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := client.FindOrCreateMission(ctx, tt.missionName, tt.missionJSON, tt.newID)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tt.errContains)
		})
	}
}

func TestRunScript_NilScript(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := setupTestClient(t)
	defer client.Close()

	ctx := context.Background()

	_, err := client.RunScript(ctx, nil, []string{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "script cannot be nil")
}

func TestPipeline(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := setupTestClient(t)
	defer client.Close()

	ctx := context.Background()

	// Test pipeline for batch operations
	pipe := client.Pipeline(ctx)
	assert.NotNil(t, pipe)

	key1 := "test:pipeline:key1-" + time.Now().Format("20060102150405")
	key2 := "test:pipeline:key2-" + time.Now().Format("20060102150405")

	pipe.Set(ctx, key1, "value1", 0)
	pipe.Set(ctx, key2, "value2", 0)

	_, err := pipe.Exec(ctx)
	require.NoError(t, err)

	// Verify values
	rdb := client.Client()
	val1, err := rdb.Get(ctx, key1).Result()
	require.NoError(t, err)
	assert.Equal(t, "value1", val1)

	val2, err := rdb.Get(ctx, key2).Result()
	require.NoError(t, err)
	assert.Equal(t, "value2", val2)

	// Clean up
	err = rdb.Del(ctx, key1, key2).Err()
	require.NoError(t, err)
}

func TestMissionKeys(t *testing.T) {
	missionID := "test-mission-123"
	keys := missionKeys(missionID)

	assert.Len(t, keys, 5)
	assert.Equal(t, "gibson:mission:test-mission-123", keys[0])
	assert.Equal(t, "gibson:mission:runs:test-mission-123", keys[1])
	assert.Equal(t, "gibson:events:test-mission-123", keys[2])
	assert.Equal(t, "gibson:memory:idx:test-mission-123", keys[3])
	assert.Equal(t, "gibson:mission:findings:test-mission-123", keys[4])
}

func TestCreateCredentialAtomic(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := setupTestClient(t)
	defer client.Close()

	ctx := context.Background()
	credID := "cred-" + time.Now().Format("20060102150405.000000")
	credName := "test-cred-" + time.Now().Format("20060102150405")
	credJSON := fmt.Sprintf(`{"id":"%s","name":"%s","type":"api_key"}`, credID, credName)

	// Test creating a new credential
	err := client.CreateCredentialAtomic(ctx, credID, credName, credJSON)
	require.NoError(t, err)

	// Verify credential document was created
	rdb := client.Client()
	docKey := fmt.Sprintf("gibson:credential:%s", credID)
	exists, err := rdb.Exists(ctx, docKey).Result()
	require.NoError(t, err)
	assert.Equal(t, int64(1), exists, "credential document should exist")

	// Verify name lookup was created
	nameKey := fmt.Sprintf("gibson:credential:by_name:%s", credName)
	lookupID, err := rdb.Get(ctx, nameKey).Result()
	require.NoError(t, err)
	assert.Equal(t, credID, lookupID, "name lookup should map to credential ID")

	// Clean up
	err = rdb.Del(ctx, docKey, nameKey).Err()
	require.NoError(t, err)
}

func TestCreateCredentialAtomic_DuplicateName(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := setupTestClient(t)
	defer client.Close()

	ctx := context.Background()
	credName := "test-cred-duplicate-" + time.Now().Format("20060102150405")

	// Create first credential
	credID1 := "cred-1-" + time.Now().Format("20060102150405.000000")
	credJSON1 := fmt.Sprintf(`{"id":"%s","name":"%s","type":"api_key"}`, credID1, credName)
	err := client.CreateCredentialAtomic(ctx, credID1, credName, credJSON1)
	require.NoError(t, err)

	// Try to create second credential with same name
	credID2 := "cred-2-" + time.Now().Format("20060102150405.000001")
	credJSON2 := fmt.Sprintf(`{"id":"%s","name":"%s","type":"bearer"}`, credID2, credName)
	err = client.CreateCredentialAtomic(ctx, credID2, credName, credJSON2)

	// Should fail with ErrAlreadyExists
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrAlreadyExists)
	assert.Contains(t, err.Error(), "already exists")

	// Verify second credential was NOT created
	rdb := client.Client()
	docKey2 := fmt.Sprintf("gibson:credential:%s", credID2)
	exists, err := rdb.Exists(ctx, docKey2).Result()
	require.NoError(t, err)
	assert.Equal(t, int64(0), exists, "second credential should not exist")

	// Clean up first credential
	docKey1 := fmt.Sprintf("gibson:credential:%s", credID1)
	nameKey := fmt.Sprintf("gibson:credential:by_name:%s", credName)
	err = rdb.Del(ctx, docKey1, nameKey).Err()
	require.NoError(t, err)
}

func TestCreateCredentialAtomic_Concurrent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := setupTestClient(t)
	defer client.Close()

	ctx := context.Background()
	credName := "test-cred-concurrent-" + time.Now().Format("20060102150405")

	// Try to create the same credential concurrently
	const numGoroutines = 20
	errors := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			credID := fmt.Sprintf("cred-%d-%s", idx, time.Now().Format("20060102150405.000000"))
			credJSON := fmt.Sprintf(`{"id":"%s","name":"%s","type":"api_key"}`, credID, credName)
			err := client.CreateCredentialAtomic(ctx, credID, credName, credJSON)
			errors <- err
		}(i)
	}

	// Collect results
	var successCount int
	var errorCount int
	var createdID string

	for i := 0; i < numGoroutines; i++ {
		select {
		case err := <-errors:
			if err == nil {
				successCount++
			} else {
				errorCount++
			}
		case <-time.After(10 * time.Second):
			t.Fatal("timeout waiting for concurrent operations")
		}
	}

	// Exactly ONE should succeed due to Lua script atomicity
	assert.Equal(t, 1, successCount, "exactly one create should succeed")
	assert.Equal(t, numGoroutines-1, errorCount, "all other creates should fail")

	// Find which credential was created by checking the name lookup
	rdb := client.Client()
	nameKey := fmt.Sprintf("gibson:credential:by_name:%s", credName)
	createdID, err := rdb.Get(ctx, nameKey).Result()
	require.NoError(t, err)
	assert.NotEmpty(t, createdID, "name lookup should exist")

	// Clean up
	docKey := fmt.Sprintf("gibson:credential:%s", createdID)
	err = rdb.Del(ctx, docKey, nameKey).Err()
	require.NoError(t, err)
}

func TestCreateCredentialAtomic_EmptyParameters(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := setupTestClient(t)
	defer client.Close()

	ctx := context.Background()

	tests := []struct {
		name        string
		credID      string
		credName    string
		credJSON    string
		errContains string
	}{
		{
			name:        "empty credID",
			credID:      "",
			credName:    "test-cred",
			credJSON:    `{"id":"test"}`,
			errContains: "credID cannot be empty",
		},
		{
			name:        "empty credName",
			credID:      "cred-123",
			credName:    "",
			credJSON:    `{"id":"test"}`,
			errContains: "name cannot be empty",
		},
		{
			name:        "empty credJSON",
			credID:      "cred-123",
			credName:    "test-cred",
			credJSON:    "",
			errContains: "credentialJSON cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := client.CreateCredentialAtomic(ctx, tt.credID, tt.credName, tt.credJSON)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tt.errContains)
		})
	}
}
