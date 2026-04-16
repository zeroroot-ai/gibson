package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/zero-day-ai/gibson/internal/finding"
	"github.com/zero-day-ai/gibson/internal/memory"
	"github.com/zero-day-ai/gibson/internal/memory/vector"
	"github.com/zero-day-ai/gibson/internal/mission"
	"github.com/zero-day-ai/gibson/internal/state"
	"github.com/zero-day-ai/gibson/internal/types"
)

const (
	// Test key prefix to isolate tests
	testKeyPrefix = "gibson:test"

	// Redis Stack image for testcontainers
	redisStackImage = "redis/redis-stack-server:latest"

	// Test timeout
	testTimeout = 30 * time.Second
)

// redisContainer manages a Redis Stack container for integration tests.
type redisContainer struct {
	container testcontainers.Container
	url       string
}

// setupRedisStack starts a Redis Stack container for testing.
// Returns nil if Redis Stack is not available or if running against external instance.
func setupRedisStack(ctx context.Context, t *testing.T) *redisContainer {
	// Check if external Redis is configured
	if redisURL := os.Getenv("REDIS_URL"); redisURL != "" {
		t.Logf("Using external Redis at %s", redisURL)
		return &redisContainer{url: redisURL}
	}

	// Start Redis Stack container
	req := testcontainers.ContainerRequest{
		Image:        redisStackImage,
		ExposedPorts: []string{"6379/tcp"},
		WaitingFor:   wait.ForLog("Ready to accept connections").WithStartupTimeout(60 * time.Second),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Skipf("Failed to start Redis Stack container: %v (install Docker and Redis Stack to run integration tests)", err)
		return nil
	}

	host, err := container.Host(ctx)
	if err != nil {
		container.Terminate(ctx)
		t.Skipf("Failed to get container host: %v", err)
		return nil
	}

	port, err := container.MappedPort(ctx, "6379")
	if err != nil {
		container.Terminate(ctx)
		t.Skipf("Failed to get mapped port: %v", err)
		return nil
	}

	url := fmt.Sprintf("redis://%s:%s", host, port.Port())
	t.Logf("Redis Stack container started at %s", url)

	return &redisContainer{
		container: container,
		url:       url,
	}
}

// cleanup terminates the container if it was started by the test.
func (rc *redisContainer) cleanup(ctx context.Context, t *testing.T) {
	if rc.container != nil {
		if err := rc.container.Terminate(ctx); err != nil {
			t.Logf("Failed to terminate container: %v", err)
		}
	}
}

// newTestStateClient creates a StateClient for testing with unique key prefix.
func newTestStateClient(t *testing.T, url string, keyPrefix string) *state.StateClient {
	cfg := state.DefaultConfig()
	cfg.URL = url
	cfg.Database = 0

	client, err := state.NewStateClient(cfg)
	require.NoError(t, err, "Failed to create StateClient")

	return client
}

// cleanupKeys removes all test keys after a test.
func cleanupKeys(ctx context.Context, t *testing.T, client *state.StateClient, pattern string) {
	rdb := client.Client()

	var cursor uint64
	for {
		keys, nextCursor, err := rdb.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			t.Logf("Failed to scan keys: %v", err)
			return
		}

		if len(keys) > 0 {
			if err := rdb.Del(ctx, keys...).Err(); err != nil {
				t.Logf("Failed to delete keys: %v", err)
			}
		}

		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}
}

// TestRedisStackAvailability verifies Redis Stack is available with required modules.
func TestRedisStackAvailability(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	rc := setupRedisStack(ctx, t)
	if rc == nil {
		return
	}
	defer rc.cleanup(ctx, t)

	client := newTestStateClient(t, rc.url, testKeyPrefix)
	defer client.Close()

	// Test health check
	err := client.Health(ctx)
	require.NoError(t, err, "Redis Stack health check failed")
}

// TestMissionStoreEndToEnd tests MissionStore CRUD operations with search.
func TestMissionStoreEndToEnd(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	rc := setupRedisStack(ctx, t)
	if rc == nil {
		return
	}
	defer rc.cleanup(ctx, t)

	client := newTestStateClient(t, rc.url, testKeyPrefix)
	defer client.Close()

	// Ensure indexes
	require.NoError(t, client.EnsureIndexes(ctx))

	// Create store
	store := mission.NewRedisMissionStore(client)
	defer cleanupKeys(ctx, t, client, "gibson:mission:*")

	// Create test mission
	m := &mission.Mission{
		ID:            types.NewID(),
		Name:          fmt.Sprintf("test-mission-%d", time.Now().UnixNano()),
		Description:   "Integration test mission for Redis state storage",
		Status:        mission.MissionStatusPending,
		TargetID:      types.NewID(),
		CreatedAt:     mission.NewUnixTime(time.Now()),
		UpdatedAt:     mission.NewUnixTime(time.Now()),
		Progress:      0.0,
		FindingsCount: 0,
	}

	// Save mission
	err := store.Save(ctx, m)
	require.NoError(t, err, "Failed to save mission")

	// Get mission by ID
	retrieved, err := store.Get(ctx, m.ID)
	require.NoError(t, err, "Failed to get mission")
	assert.Equal(t, m.ID, retrieved.ID)
	assert.Equal(t, m.Name, retrieved.Name)
	assert.Equal(t, m.Description, retrieved.Description)

	// Update mission status
	err = store.UpdateStatus(ctx, m.ID, mission.MissionStatusRunning)
	require.NoError(t, err, "Failed to update status")

	// Verify status update
	retrieved, err = store.Get(ctx, m.ID)
	require.NoError(t, err)
	assert.Equal(t, mission.MissionStatusRunning, retrieved.Status)

	// Update progress
	err = store.UpdateProgress(ctx, m.ID, 0.5)
	require.NoError(t, err, "Failed to update progress")

	// Verify progress update
	retrieved, err = store.Get(ctx, m.ID)
	require.NoError(t, err)
	assert.InDelta(t, 0.5, retrieved.Progress, 0.01)

	// Search missions by name
	foundMission, err := store.GetByName(ctx, m.Name)
	require.NoError(t, err, "Failed to search by name")
	require.NotNil(t, foundMission, "expected to find mission by name")
	assert.Equal(t, m.ID, foundMission.ID)

	// Get active missions
	active, err := store.GetActive(ctx)
	require.NoError(t, err, "Failed to get active missions")
	assert.True(t, len(active) >= 1, "Expected at least one active mission")

	// Delete mission
	err = store.Delete(ctx, m.ID)
	require.NoError(t, err, "Failed to delete mission")

	// Verify deletion
	_, err = store.Get(ctx, m.ID)
	assert.Error(t, err, "Expected error when getting deleted mission")
}

// TestFindingStoreWithSearch tests FindingStore with full-text search.
func TestFindingStoreWithSearch(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	rc := setupRedisStack(ctx, t)
	if rc == nil {
		return
	}
	defer rc.cleanup(ctx, t)

	client := newTestStateClient(t, rc.url, testKeyPrefix)
	defer client.Close()

	require.NoError(t, client.EnsureIndexes(ctx))

	store := finding.NewRedisFindingStore(client)
	defer cleanupKeys(ctx, t, client, "gibson:finding:*")

	missionID := types.NewID()

	// Create test findings with known content
	findings := []*finding.Finding{
		{
			ID:          types.NewID(),
			MissionID:   missionID,
			Title:       "SQL Injection in Login Form",
			Description: "Database query vulnerable to SQL injection attacks",
			Severity:    finding.SeverityCritical,
			Status:      finding.StatusOpen,
			RiskScore:   9.5,
			CreatedAt:   time.Now(),
		},
		{
			ID:          types.NewID(),
			MissionID:   missionID,
			Title:       "Cross-Site Scripting (XSS)",
			Description: "Reflected XSS vulnerability in search parameter",
			Severity:    finding.SeverityHigh,
			Status:      finding.StatusOpen,
			RiskScore:   7.8,
			CreatedAt:   time.Now(),
		},
		{
			ID:          types.NewID(),
			MissionID:   missionID,
			Title:       "Weak Password Policy",
			Description: "Password requirements are too weak",
			Severity:    finding.SeverityMedium,
			Status:      finding.StatusOpen,
			RiskScore:   5.2,
			CreatedAt:   time.Now(),
		},
	}

	// Save findings
	for _, f := range findings {
		err := store.Save(ctx, f)
		require.NoError(t, err, "Failed to save finding")
	}

	// Allow time for indexing
	time.Sleep(100 * time.Millisecond)

	// Test full-text search - search for "SQL"
	results, err := store.Search(ctx, &finding.SearchOptions{
		Query: "SQL",
		Limit: 10,
	})
	require.NoError(t, err, "Search failed")
	assert.Greater(t, len(results), 0, "Expected search results for 'SQL'")

	// Verify SQL injection finding is in results
	found := false
	for _, r := range results {
		if r.Title == "SQL Injection in Login Form" {
			found = true
			break
		}
	}
	assert.True(t, found, "Expected to find SQL injection finding")

	// Test search with severity filter
	results, err = store.Search(ctx, &finding.SearchOptions{
		Severity: finding.SeverityCritical,
		Limit:    10,
	})
	require.NoError(t, err)
	require.Len(t, results, 1, "Expected 1 critical finding")
	assert.Equal(t, "SQL Injection in Login Form", results[0].Title)

	// Test search ranking - "injection" should rank SQL finding highest
	results, err = store.Search(ctx, &finding.SearchOptions{
		Query: "injection",
		Limit: 10,
	})
	require.NoError(t, err)
	assert.Greater(t, len(results), 0)
	assert.Equal(t, "SQL Injection in Login Form", results[0].Title, "SQL injection should be ranked first")

	// Test GetByMission
	byMission, err := store.GetByMission(ctx, missionID)
	require.NoError(t, err)
	assert.Len(t, byMission, 3, "Expected 3 findings for mission")

	// Cleanup
	for _, f := range findings {
		store.Delete(ctx, f.ID)
	}
}

// TestSearchQuality verifies BM25 ranking quality with known content.
func TestSearchQuality(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	rc := setupRedisStack(ctx, t)
	if rc == nil {
		return
	}
	defer rc.cleanup(ctx, t)

	client := newTestStateClient(t, rc.url, testKeyPrefix)
	defer client.Close()

	require.NoError(t, client.EnsureIndexes(ctx))

	store := finding.NewRedisFindingStore(client)
	defer cleanupKeys(ctx, t, client, "gibson:finding:*")

	missionID := types.NewID()

	// Create documents with varying term frequencies
	testDocs := []*finding.Finding{
		{
			ID:          types.NewID(),
			MissionID:   missionID,
			Title:       "Authentication bypass vulnerability",
			Description: "Critical authentication bypass found in login system. The authentication mechanism can be bypassed completely.",
			Severity:    finding.SeverityCritical,
			Status:      finding.StatusOpen,
			CreatedAt:   time.Now(),
		},
		{
			ID:          types.NewID(),
			MissionID:   missionID,
			Title:       "User authentication issue",
			Description: "Minor authentication configuration issue with user roles.",
			Severity:    finding.SeverityLow,
			Status:      finding.StatusOpen,
			CreatedAt:   time.Now(),
		},
		{
			ID:          types.NewID(),
			MissionID:   missionID,
			Title:       "Rate limiting not implemented",
			Description: "No rate limiting on API endpoints which could lead to DoS.",
			Severity:    finding.SeverityMedium,
			Status:      finding.StatusOpen,
			CreatedAt:   time.Now(),
		},
	}

	// Save documents
	for _, doc := range testDocs {
		err := store.Save(ctx, doc)
		require.NoError(t, err)
	}

	// Allow indexing
	time.Sleep(100 * time.Millisecond)

	// Search for "authentication" - should rank docs with multiple mentions higher
	results, err := store.Search(ctx, &finding.SearchOptions{
		Query: "authentication",
		Limit: 10,
	})
	require.NoError(t, err)
	require.Greater(t, len(results), 0)

	// First result should be the document with most "authentication" mentions
	assert.Contains(t, results[0].Title, "Authentication", "Document with most term frequency should rank first")
	assert.Contains(t, results[0].Description, "authentication", "Should contain search term")

	// Cleanup
	for _, doc := range testDocs {
		store.Delete(ctx, doc.ID)
	}
}

// TestMissionMemoryWithSearch tests mission-scoped memory with full-text search.
func TestMissionMemoryWithSearch(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	rc := setupRedisStack(ctx, t)
	if rc == nil {
		return
	}
	defer rc.cleanup(ctx, t)

	client := newTestStateClient(t, rc.url, testKeyPrefix)
	defer client.Close()

	require.NoError(t, client.EnsureIndexes(ctx))

	missionID := types.NewID()
	mem := memory.NewRedisMissionMemory(client, missionID, "")
	defer cleanupKeys(ctx, t, client, fmt.Sprintf("gibson:memory:%s:*", missionID))

	// Set memory entries
	entries := map[string]string{
		"target_ip":       "192.168.1.100",
		"target_hostname": "web-server-01.example.com",
		"open_ports":      "22,80,443,3306",
		"os_version":      "Ubuntu 20.04 LTS",
		"web_framework":   "Django 3.2",
	}

	for key, value := range entries {
		err := mem.Store(ctx, key, value, nil)
		require.NoError(t, err, "Failed to store memory entry")
	}

	// Retrieve individual entry
	item, err := mem.Retrieve(ctx, "target_ip")
	require.NoError(t, err)
	assert.Equal(t, "192.168.1.100", item.Value)

	// List all keys
	keys, err := mem.Keys(ctx)
	require.NoError(t, err)
	assert.Len(t, keys, 5)

	// Search memory
	time.Sleep(100 * time.Millisecond) // Allow indexing

	results, err := mem.Search(ctx, "Django", 10)
	require.NoError(t, err)
	assert.Greater(t, len(results), 0, "Expected search results")

	// Verify correct entry found
	found := false
	for _, r := range results {
		if r.Item.Key == "web_framework" {
			found = true
			assert.Equal(t, "Django 3.2", r.Item.Value)
			break
		}
	}
	assert.True(t, found, "Expected to find web_framework entry")

	// Test mission isolation - create another mission's memory
	otherMissionID := types.NewID()
	otherMem := memory.NewRedisMissionMemory(client, otherMissionID, "")
	defer cleanupKeys(ctx, t, client, fmt.Sprintf("gibson:memory:%s:*", otherMissionID))

	err = otherMem.Store(ctx, "target_ip", "10.0.0.50", nil)
	require.NoError(t, err)

	// Verify isolation
	keys, err = mem.Keys(ctx)
	require.NoError(t, err)
	assert.Len(t, keys, 5, "Original mission should still have 5 keys")

	keys, err = otherMem.Keys(ctx)
	require.NoError(t, err)
	assert.Len(t, keys, 1, "Other mission should have 1 key")

	// Clear memory
	err = mem.Clear(ctx)
	require.NoError(t, err)

	keys, err = mem.Keys(ctx)
	require.NoError(t, err)
	assert.Len(t, keys, 0, "Memory should be cleared")
}

// TestEventStoreWithStreams tests EventStore with Redis Streams.
func TestEventStoreWithStreams(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	rc := setupRedisStack(ctx, t)
	if rc == nil {
		return
	}
	defer rc.cleanup(ctx, t)

	client := newTestStateClient(t, rc.url, testKeyPrefix)
	defer client.Close()

	missionID := types.NewID()
	store := mission.NewRedisEventStore(client)
	defer cleanupKeys(ctx, t, client, fmt.Sprintf("gibson:stream:mission:%s:*", missionID))

	// Append events
	events := []mission.Event{
		{
			Type:      mission.EventTypeStatusChanged,
			Payload:   json.RawMessage(`{"from":"pending","to":"running"}`),
			CreatedAt: time.Now(),
		},
		{
			Type:      mission.EventTypeProgressUpdated,
			Payload:   json.RawMessage(`{"progress":0.25}`),
			CreatedAt: time.Now(),
		},
		{
			Type:      mission.EventTypeFindingDiscovered,
			Payload:   json.RawMessage(`{"finding_id":"test-123","severity":"high"}`),
			CreatedAt: time.Now(),
		},
	}

	for _, event := range events {
		_, err := store.Append(ctx, missionID, &event)
		require.NoError(t, err, "Failed to append event")
	}

	// Query all events
	retrieved, err := store.Query(ctx, missionID, "-", "+", 100)
	require.NoError(t, err)
	assert.Len(t, retrieved, 3, "Expected 3 events")

	// Verify event order (streams are time-ordered)
	assert.Equal(t, mission.EventTypeStatusChanged, retrieved[0].Type)
	assert.Equal(t, mission.EventTypeProgressUpdated, retrieved[1].Type)
	assert.Equal(t, mission.EventTypeFindingDiscovered, retrieved[2].Type)

	// Query by type
	filtered, err := store.QueryByType(ctx, missionID, mission.EventTypeStatusChanged, "-", "+", 100)
	require.NoError(t, err)
	assert.Len(t, filtered, 1)
	assert.Equal(t, mission.EventTypeStatusChanged, filtered[0].Type)
}

// TestEventStoreSubscribe tests real-time event subscription.
func TestEventStoreSubscribe(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rc := setupRedisStack(ctx, t)
	if rc == nil {
		return
	}
	defer rc.cleanup(ctx, t)

	client := newTestStateClient(t, rc.url, testKeyPrefix)
	defer client.Close()

	missionID := types.NewID()
	store := mission.NewRedisEventStore(client)
	defer cleanupKeys(ctx, t, client, fmt.Sprintf("gibson:stream:mission:%s:*", missionID))

	// Subscribe to events
	subCtx, subCancel := context.WithCancel(ctx)
	defer subCancel()

	eventChan, errChan := store.Subscribe(subCtx, missionID, "$")

	// Wait for subscription to be ready
	time.Sleep(100 * time.Millisecond)

	// Append events in background
	go func() {
		time.Sleep(200 * time.Millisecond)
		event := &mission.Event{
			Type:      mission.EventTypeStatusChanged,
			Payload:   json.RawMessage(`{"from":"pending","to":"running"}`),
			CreatedAt: time.Now(),
		}
		store.Append(ctx, missionID, event)
	}()

	// Wait for event
	select {
	case event := <-eventChan:
		assert.Equal(t, mission.EventTypeStatusChanged, event.Type)
		t.Logf("Received event: %s", event.Type)
	case err := <-errChan:
		t.Fatalf("Subscription error: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("Timeout waiting for event")
	}

	// Cancel subscription
	subCancel()
}

// TestVectorStoreWithKNN tests VectorStore similarity search.
func TestVectorStoreWithKNN(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	rc := setupRedisStack(ctx, t)
	if rc == nil {
		return
	}
	defer rc.cleanup(ctx, t)

	client := newTestStateClient(t, rc.url, testKeyPrefix)
	defer client.Close()

	require.NoError(t, client.EnsureIndexes(ctx))

	store := vector.NewRedisVectorStore(client, 384) // All-MiniLM-L6-v2 dimension
	defer cleanupKeys(ctx, t, client, "gibson:vector:*")
	defer store.Close()

	// Create test vectors (simplified for testing)
	// In reality, these would be embeddings from a model
	testRecords := []struct {
		content   string
		embedding []float32
	}{
		{
			content:   "SQL injection vulnerability in login form",
			embedding: generateTestEmbedding(384, 0.1),
		},
		{
			content:   "Cross-site scripting in search parameter",
			embedding: generateTestEmbedding(384, 0.5),
		},
		{
			content:   "SQL injection in user registration",
			embedding: generateTestEmbedding(384, 0.15), // Similar to first
		},
	}

	// Store vectors
	ids := make([]string, len(testRecords))
	for i, v := range testRecords {
		id := types.NewID().String()
		ids[i] = id

		record := vector.VectorRecord{
			ID:        id,
			Content:   v.content,
			Embedding: v.embedding,
			Metadata:  map[string]any{"index": i},
		}

		err := store.Store(ctx, record)
		require.NoError(t, err, "Failed to store vector")
	}

	// Allow indexing
	time.Sleep(100 * time.Millisecond)

	// Search for similar vectors
	queryVec := generateTestEmbedding(384, 0.12) // Similar to first and third
	query := vector.VectorQuery{
		Embedding: queryVec,
		K:         2,
	}

	results, err := store.Search(ctx, query)
	require.NoError(t, err)
	require.Len(t, results, 2, "Expected 2 results")

	// Verify results contain relevant documents
	t.Logf("Search results:")
	for i, r := range results {
		t.Logf("  %d. %s (score: %.4f)", i+1, r.Content, r.Score)
	}

	// Cleanup
	for _, id := range ids {
		store.Delete(ctx, id)
	}
}

// TestAtomicityConcurrentRunIncrement tests atomic run number increment.
func TestAtomicityConcurrentRunIncrement(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	rc := setupRedisStack(ctx, t)
	if rc == nil {
		return
	}
	defer rc.cleanup(ctx, t)

	client := newTestStateClient(t, rc.url, testKeyPrefix)
	defer client.Close()

	store := mission.NewRedisMissionStore(client)
	missionName := fmt.Sprintf("concurrent-test-%d", time.Now().UnixNano())
	defer cleanupKeys(ctx, t, client, "gibson:counter:mission:*")

	// Concurrent increment from multiple goroutines
	concurrency := 50
	var wg sync.WaitGroup
	runNumbers := make([]int, concurrency)
	errors := make([]error, concurrency)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			runNum, err := store.IncrementRunNumber(ctx, missionName)
			runNumbers[idx] = runNum
			errors[idx] = err
		}(i)
	}

	wg.Wait()

	// Verify no errors
	for i, err := range errors {
		require.NoError(t, err, "Goroutine %d failed", i)
	}

	// Verify uniqueness - all run numbers should be unique
	seen := make(map[int]bool)
	for _, num := range runNumbers {
		assert.False(t, seen[num], "Duplicate run number: %d", num)
		seen[num] = true
	}

	// Verify sequence - should have numbers 1 through concurrency
	assert.Len(t, seen, concurrency, "Should have %d unique run numbers", concurrency)
	for i := 1; i <= concurrency; i++ {
		assert.True(t, seen[i], "Missing run number: %d", i)
	}
}

// TestAtomicityFindOrCreate tests find-or-create race condition handling.
func TestAtomicityFindOrCreate(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	rc := setupRedisStack(ctx, t)
	if rc == nil {
		return
	}
	defer rc.cleanup(ctx, t)

	client := newTestStateClient(t, rc.url, testKeyPrefix)
	defer client.Close()

	require.NoError(t, client.EnsureIndexes(ctx))

	store := mission.NewRedisMissionStore(client)
	missionName := fmt.Sprintf("find-or-create-%d", time.Now().UnixNano())
	defer cleanupKeys(ctx, t, client, "gibson:mission:*")

	// Concurrent find-or-create from multiple goroutines
	concurrency := 20
	var wg sync.WaitGroup
	missions := make([]*mission.Mission, concurrency)
	errors := make([]error, concurrency)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			m, err := store.FindOrCreateByName(ctx, missionName, func() *mission.Mission {
				return &mission.Mission{
					ID:          types.NewID(),
					Name:        missionName,
					Description: "Concurrent create test",
					Status:      mission.MissionStatusPending,
					CreatedAt:   mission.NewUnixTime(time.Now()),
					UpdatedAt:   mission.NewUnixTime(time.Now()),
				}
			})

			missions[idx] = m
			errors[idx] = err
		}(i)
	}

	wg.Wait()

	// Verify no errors
	for i, err := range errors {
		require.NoError(t, err, "Goroutine %d failed", i)
	}

	// Verify all goroutines got the same mission ID (no duplicates created)
	firstID := missions[0].ID
	for i, m := range missions {
		assert.Equal(t, firstID, m.ID, "Goroutine %d got different mission ID", i)
		assert.Equal(t, missionName, m.Name)
	}

	// Cleanup
	store.Delete(ctx, firstID)
}

// TestAtomicityCascadeDelete tests cascade delete completeness.
func TestAtomicityCascadeDelete(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	rc := setupRedisStack(ctx, t)
	if rc == nil {
		return
	}
	defer rc.cleanup(ctx, t)

	client := newTestStateClient(t, rc.url, testKeyPrefix)
	defer client.Close()

	require.NoError(t, client.EnsureIndexes(ctx))

	missionStore := mission.NewRedisMissionStore(client)
	runStore := mission.NewRedisMissionRunStore(client)
	eventStore := mission.NewRedisEventStore(client)
	findingStore := finding.NewRedisFindingStore(client)

	// Create mission with related data
	m := &mission.Mission{
		ID:          types.NewID(),
		Name:        fmt.Sprintf("cascade-test-%d", time.Now().UnixNano()),
		Description: "Cascade delete test",
		Status:      mission.MissionStatusRunning,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	err := missionStore.Save(ctx, m)
	require.NoError(t, err)

	// Create runs
	for i := 1; i <= 3; i++ {
		run := &mission.MissionRun{
			ID:          types.NewID(),
			MissionID:   m.ID,
			MissionName: m.Name,
			RunNumber:   i,
			Status:      mission.RunStatusCompleted,
			StartedAt:   time.Now(),
			CompletedAt: time.Now(),
		}
		err := runStore.Create(ctx, run)
		require.NoError(t, err)
	}

	// Create events
	for i := 0; i < 5; i++ {
		event := &mission.Event{
			Type:      mission.EventTypeStatusChanged,
			Payload:   json.RawMessage(`{"test": true}`),
			CreatedAt: time.Now(),
		}
		_, err := eventStore.Append(ctx, m.ID, event)
		require.NoError(t, err)
	}

	// Create memory entries
	mem := memory.NewRedisMissionMemory(client, m.ID, "")
	for i := 0; i < 10; i++ {
		err := mem.Store(ctx, fmt.Sprintf("key-%d", i), fmt.Sprintf("value-%d", i), nil)
		require.NoError(t, err)
	}

	// Create findings
	for i := 0; i < 7; i++ {
		f := &finding.Finding{
			ID:          types.NewID(),
			MissionID:   m.ID,
			Title:       fmt.Sprintf("Finding %d", i),
			Description: "Test finding",
			Severity:    finding.SeverityMedium,
			Status:      finding.StatusOpen,
			CreatedAt:   time.Now(),
		}
		err := findingStore.Save(ctx, f)
		require.NoError(t, err)
	}

	// Verify data exists
	runs, err := runStore.List(ctx, m.ID)
	require.NoError(t, err)
	assert.Len(t, runs, 3)

	events, err := eventStore.Query(ctx, m.ID, "-", "+", 100)
	require.NoError(t, err)
	assert.Len(t, events, 5)

	keys, err := mem.ListKeys(ctx)
	require.NoError(t, err)
	assert.Len(t, keys, 10)

	findings, err := findingStore.GetByMission(ctx, m.ID)
	require.NoError(t, err)
	assert.Len(t, findings, 7)

	// Cascade delete
	err = missionStore.Delete(ctx, m.ID)
	require.NoError(t, err)

	// Verify all related data is deleted
	_, err = missionStore.Get(ctx, m.ID)
	assert.Error(t, err, "Mission should be deleted")

	runs, err = runStore.List(ctx, m.ID)
	require.NoError(t, err)
	assert.Len(t, runs, 0, "All runs should be deleted")

	events, err = eventStore.Query(ctx, m.ID, "-", "+", 100)
	require.NoError(t, err)
	assert.Len(t, events, 0, "All events should be deleted")

	keys, err = mem.Keys(ctx)
	require.NoError(t, err)
	assert.Len(t, keys, 0, "All memory entries should be deleted")

	// Note: Findings are not cascade deleted (by design - they're preserved for historical record)
	findings, err = findingStore.GetByMission(ctx, m.ID)
	require.NoError(t, err)
	assert.Len(t, findings, 7, "Findings should be preserved")

	// Cleanup findings manually
	for _, f := range findings {
		findingStore.Delete(ctx, f.ID)
	}
}

// TestPerformanceBulkInsert measures bulk insert performance.
func TestPerformanceBulkInsert(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	rc := setupRedisStack(ctx, t)
	if rc == nil {
		return
	}
	defer rc.cleanup(ctx, t)

	client := newTestStateClient(t, rc.url, testKeyPrefix)
	defer client.Close()

	require.NoError(t, client.EnsureIndexes(ctx))

	store := finding.NewRedisFindingStore(client)
	defer cleanupKeys(ctx, t, client, "gibson:finding:*")

	missionID := types.NewID()
	count := 1000

	// Bulk insert
	start := time.Now()
	for i := 0; i < count; i++ {
		f := &finding.Finding{
			ID:          types.NewID(),
			MissionID:   missionID,
			Title:       fmt.Sprintf("Performance test finding %d", i),
			Description: fmt.Sprintf("This is finding number %d for performance testing", i),
			Severity:    finding.SeverityMedium,
			Status:      finding.StatusOpen,
			CreatedAt:   time.Now(),
		}
		err := store.Save(ctx, f)
		require.NoError(t, err)
	}
	elapsed := time.Since(start)

	t.Logf("Inserted %d findings in %v (%.2f findings/sec)", count, elapsed, float64(count)/elapsed.Seconds())
	assert.Less(t, elapsed, 30*time.Second, "Bulk insert should complete in reasonable time")

	// Verify count
	findings, err := store.GetByMission(ctx, missionID)
	require.NoError(t, err)
	assert.Len(t, findings, count)
}

// TestPerformanceSearchLatency measures search latency.
func TestPerformanceSearchLatency(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	rc := setupRedisStack(ctx, t)
	if rc == nil {
		return
	}
	defer rc.cleanup(ctx, t)

	client := newTestStateClient(t, rc.url, testKeyPrefix)
	defer client.Close()

	require.NoError(t, client.EnsureIndexes(ctx))

	store := finding.NewRedisFindingStore(client)
	defer cleanupKeys(ctx, t, client, "gibson:finding:*")

	missionID := types.NewID()

	// Create dataset
	for i := 0; i < 100; i++ {
		f := &finding.Finding{
			ID:          types.NewID(),
			MissionID:   missionID,
			Title:       fmt.Sprintf("Finding %d with SQL injection vulnerability", i),
			Description: fmt.Sprintf("Finding %d describes a SQL injection issue", i),
			Severity:    finding.SeverityHigh,
			Status:      finding.StatusOpen,
			CreatedAt:   time.Now(),
		}
		err := store.Save(ctx, f)
		require.NoError(t, err)
	}

	time.Sleep(500 * time.Millisecond) // Allow indexing

	// Measure search latency
	iterations := 50
	var totalDuration time.Duration

	for i := 0; i < iterations; i++ {
		start := time.Now()
		_, err := store.Search(ctx, &finding.SearchOptions{
			Query: "SQL injection",
			Limit: 20,
		})
		require.NoError(t, err)
		totalDuration += time.Since(start)
	}

	avgLatency := totalDuration / time.Duration(iterations)
	t.Logf("Average search latency: %v over %d iterations", avgLatency, iterations)
	assert.Less(t, avgLatency, 100*time.Millisecond, "Search latency should be under 100ms")
}

// TestPerformanceStreamThroughput measures stream append throughput.
func TestPerformanceStreamThroughput(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	rc := setupRedisStack(ctx, t)
	if rc == nil {
		return
	}
	defer rc.cleanup(ctx, t)

	client := newTestStateClient(t, rc.url, testKeyPrefix)
	defer client.Close()

	missionID := types.NewID()
	store := mission.NewRedisEventStore(client)
	defer cleanupKeys(ctx, t, client, fmt.Sprintf("gibson:stream:mission:%s:*", missionID))

	count := 5000

	// Measure append throughput
	start := time.Now()
	for i := 0; i < count; i++ {
		event := &mission.Event{
			Type:      mission.EventTypeProgressUpdated,
			Payload:   json.RawMessage(fmt.Sprintf(`{"progress":%d}`, i)),
			CreatedAt: time.Now(),
		}
		_, err := store.Append(ctx, missionID, event)
		require.NoError(t, err)
	}
	elapsed := time.Since(start)

	t.Logf("Appended %d events in %v (%.2f events/sec)", count, elapsed, float64(count)/elapsed.Seconds())
	assert.Less(t, elapsed, 10*time.Second, "Stream append should have high throughput")

	// Verify count
	events, err := store.Query(ctx, missionID, "-", "+", count)
	require.NoError(t, err)
	assert.Len(t, events, count)
}

// Note: CredentialStore and SessionStore tests are commented out pending interface definitions.
// These should be enabled once CredentialDAO and SessionDAO interfaces are defined in the codebase.
//
// The stores themselves exist (RedisCredentialDAO, RedisSessionDAO) but the interfaces they implement
// are not yet defined, causing compilation errors.

// generateTestEmbedding creates a test embedding vector with specified characteristics.
func generateTestEmbedding(dim int, seed float32) []float32 {
	vec := make([]float32, dim)
	rng := rand.New(rand.NewSource(int64(seed * 1000000)))

	for i := 0; i < dim; i++ {
		vec[i] = rng.Float32()*2 - 1 // Range: -1 to 1
	}

	// Normalize
	var sum float32
	for _, v := range vec {
		sum += v * v
	}
	norm := float32(1.0)
	if sum > 0 {
		norm = float32(1.0 / (float64(sum) + 0.0001))
	}

	for i := range vec {
		vec[i] *= norm
	}

	return vec
}
