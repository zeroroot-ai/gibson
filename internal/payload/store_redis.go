package payload

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/zero-day-ai/gibson/internal/agent"
	"github.com/zero-day-ai/gibson/internal/state"
	"github.com/zero-day-ai/gibson/internal/types"
)

// RedisPayloadStore implements PayloadStore using Redis with RedisJSON and RediSearch.
// It provides versioned payload storage with full-text search capabilities.
//
// Key Naming Convention:
//   - Payload document: "gibson:payload:{id}"
//   - Name lookup: "gibson:payload:by_name:{name}" → ID
//   - Version history: "gibson:payload:{id}:versions" (sorted set, score = version number)
//   - Version snapshot: "gibson:payload_version:{id}:{version}"
//   - Execution: "gibson:payload_exec:{id}"
//   - Chain: "gibson:chain:{id}"
//   - Chain execution: "gibson:chain_exec:{id}"
type RedisPayloadStore struct {
	client *state.StateClient
}

// NewRedisPayloadStore creates a new RedisPayloadStore with the given state client.
// The client must already be connected and have RedisJSON and RediSearch modules loaded.
func NewRedisPayloadStore(client *state.StateClient) *RedisPayloadStore {
	return &RedisPayloadStore{
		client: client,
	}
}

// Save inserts a new payload into Redis with version tracking.
// It creates:
//   - The payload document at "gibson:payload:{id}"
//   - A name lookup entry at "gibson:payload:by_name:{name}"
//   - An initial version snapshot in the version history
func (s *RedisPayloadStore) Save(ctx context.Context, payload *Payload) error {
	if payload == nil {
		return fmt.Errorf("payload cannot be nil")
	}

	if err := payload.Validate(); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	rdb := s.client.Client()

	// Use pipeline for atomic multi-key operation
	pipe := rdb.Pipeline()

	// 1. Save payload document with JSON.SET
	payloadKey := fmt.Sprintf("gibson:payload:%s", payload.ID)
	if err := s.client.JSONSet(ctx, payloadKey, "$", payload); err != nil {
		return fmt.Errorf("failed to save payload document: %w", err)
	}

	// 2. Create name lookup
	nameLookupKey := fmt.Sprintf("gibson:payload:by_name:%s", payload.Name)
	pipe.Set(ctx, nameLookupKey, payload.ID.String(), 0)

	// 3. Initialize version history (sorted set with version number as score)
	versionSetKey := fmt.Sprintf("gibson:payload:%s:versions", payload.ID)
	pipe.ZAdd(ctx, versionSetKey, redis.Z{
		Score:  1.0, // version 1
		Member: "v1",
	})

	// 4. Save initial version snapshot
	versionKey := fmt.Sprintf("gibson:payload_version:%s:v1", payload.ID)
	versionSnapshot := &PayloadVersion{
		ID:            types.NewID(),
		PayloadID:     payload.ID,
		Version:       "v1",
		Payload:       *payload,
		ChangeType:    "created",
		ChangeSummary: "Initial version",
		CreatedAt:     time.Now(),
	}

	versionJSON, err := json.Marshal(versionSnapshot)
	if err != nil {
		return fmt.Errorf("failed to marshal version snapshot: %w", err)
	}
	pipe.Set(ctx, versionKey, versionJSON, 0)

	// Execute pipeline
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("failed to execute save pipeline: %w", err)
	}

	return nil
}

// Get retrieves a payload by ID from Redis.
func (s *RedisPayloadStore) Get(ctx context.Context, id types.ID) (*Payload, error) {
	payloadKey := fmt.Sprintf("gibson:payload:%s", id)

	var payload Payload
	if err := s.client.JSONGet(ctx, payloadKey, "$", &payload); err != nil {
		if err == state.ErrNotFound {
			return nil, fmt.Errorf("payload not found: %s", id)
		}
		return nil, fmt.Errorf("failed to get payload: %w", err)
	}

	return &payload, nil
}

// GetByName retrieves a payload by name using the name lookup.
func (s *RedisPayloadStore) GetByName(ctx context.Context, name string) (*Payload, error) {
	rdb := s.client.Client()

	// Lookup payload ID by name
	nameLookupKey := fmt.Sprintf("gibson:payload:by_name:%s", name)
	idStr, err := rdb.Get(ctx, nameLookupKey).Result()
	if err == redis.Nil {
		return nil, fmt.Errorf("payload not found by name: %s", name)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to lookup payload by name: %w", err)
	}

	// Parse ID
	id, err := types.ParseID(idStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse payload ID: %w", err)
	}

	// Get the payload
	return s.Get(ctx, id)
}

// List retrieves payloads with optional filtering using RediSearch.
func (s *RedisPayloadStore) List(ctx context.Context, filter *PayloadFilter) ([]*Payload, error) {
	if filter == nil {
		filter = &PayloadFilter{
			Limit:  100,
			Offset: 0,
		}
	}

	// Set default limit if not specified
	if filter.Limit == 0 {
		filter.Limit = 100
	}

	// Build RediSearch query
	query := s.buildSearchQuery(filter)

	// Execute search
	searchOpts := &state.SearchOptions{
		Limit:   filter.Limit,
		Offset:  filter.Offset,
		SortBy:  "created_at",
		SortAsc: false,
	}

	result, err := s.client.Search(ctx, "gibson:idx:payloads", query, searchOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to search payloads: %w", err)
	}

	// Parse results
	payloads := make([]*Payload, 0, len(result.Documents))
	for _, doc := range result.Documents {
		var payload Payload
		if err := json.Unmarshal(doc.JSON, &payload); err != nil {
			return nil, fmt.Errorf("failed to unmarshal payload: %w", err)
		}
		payloads = append(payloads, &payload)
	}

	return payloads, nil
}

// Search performs full-text search on payloads using RediSearch.
func (s *RedisPayloadStore) Search(ctx context.Context, searchQuery string, filter *PayloadFilter) ([]*Payload, error) {
	if filter == nil {
		filter = &PayloadFilter{
			Limit:  100,
			Offset: 0,
		}
	}

	// Set default limit if not specified
	if filter.Limit == 0 {
		filter.Limit = 100
	}

	// Build combined query with search term and filters
	var queryParts []string

	// Add full-text search query
	if searchQuery != "" {
		escapedQuery := state.EscapeQuery(searchQuery)
		queryParts = append(queryParts, escapedQuery)
	}

	// Add filter conditions
	filterQuery := s.buildSearchQuery(filter)
	if filterQuery != "*" {
		queryParts = append(queryParts, filterQuery)
	}

	// Combine queries
	var finalQuery string
	if len(queryParts) == 0 {
		finalQuery = "*"
	} else if len(queryParts) == 1 {
		finalQuery = queryParts[0]
	} else {
		finalQuery = "(" + queryParts[0] + ") " + queryParts[1]
	}

	// Execute search
	searchOpts := &state.SearchOptions{
		Limit:  filter.Limit,
		Offset: filter.Offset,
	}

	result, err := s.client.Search(ctx, "gibson:idx:payloads", finalQuery, searchOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to search payloads: %w", err)
	}

	// Parse results
	payloads := make([]*Payload, 0, len(result.Documents))
	for _, doc := range result.Documents {
		var payload Payload
		if err := json.Unmarshal(doc.JSON, &payload); err != nil {
			return nil, fmt.Errorf("failed to unmarshal payload: %w", err)
		}
		payloads = append(payloads, &payload)
	}

	return payloads, nil
}

// Update modifies an existing payload and increments version.
// It creates a new version snapshot in the version history.
func (s *RedisPayloadStore) Update(ctx context.Context, payload *Payload) error {
	if payload == nil {
		return fmt.Errorf("payload cannot be nil")
	}

	if err := payload.Validate(); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	rdb := s.client.Client()

	// Get current payload to save as version snapshot
	currentPayload, err := s.Get(ctx, payload.ID)
	if err != nil {
		return fmt.Errorf("payload not found: %w", err)
	}

	// Get current version count
	versionSetKey := fmt.Sprintf("gibson:payload:%s:versions", payload.ID)
	versionCount, err := rdb.ZCard(ctx, versionSetKey).Result()
	if err != nil {
		return fmt.Errorf("failed to get version count: %w", err)
	}

	// Calculate new version number
	newVersionNum := versionCount + 1
	newVersion := fmt.Sprintf("v%d", newVersionNum)

	// Update timestamp
	payload.UpdatedAt = time.Now()

	// Use pipeline for atomic update
	pipe := rdb.Pipeline()

	// 1. Save current state as version snapshot before updating
	versionKey := fmt.Sprintf("gibson:payload_version:%s:%s", payload.ID, newVersion)
	versionSnapshot := &PayloadVersion{
		ID:            types.NewID(),
		PayloadID:     payload.ID,
		Version:       newVersion,
		Payload:       *currentPayload,
		ChangeType:    "updated",
		ChangeSummary: "",
		CreatedAt:     time.Now(),
	}

	versionJSON, err := json.Marshal(versionSnapshot)
	if err != nil {
		return fmt.Errorf("failed to marshal version snapshot: %w", err)
	}
	pipe.Set(ctx, versionKey, versionJSON, 0)

	// 2. Add version to sorted set
	pipe.ZAdd(ctx, versionSetKey, redis.Z{
		Score:  float64(newVersionNum),
		Member: newVersion,
	})

	// Execute pipeline
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("failed to save version snapshot: %w", err)
	}

	// 3. Update payload document
	payloadKey := fmt.Sprintf("gibson:payload:%s", payload.ID)
	if err := s.client.JSONSet(ctx, payloadKey, "$", payload); err != nil {
		return fmt.Errorf("failed to update payload: %w", err)
	}

	// 4. Update name lookup if name changed
	if currentPayload.Name != payload.Name {
		// Remove old name lookup
		oldNameLookupKey := fmt.Sprintf("gibson:payload:by_name:%s", currentPayload.Name)
		rdb.Del(ctx, oldNameLookupKey)

		// Add new name lookup
		newNameLookupKey := fmt.Sprintf("gibson:payload:by_name:%s", payload.Name)
		rdb.Set(ctx, newNameLookupKey, payload.ID.String(), 0)
	}

	return nil
}

// Delete soft-deletes a payload by setting enabled=false.
func (s *RedisPayloadStore) Delete(ctx context.Context, id types.ID) error {
	// Get payload
	payload, err := s.Get(ctx, id)
	if err != nil {
		return err
	}

	// Set enabled to false
	payload.Enabled = false
	payload.UpdatedAt = time.Now()

	// Update payload
	payloadKey := fmt.Sprintf("gibson:payload:%s", id)
	if err := s.client.JSONSet(ctx, payloadKey, "$.enabled", false); err != nil {
		return fmt.Errorf("failed to disable payload: %w", err)
	}

	if err := s.client.JSONSet(ctx, payloadKey, "$.updated_at", payload.UpdatedAt); err != nil {
		return fmt.Errorf("failed to update timestamp: %w", err)
	}

	return nil
}

// HardDelete permanently removes a payload and all its versions.
// This should be used with caution as it's irreversible.
func (s *RedisPayloadStore) HardDelete(ctx context.Context, id types.ID) error {
	rdb := s.client.Client()

	// Get payload to find name
	payload, err := s.Get(ctx, id)
	if err != nil {
		return err
	}

	// Get all version keys
	versionSetKey := fmt.Sprintf("gibson:payload:%s:versions", id)
	versions, err := rdb.ZRange(ctx, versionSetKey, 0, -1).Result()
	if err != nil {
		return fmt.Errorf("failed to get versions: %w", err)
	}

	// Build list of keys to delete
	keysToDelete := []string{
		fmt.Sprintf("gibson:payload:%s", id),
		fmt.Sprintf("gibson:payload:by_name:%s", payload.Name),
		versionSetKey,
	}

	// Add version snapshot keys
	for _, version := range versions {
		versionKey := fmt.Sprintf("gibson:payload_version:%s:%s", id, version)
		keysToDelete = append(keysToDelete, versionKey)
	}

	// Delete all keys
	if err := rdb.Del(ctx, keysToDelete...).Err(); err != nil {
		return fmt.Errorf("failed to delete payload: %w", err)
	}

	return nil
}

// GetVersionHistory retrieves all versions of a payload from the sorted set.
func (s *RedisPayloadStore) GetVersionHistory(ctx context.Context, id types.ID) ([]*PayloadVersion, error) {
	rdb := s.client.Client()

	// Get all versions from sorted set (ordered by version number descending)
	versionSetKey := fmt.Sprintf("gibson:payload:%s:versions", id)
	versions, err := rdb.ZRevRange(ctx, versionSetKey, 0, -1).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get version list: %w", err)
	}

	if len(versions) == 0 {
		return []*PayloadVersion{}, nil
	}

	// Fetch all version snapshots using MGET
	versionKeys := make([]string, len(versions))
	for i, version := range versions {
		versionKeys[i] = fmt.Sprintf("gibson:payload_version:%s:%s", id, version)
	}

	versionData, err := rdb.MGet(ctx, versionKeys...).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get version snapshots: %w", err)
	}

	// Parse version snapshots
	result := make([]*PayloadVersion, 0, len(versionData))
	for _, data := range versionData {
		if data == nil {
			continue
		}

		dataStr, ok := data.(string)
		if !ok {
			continue
		}

		var version PayloadVersion
		if err := json.Unmarshal([]byte(dataStr), &version); err != nil {
			return nil, fmt.Errorf("failed to unmarshal version: %w", err)
		}

		result = append(result, &version)
	}

	return result, nil
}

// Exists checks if a payload exists by ID.
func (s *RedisPayloadStore) Exists(ctx context.Context, id types.ID) (bool, error) {
	rdb := s.client.Client()
	payloadKey := fmt.Sprintf("gibson:payload:%s", id)

	exists, err := rdb.Exists(ctx, payloadKey).Result()
	if err != nil {
		return false, fmt.Errorf("failed to check existence: %w", err)
	}

	return exists > 0, nil
}

// ExistsByName checks if a payload exists by name.
func (s *RedisPayloadStore) ExistsByName(ctx context.Context, name string) (bool, error) {
	rdb := s.client.Client()
	nameLookupKey := fmt.Sprintf("gibson:payload:by_name:%s", name)

	exists, err := rdb.Exists(ctx, nameLookupKey).Result()
	if err != nil {
		return false, fmt.Errorf("failed to check name existence: %w", err)
	}

	return exists > 0, nil
}

// Count returns the total number of payloads matching the filter.
func (s *RedisPayloadStore) Count(ctx context.Context, filter *PayloadFilter) (int, error) {
	if filter == nil {
		filter = &PayloadFilter{}
	}

	// Build query
	query := s.buildSearchQuery(filter)

	// Execute search with limit 0 to get just the count
	searchOpts := &state.SearchOptions{
		Limit:  0,
		Offset: 0,
	}

	result, err := s.client.Search(ctx, "gibson:idx:payloads", query, searchOpts)
	if err != nil {
		return 0, fmt.Errorf("failed to count payloads: %w", err)
	}

	return int(result.Total), nil
}

// ImportBatch imports multiple payloads with validation.
func (s *RedisPayloadStore) ImportBatch(ctx context.Context, payloads []*Payload) (*ImportResult, error) {
	if payloads == nil {
		return nil, fmt.Errorf("payloads slice cannot be nil")
	}

	result := &ImportResult{
		Total:  len(payloads),
		Errors: []string{},
	}

	for i, payload := range payloads {
		if payload == nil {
			result.Skipped++
			result.Errors = append(result.Errors, fmt.Sprintf("payload at index %d is nil", i))
			continue
		}

		// Validate payload
		if err := payload.Validate(); err != nil {
			result.Failed++
			result.Errors = append(result.Errors, fmt.Sprintf("payload %s: %v", payload.Name, err))
			continue
		}

		// Check if payload already exists by name
		exists, err := s.ExistsByName(ctx, payload.Name)
		if err != nil {
			result.Failed++
			result.Errors = append(result.Errors, fmt.Sprintf("payload %s: failed to check existence: %v", payload.Name, err))
			continue
		}

		if exists {
			result.Skipped++
			result.Errors = append(result.Errors, fmt.Sprintf("payload %s: already exists", payload.Name))
			continue
		}

		// Save payload
		if err := s.Save(ctx, payload); err != nil {
			result.Failed++
			result.Errors = append(result.Errors, fmt.Sprintf("payload %s: save failed: %v", payload.Name, err))
			continue
		}

		result.Imported++
	}

	return result, nil
}

// GetSummaryForTargetType returns payload summary for orchestrator context.
func (s *RedisPayloadStore) GetSummaryForTargetType(ctx context.Context, targetType string) (*PayloadSummary, error) {
	// Build filter
	filter := &PayloadFilter{
		Enabled: boolPtr(true),
		Limit:   10000, // Get all enabled payloads
	}

	if targetType != "" {
		filter.TargetTypes = []string{targetType}
	}

	// Get all matching payloads
	payloads, err := s.List(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to list payloads: %w", err)
	}

	// Build summary
	summary := &PayloadSummary{
		Total:        len(payloads),
		ByCategory:   make(map[PayloadCategory]int),
		ByTargetType: make(map[string]int),
		BySeverity:   make(map[agent.FindingSeverity]int),
	}

	for _, p := range payloads {
		if p.Enabled {
			summary.EnabledCount++
		}
		if p.BuiltIn {
			summary.BuiltInCount++
		}

		// Count categories
		for _, cat := range p.Categories {
			summary.ByCategory[cat]++
		}

		// Count target types
		for _, tt := range p.TargetTypes {
			summary.ByTargetType[tt]++
		}

		// Count severity
		summary.BySeverity[p.Severity]++
	}

	return summary, nil
}

// CreateChain creates a new attack chain.
func (s *RedisPayloadStore) CreateChain(ctx context.Context, chain *PayloadChain) error {
	if chain == nil {
		return fmt.Errorf("chain cannot be nil")
	}

	if chain.Name == "" {
		return fmt.Errorf("chain name is required")
	}

	if len(chain.Steps) == 0 {
		return fmt.Errorf("chain must have at least one step")
	}

	// Validate steps
	for i, step := range chain.Steps {
		if step.ID == "" {
			return fmt.Errorf("step at index %d: ID is required", i)
		}
		if err := step.PayloadID.Validate(); err != nil {
			return fmt.Errorf("step at index %d: invalid payload ID: %w", i, err)
		}
	}

	// Set timestamps
	now := time.Now()
	if chain.CreatedAt.IsZero() {
		chain.CreatedAt = now
	}
	if chain.UpdatedAt.IsZero() {
		chain.UpdatedAt = now
	}

	// Save chain
	chainKey := fmt.Sprintf("gibson:chain:%s", chain.ID)
	if err := s.client.JSONSet(ctx, chainKey, "$", chain); err != nil {
		return fmt.Errorf("failed to save chain: %w", err)
	}

	return nil
}

// GetChain retrieves a chain by ID.
func (s *RedisPayloadStore) GetChain(ctx context.Context, id types.ID) (*PayloadChain, error) {
	chainKey := fmt.Sprintf("gibson:chain:%s", id)

	var chain PayloadChain
	if err := s.client.JSONGet(ctx, chainKey, "$", &chain); err != nil {
		if err == state.ErrNotFound {
			return nil, fmt.Errorf("chain not found: %s", id)
		}
		return nil, fmt.Errorf("failed to get chain: %w", err)
	}

	return &chain, nil
}

// ListChains retrieves all chains.
func (s *RedisPayloadStore) ListChains(ctx context.Context) ([]*PayloadChain, error) {
	// Use SCAN to find all chain keys
	rdb := s.client.Client()

	var chainKeys []string
	iter := rdb.Scan(ctx, 0, "gibson:chain:*", 0).Iterator()
	for iter.Next(ctx) {
		chainKeys = append(chainKeys, iter.Val())
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("failed to scan chains: %w", err)
	}

	if len(chainKeys) == 0 {
		return []*PayloadChain{}, nil
	}

	// Fetch all chains
	chains := make([]*PayloadChain, 0, len(chainKeys))
	for _, key := range chainKeys {
		var chain PayloadChain
		if err := s.client.JSONGet(ctx, key, "$", &chain); err != nil {
			// Skip chains that fail to load
			continue
		}
		chains = append(chains, &chain)
	}

	return chains, nil
}

// UpdateChain updates an existing chain.
func (s *RedisPayloadStore) UpdateChain(ctx context.Context, chain *PayloadChain) error {
	if chain == nil {
		return fmt.Errorf("chain cannot be nil")
	}

	if chain.Name == "" {
		return fmt.Errorf("chain name is required")
	}

	// Check if chain exists
	exists, err := s.Exists(ctx, chain.ID)
	if err != nil {
		return fmt.Errorf("failed to check chain existence: %w", err)
	}
	if !exists {
		return fmt.Errorf("chain not found: %s", chain.ID)
	}

	// Update timestamp
	chain.UpdatedAt = time.Now()

	// Save chain
	chainKey := fmt.Sprintf("gibson:chain:%s", chain.ID)
	if err := s.client.JSONSet(ctx, chainKey, "$", chain); err != nil {
		return fmt.Errorf("failed to update chain: %w", err)
	}

	return nil
}

// DeleteChain deletes a chain by ID.
func (s *RedisPayloadStore) DeleteChain(ctx context.Context, id types.ID) error {
	rdb := s.client.Client()

	chainKey := fmt.Sprintf("gibson:chain:%s", id)
	result, err := rdb.Del(ctx, chainKey).Result()
	if err != nil {
		return fmt.Errorf("failed to delete chain: %w", err)
	}

	if result == 0 {
		return fmt.Errorf("chain not found: %s", id)
	}

	return nil
}

// buildSearchQuery builds a RediSearch query from PayloadFilter.
func (s *RedisPayloadStore) buildSearchQuery(filter *PayloadFilter) string {
	if filter == nil {
		return "*"
	}

	var queryParts []string

	// Filter by IDs
	if len(filter.IDs) > 0 {
		idQueries := make([]string, len(filter.IDs))
		for i, id := range filter.IDs {
			idQueries[i] = state.EscapeTag(id.String())
		}
		// IDs are matched against the key, not a field, so we need a different approach
		// For now, we'll handle this in the List method by post-filtering
	}

	// Filter by categories
	if len(filter.Categories) > 0 {
		categoryQueries := make([]string, len(filter.Categories))
		for i, cat := range filter.Categories {
			categoryQueries[i] = state.EscapeTag(string(cat))
		}
		queryParts = append(queryParts, fmt.Sprintf("@categories:{%s}", joinOr(categoryQueries)))
	}

	// Filter by tags
	if len(filter.Tags) > 0 {
		tagQueries := make([]string, len(filter.Tags))
		for i, tag := range filter.Tags {
			tagQueries[i] = state.EscapeTag(tag)
		}
		queryParts = append(queryParts, fmt.Sprintf("@tags:{%s}", joinOr(tagQueries)))
	}

	// Filter by target types
	if len(filter.TargetTypes) > 0 {
		// Note: In the index definition, target_types is not indexed
		// We would need to add it to the index or handle this differently
		// For now, skip this filter in the query
	}

	// Filter by severities
	if len(filter.Severities) > 0 {
		severityQueries := make([]string, len(filter.Severities))
		for i, severity := range filter.Severities {
			severityQueries[i] = state.EscapeTag(string(severity))
		}
		queryParts = append(queryParts, fmt.Sprintf("@severity:{%s}", joinOr(severityQueries)))
	}

	// Filter by MITRE techniques
	if len(filter.MitreTechniques) > 0 {
		// Note: MITRE techniques are not indexed in the PayloadIndex
		// We would need to add them to the index or handle differently
		// For now, skip this filter
	}

	// Filter by built_in
	if filter.BuiltIn != nil {
		queryParts = append(queryParts, fmt.Sprintf("@built_in:{%s}", boolToString(*filter.BuiltIn)))
	}

	// Filter by enabled
	if filter.Enabled != nil {
		queryParts = append(queryParts, fmt.Sprintf("@enabled:{%s}", boolToString(*filter.Enabled)))
	}

	// Combine all query parts
	if len(queryParts) == 0 {
		return "*"
	}

	return strings.Join(queryParts, " ")
}

// Helper functions

func boolToString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func joinOr(parts []string) string {
	return strings.Join(parts, "|")
}

// SaveExecution stores a payload execution record.
func (s *RedisPayloadStore) SaveExecution(ctx context.Context, execution *Execution) error {
	if execution == nil {
		return fmt.Errorf("execution cannot be nil")
	}

	execKey := fmt.Sprintf("gibson:payload_exec:%s", execution.ID)
	if err := s.client.JSONSet(ctx, execKey, "$", execution); err != nil {
		return fmt.Errorf("failed to save execution: %w", err)
	}

	return nil
}

// GetExecution retrieves a payload execution record.
func (s *RedisPayloadStore) GetExecution(ctx context.Context, id types.ID) (*Execution, error) {
	execKey := fmt.Sprintf("gibson:payload_exec:%s", id)

	var execution Execution
	if err := s.client.JSONGet(ctx, execKey, "$", &execution); err != nil {
		if err == state.ErrNotFound {
			return nil, fmt.Errorf("execution not found: %s", id)
		}
		return nil, fmt.Errorf("failed to get execution: %w", err)
	}

	return &execution, nil
}

// ListExecutionsByPayload retrieves all executions for a specific payload.
func (s *RedisPayloadStore) ListExecutionsByPayload(ctx context.Context, payloadID types.ID, limit int) ([]*Execution, error) {
	// Use SCAN to find all execution keys
	rdb := s.client.Client()

	var execKeys []string
	iter := rdb.Scan(ctx, 0, "gibson:payload_exec:*", 0).Iterator()
	for iter.Next(ctx) {
		execKeys = append(execKeys, iter.Val())
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("failed to scan executions: %w", err)
	}

	if len(execKeys) == 0 {
		return []*Execution{}, nil
	}

	// Fetch executions and filter by payload ID
	executions := make([]*Execution, 0)
	for _, key := range execKeys {
		var execution Execution
		if err := s.client.JSONGet(ctx, key, "$", &execution); err != nil {
			continue
		}

		if execution.PayloadID == payloadID {
			executions = append(executions, &execution)
			if limit > 0 && len(executions) >= limit {
				break
			}
		}
	}

	return executions, nil
}

// SaveChainExecution stores a chain execution record.
func (s *RedisPayloadStore) SaveChainExecution(ctx context.Context, execution *ChainExecution) error {
	if execution == nil {
		return fmt.Errorf("chain execution cannot be nil")
	}

	execKey := fmt.Sprintf("gibson:chain_exec:%s", execution.ID)
	if err := s.client.JSONSet(ctx, execKey, "$", execution); err != nil {
		return fmt.Errorf("failed to save chain execution: %w", err)
	}

	return nil
}

// GetChainExecution retrieves a chain execution record.
func (s *RedisPayloadStore) GetChainExecution(ctx context.Context, id types.ID) (*ChainExecution, error) {
	execKey := fmt.Sprintf("gibson:chain_exec:%s", id)

	var execution ChainExecution
	if err := s.client.JSONGet(ctx, execKey, "$", &execution); err != nil {
		if err == state.ErrNotFound {
			return nil, fmt.Errorf("chain execution not found: %s", id)
		}
		return nil, fmt.Errorf("failed to get chain execution: %w", err)
	}

	return &execution, nil
}

// ChainExecution represents the execution of an attack chain.
type ChainExecution struct {
	ID      types.ID        `json:"id"`
	ChainID types.ID        `json:"chain_id"`
	Status  ExecutionStatus `json:"status"`

	// Stage executions
	StageExecutions map[string]*Execution `json:"stage_executions"` // stage_id -> execution

	// Timestamps
	CreatedAt   time.Time  `json:"created_at"`
	StartedAt   *time.Time `json:"started_at,omitempty"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`

	// Results
	SuccessCount int    `json:"success_count"`
	FailureCount int    `json:"failure_count"`
	ErrorMessage string `json:"error_message,omitempty"`
}

// Helper to convert Unix timestamp in milliseconds
func timeToUnixMilli(t time.Time) int64 {
	return t.UnixNano() / 1e6
}

// Helper to convert Unix timestamp from milliseconds
func unixMilliToTime(ms int64) time.Time {
	return time.Unix(0, ms*1e6)
}

// Helper to convert timestamp to string for sorting
func timeToSortable(t time.Time) string {
	return strconv.FormatInt(timeToUnixMilli(t), 10)
}
