package finding

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/zero-day-ai/gibson/internal/agent"
	"github.com/zero-day-ai/gibson/internal/state"
	"github.com/zero-day-ai/gibson/internal/types"
)

// RedisFindingStore implements FindingStore using Redis with RedisJSON and RediSearch.
// It provides full-text search capabilities, secondary indexes for efficient filtering,
// and atomic operations using Redis pipelines.
//
// Key Naming Convention (tenant-scoped, where {tenant} is the tenantID or "_" when empty):
//   - Finding document: "gibson:finding:{tenant}:{id}"
//   - By mission index: "gibson:finding:by_mission:{tenant}:{mission_id}"
//   - By severity index: "gibson:finding:by_severity:{tenant}:{severity}"
//
// When a finding has an empty TenantID (single-tenant / auth-disabled mode), the
// tenant segment is replaced with "_" so that keys remain consistent and scannable.
//
// Secondary Indexes:
//   - Mission index: Set of finding IDs per (tenant, mission) for efficient queries
//   - Severity index: Set of finding IDs per (tenant, severity) for filtering
//
// Full-Text Search:
//   - Uses RediSearch index: "gibson:idx:findings"
//   - Weighted fields: title (3.0), description (2.0), remediation (1.0)
//   - TAG filters: severity, status, mission_id, agent_name, category, tenant_id
//   - Sortable: risk_score, cvss_score, created_at
type RedisFindingStore struct {
	client *state.StateClient
}

// NewRedisFindingStore creates a new Redis-backed finding store.
// The StateClient must be initialized with RediSearch and RedisJSON modules.
//
// Example:
//
//	cfg := state.DefaultConfig()
//	cfg.URL = "redis://localhost:6379"
//	client, err := state.NewStateClient(cfg)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer client.Close()
//
//	store := finding.NewRedisFindingStore(client)
func NewRedisFindingStore(client *state.StateClient) *RedisFindingStore {
	return &RedisFindingStore{
		client: client,
	}
}

// Store persists an enhanced finding to Redis using JSON.SET.
// It maintains secondary indexes for mission and severity using tenant-scoped sets.
// The operation is performed atomically using a Redis pipeline.
//
// Tenant isolation strategy:
//   - The finding document is stored under a globally-unique UUID key (no tenant prefix)
//     so that Get(id) point lookups remain efficient without requiring tenantID.
//   - Secondary index sets (by_mission, by_severity) ARE scoped by tenantID, preventing
//     cross-tenant enumeration via List() and Count() operations.
//   - The finding document itself carries TenantID as a field for data-level validation.
//
// Steps:
//  1. JSON.SET the finding document (unscoped key — UUID is globally unique)
//  2. SADD to tenant-scoped mission index set
//  3. SADD to tenant-scoped severity index set
//
// Returns an error if the operation fails.
func (s *RedisFindingStore) Store(ctx context.Context, finding EnhancedFinding) error {
	// Build keys: document key is ID-only (UUID unique); index keys are tenant-scoped.
	findingKey := s.findingKey(finding.ID)
	missionSetKey := s.missionSetKey(finding.TenantID, finding.MissionID)
	severitySetKey := s.severitySetKey(finding.TenantID, finding.Severity)

	// Get underlying Redis client
	rdb := s.client.Client()

	// Use pipeline for atomic multi-key write
	pipe := rdb.Pipeline()

	// Marshal finding to JSON for JSON.SET
	data, err := json.Marshal(finding)
	if err != nil {
		return fmt.Errorf("failed to marshal finding: %w", err)
	}

	// 1. Set JSON document
	pipe.Do(ctx, "JSON.SET", findingKey, "$", string(data))

	// 2. Add to mission index
	pipe.SAdd(ctx, missionSetKey, finding.ID.String())

	// 3. Add to severity index
	pipe.SAdd(ctx, severitySetKey, finding.ID.String())

	// Execute pipeline
	_, err = pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to store finding: %w", err)
	}

	return nil
}

// Get retrieves a finding by ID using JSON.GET.
// Returns ErrNotFound if the finding does not exist.
//
// Security note: This is an ID-only point lookup. The returned EnhancedFinding carries
// its own TenantID field, allowing callers to validate tenant ownership after retrieval.
// For tenant-scoped bulk operations (listing, counting), use List() and Count() which
// enforce isolation at the index level via tenant-scoped Redis sets.
func (s *RedisFindingStore) Get(ctx context.Context, id types.ID) (*EnhancedFinding, error) {
	key := s.findingKey(id)

	var finding EnhancedFinding
	if err := s.client.JSONGet(ctx, key, "$", &finding); err != nil {
		if state.IsNotFound(err) {
			return nil, fmt.Errorf("finding not found: %s", id)
		}
		return nil, fmt.Errorf("failed to get finding: %w", err)
	}

	return &finding, nil
}

// List retrieves findings for a mission with optional filtering.
// This method uses FT.SEARCH for filtered queries and secondary indexes for simple mission queries.
//
// Without filters: Uses SMEMBERS + JSON.MGET on mission index
// With filters: Uses FT.SEARCH with filter clauses
func (s *RedisFindingStore) List(ctx context.Context, missionID types.ID, filter *FindingFilter) ([]EnhancedFinding, error) {
	// Extract tenantID from filter for tenant-scoped index lookups.
	// When filter is nil or filter.TenantID is empty, falls back to unscoped ("_") key.
	tenantID := ""
	if filter != nil {
		tenantID = filter.TenantID
	}

	// If no filters (or only tenantID filter), use efficient tenant-scoped set-based retrieval
	if filter == nil || s.isEmptyFilter(filter) {
		return s.listByMission(ctx, tenantID, missionID)
	}

	// Build search query with filters
	query := s.buildSearchQuery(missionID, filter)

	// Execute search
	searchOpts := &state.SearchOptions{
		Limit:      1000, // Default limit for list operations
		Offset:     0,
		WithScores: false,
	}

	result, err := s.client.Search(ctx, "gibson:idx:findings", query, searchOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to search findings: %w", err)
	}

	// Parse documents
	findings := make([]EnhancedFinding, 0, len(result.Documents))
	for _, doc := range result.Documents {
		var finding EnhancedFinding
		if err := json.Unmarshal(doc.JSON, &finding); err != nil {
			return nil, fmt.Errorf("failed to unmarshal finding: %w", err)
		}
		findings = append(findings, finding)
	}

	return findings, nil
}

// Update updates an existing finding in Redis.
// It handles secondary index updates if the mission or severity changed.
//
// Steps:
//  1. Fetch old finding to detect index changes
//  2. JSON.SET the updated finding
//  3. Update secondary indexes if needed
func (s *RedisFindingStore) Update(ctx context.Context, finding EnhancedFinding) error {
	// Fetch old finding to detect index changes
	oldFinding, err := s.Get(ctx, finding.ID)
	if err != nil {
		return fmt.Errorf("finding not found: %w", err)
	}

	findingKey := s.findingKey(finding.ID)
	rdb := s.client.Client()
	pipe := rdb.Pipeline()

	// Update JSON document
	data, err := json.Marshal(finding)
	if err != nil {
		return fmt.Errorf("failed to marshal finding: %w", err)
	}
	pipe.Do(ctx, "JSON.SET", findingKey, "$", string(data))

	// Update mission index if mission changed.
	// Use tenant-scoped index keys to maintain isolation.
	if oldFinding.MissionID != finding.MissionID {
		oldMissionKey := s.missionSetKey(oldFinding.TenantID, oldFinding.MissionID)
		newMissionKey := s.missionSetKey(finding.TenantID, finding.MissionID)
		pipe.SRem(ctx, oldMissionKey, finding.ID.String())
		pipe.SAdd(ctx, newMissionKey, finding.ID.String())
	}

	// Update severity index if severity changed.
	// Use tenant-scoped index keys to maintain isolation.
	if oldFinding.Severity != finding.Severity {
		oldSeverityKey := s.severitySetKey(oldFinding.TenantID, oldFinding.Severity)
		newSeverityKey := s.severitySetKey(finding.TenantID, finding.Severity)
		pipe.SRem(ctx, oldSeverityKey, finding.ID.String())
		pipe.SAdd(ctx, newSeverityKey, finding.ID.String())
	}

	// Execute pipeline
	_, err = pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to update finding: %w", err)
	}

	return nil
}

// Delete removes a finding from Redis.
// It removes both the document and all secondary index entries.
//
// Steps:
//  1. Fetch finding to get mission and severity
//  2. JSON.DEL the document
//  3. SREM from mission index
//  4. SREM from severity index
func (s *RedisFindingStore) Delete(ctx context.Context, id types.ID) error {
	// Fetch finding to get index keys (including tenant for scoped index removal)
	finding, err := s.Get(ctx, id)
	if err != nil {
		return fmt.Errorf("finding not found: %w", err)
	}

	findingKey := s.findingKey(id)
	// Use tenant-scoped index keys so that removal targets the correct tenant's sets.
	missionSetKey := s.missionSetKey(finding.TenantID, finding.MissionID)
	severitySetKey := s.severitySetKey(finding.TenantID, finding.Severity)

	rdb := s.client.Client()
	pipe := rdb.Pipeline()

	// 1. Delete JSON document
	pipe.Do(ctx, "JSON.DEL", findingKey, "$")

	// 2. Remove from mission index
	pipe.SRem(ctx, missionSetKey, id.String())

	// 3. Remove from severity index
	pipe.SRem(ctx, severitySetKey, id.String())

	// Execute pipeline
	_, err = pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to delete finding: %w", err)
	}

	return nil
}

// Count returns the total number of findings for a mission.
// Uses SCARD on the mission index set for O(1) performance.
//
// Note: Count uses the unscoped (no-tenant) mission set key for backward compatibility,
// since the FindingStore interface does not include tenantID on Count(). The primary
// use of Count() is health checks and metrics — contexts where cross-tenant precision
// is not required. For tenant-isolated counting, use List() with a tenanted filter.
func (s *RedisFindingStore) Count(ctx context.Context, missionID types.ID) (int, error) {
	// Use the no-tenant segment ("_") which represents single-tenant / legacy records.
	// Tenant-aware code that needs precise per-tenant counts should use List() instead.
	key := s.missionSetKey("", missionID)
	rdb := s.client.Client()

	count, err := rdb.SCard(ctx, key).Result()
	if err != nil {
		return 0, fmt.Errorf("failed to count findings: %w", err)
	}

	return int(count), nil
}

// ListBySeverity retrieves all findings with a specific severity level.
// Uses the severity index set for efficient retrieval.
//
// Note: ListBySeverity uses the unscoped severity index for backward compatibility.
// Tenant-scoped severity listings should use List() with a severity filter instead.
func (s *RedisFindingStore) ListBySeverity(ctx context.Context, severity agent.FindingSeverity) ([]EnhancedFinding, error) {
	key := s.severitySetKey("", severity)
	rdb := s.client.Client()

	// Get all finding IDs from severity set
	ids, err := rdb.SMembers(ctx, key).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get severity set: %w", err)
	}

	if len(ids) == 0 {
		return []EnhancedFinding{}, nil
	}

	// Build keys for JSON.MGET
	keys := make([]string, len(ids))
	for i, id := range ids {
		parsedID, err := types.ParseID(id)
		if err != nil {
			continue
		}
		keys[i] = s.findingKey(parsedID)
	}

	// Fetch all findings using JSON.MGET
	results, err := s.client.JSONMGet(ctx, keys, "$")
	if err != nil {
		return nil, fmt.Errorf("failed to mget findings: %w", err)
	}

	// Parse results
	findings := make([]EnhancedFinding, 0, len(results))
	for _, raw := range results {
		if raw == nil {
			continue
		}

		var finding EnhancedFinding
		if err := json.Unmarshal(raw, &finding); err != nil {
			return nil, fmt.Errorf("failed to unmarshal finding: %w", err)
		}
		findings = append(findings, finding)
	}

	return findings, nil
}

// Search performs full-text search on findings using RediSearch.
// Searches across title (weight 3.0), description (2.0), and remediation (1.0).
// Returns results sorted by relevance with optional score information.
//
// Query syntax supports:
//   - Full-text: "SQL injection"
//   - Exact phrase: "\"cross site scripting\""
//   - TAG filters: "@severity:{critical} @status:{open}"
//   - Numeric ranges: "@risk_score:[7.0 10.0]"
//   - Combinations: "authentication @severity:{high|critical}"
func (s *RedisFindingStore) Search(ctx context.Context, query string, opts *state.SearchOptions) (*state.SearchResult, error) {
	if opts == nil {
		opts = &state.SearchOptions{
			Limit:      50,
			Offset:     0,
			WithScores: true,
		}
	}

	// Escape query if it's not already a structured query
	if !s.isStructuredQuery(query) {
		query = state.EscapeQuery(query)
	}

	// Execute search
	result, err := s.client.Search(ctx, "gibson:idx:findings", query, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to search findings: %w", err)
	}

	return result, nil
}

// SearchWithFilter performs a full-text search with additional filtering.
// Combines text search with filter criteria for precise results.
func (s *RedisFindingStore) SearchWithFilter(ctx context.Context, searchText string, filter *FindingFilter, opts *state.SearchOptions) ([]EnhancedFinding, error) {
	// Build combined query
	var queryParts []string

	// Add text search if provided
	if searchText != "" {
		if !s.isStructuredQuery(searchText) {
			searchText = state.EscapeQuery(searchText)
		}
		queryParts = append(queryParts, searchText)
	}

	// Add filter clauses
	if filter != nil {
		filterClauses := s.buildFilterClauses(filter)
		queryParts = append(queryParts, filterClauses...)
	}

	// Combine all parts
	query := "*" // Default to match all if no parts
	if len(queryParts) > 0 {
		query = strings.Join(queryParts, " ")
	}

	// Execute search
	if opts == nil {
		opts = &state.SearchOptions{
			Limit:      50,
			Offset:     0,
			WithScores: true,
		}
	}

	result, err := s.client.Search(ctx, "gibson:idx:findings", query, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to search findings: %w", err)
	}

	// Parse documents
	findings := make([]EnhancedFinding, 0, len(result.Documents))
	for _, doc := range result.Documents {
		var finding EnhancedFinding
		if err := json.Unmarshal(doc.JSON, &finding); err != nil {
			return nil, fmt.Errorf("failed to unmarshal finding: %w", err)
		}
		findings = append(findings, finding)
	}

	return findings, nil
}

// listByMission retrieves all findings for a (tenant, mission) pair using secondary index.
// This is an optimized path for queries without filters.
// The tenantID parameter scopes the mission set lookup for tenant isolation.
// An empty tenantID uses the unscoped ("_") segment for backward compatibility.
func (s *RedisFindingStore) listByMission(ctx context.Context, tenantID string, missionID types.ID) ([]EnhancedFinding, error) {
	key := s.missionSetKey(tenantID, missionID)
	rdb := s.client.Client()

	// Get all finding IDs from tenant-scoped mission set
	ids, err := rdb.SMembers(ctx, key).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get mission set: %w", err)
	}

	if len(ids) == 0 {
		return []EnhancedFinding{}, nil
	}

	// Build document keys for JSON.MGET (document keys are unscoped by tenant)
	keys := make([]string, len(ids))
	for i, id := range ids {
		parsedID, err := types.ParseID(id)
		if err != nil {
			continue
		}
		keys[i] = s.findingKey(parsedID)
	}

	// Fetch all findings using JSON.MGET
	results, err := s.client.JSONMGet(ctx, keys, "$")
	if err != nil {
		return nil, fmt.Errorf("failed to mget findings: %w", err)
	}

	// Parse results
	findings := make([]EnhancedFinding, 0, len(results))
	for _, raw := range results {
		if raw == nil {
			continue
		}

		var finding EnhancedFinding
		if err := json.Unmarshal(raw, &finding); err != nil {
			return nil, fmt.Errorf("failed to unmarshal finding: %w", err)
		}
		findings = append(findings, finding)
	}

	return findings, nil
}

// buildSearchQuery constructs a RediSearch query string from mission ID and filters.
func (s *RedisFindingStore) buildSearchQuery(missionID types.ID, filter *FindingFilter) string {
	var parts []string

	// Always filter by mission
	if missionID.String() != "" {
		parts = append(parts, fmt.Sprintf("@mission_id:{%s}", state.EscapeTag(missionID.String())))
	}

	// Add filter clauses
	if filter != nil {
		parts = append(parts, s.buildFilterClauses(filter)...)
	}

	// If no parts, match all
	if len(parts) == 0 {
		return "*"
	}

	return strings.Join(parts, " ")
}

// buildFilterClauses builds RediSearch filter clauses from a FindingFilter.
// When filter.TenantID is set, a tenant_id TAG clause is included so that
// RediSearch results are scoped to the correct tenant.
func (s *RedisFindingStore) buildFilterClauses(filter *FindingFilter) []string {
	var clauses []string

	// Tenant isolation: add tenant_id TAG filter when tenantID is specified.
	// This provides defense-in-depth by scoping full-text search results to the tenant.
	if filter.TenantID != "" {
		clauses = append(clauses, fmt.Sprintf("@tenant_id:{%s}", state.EscapeTag(filter.TenantID)))
	}

	if filter.Severity != nil {
		clauses = append(clauses, fmt.Sprintf("@severity:{%s}", state.EscapeTag(string(*filter.Severity))))
	}

	if filter.Category != nil {
		clauses = append(clauses, fmt.Sprintf("@category:{%s}", state.EscapeTag(string(*filter.Category))))
	}

	if filter.Status != nil {
		clauses = append(clauses, fmt.Sprintf("@status:{%s}", state.EscapeTag(string(*filter.Status))))
	}

	if filter.AgentName != nil {
		clauses = append(clauses, fmt.Sprintf("@agent_name:{%s}", state.EscapeTag(*filter.AgentName)))
	}

	if filter.MinRisk != nil && filter.MaxRisk != nil {
		clauses = append(clauses, fmt.Sprintf("@risk_score:[%f %f]", *filter.MinRisk, *filter.MaxRisk))
	} else if filter.MinRisk != nil {
		clauses = append(clauses, fmt.Sprintf("@risk_score:[%f +inf]", *filter.MinRisk))
	} else if filter.MaxRisk != nil {
		clauses = append(clauses, fmt.Sprintf("@risk_score:[-inf %f]", *filter.MaxRisk))
	}

	if filter.SearchText != nil {
		// Add full-text search (will be weighted by index definition)
		text := state.EscapeQuery(*filter.SearchText)
		clauses = append(clauses, text)
	}

	return clauses
}

// isEmptyFilter checks if a filter has no criteria set.
// TenantID alone is not considered a "non-empty" filter for the purpose of
// choosing between set-based vs. search-based retrieval — it only determines
// which set key to use via listByMission.
func (s *RedisFindingStore) isEmptyFilter(filter *FindingFilter) bool {
	return filter.Severity == nil &&
		filter.Category == nil &&
		filter.Status == nil &&
		filter.MinRisk == nil &&
		filter.MaxRisk == nil &&
		filter.AgentName == nil &&
		filter.SearchText == nil
}

// isStructuredQuery checks if a query is already structured with RediSearch syntax.
func (s *RedisFindingStore) isStructuredQuery(query string) bool {
	// Structured queries typically contain @field: or other special syntax
	return strings.Contains(query, "@") || strings.Contains(query, "{") || strings.Contains(query, "[")
}

// tenantSegment returns the tenant segment for a Redis key.
// When tenantID is empty (single-tenant / auth-disabled mode), "_" is used as a
// placeholder so that all key patterns remain structurally consistent and scannable.
func tenantSegment(tenantID string) string {
	if tenantID == "" {
		return "_"
	}
	return tenantID
}

// findingKey generates the Redis key for a finding document.
// Document keys are intentionally NOT scoped by tenant because:
//   - Finding IDs are globally unique UUIDs
//   - Get(id) point-lookups don't carry tenantID in the interface signature
//   - The document itself carries TenantID for data-level validation by callers
//
// Tenant isolation is enforced at the index level via missionSetKey and severitySetKey.
//
//	"gibson:finding:{id}"
func (s *RedisFindingStore) findingKey(id types.ID) string {
	return fmt.Sprintf("gibson:finding:%s", id.String())
}

// missionSetKey generates the Redis key for the mission index set.
// The key is scoped by tenantID so that mission indexes cannot bleed across tenants:
//
//	"gibson:finding:by_mission:{tenant}:{mission_id}"
func (s *RedisFindingStore) missionSetKey(tenantID string, missionID types.ID) string {
	return fmt.Sprintf("gibson:finding:by_mission:%s:%s", tenantSegment(tenantID), missionID.String())
}

// severitySetKey generates the Redis key for the severity index set.
// The key is scoped by tenantID so that severity indexes cannot bleed across tenants:
//
//	"gibson:finding:by_severity:{tenant}:{severity}"
func (s *RedisFindingStore) severitySetKey(tenantID string, severity agent.FindingSeverity) string {
	return fmt.Sprintf("gibson:finding:by_severity:%s:%s", tenantSegment(tenantID), string(severity))
}

// ScanAll retrieves all findings using Redis SCAN.
// This method iterates through all finding keys and deserializes them.
// It skips index keys (containing `:idx:`) and handles deserialization errors gracefully.
//
// This is useful for analytics operations that need access to all findings
// across all missions. For production use with large datasets, consider
// adding pagination support.
//
// Returns a slice of all findings, or an error if the scan operation fails.
func (s *RedisFindingStore) ScanAll(ctx context.Context) ([]EnhancedFinding, error) {
	var findings []EnhancedFinding
	var cursor uint64

	// Build key pattern with prefix
	pattern := "gibson:finding:*"

	rdb := s.client.Client()

	for {
		// SCAN with cursor iteration
		keys, nextCursor, err := rdb.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			return nil, fmt.Errorf("scan failed: %w", err)
		}

		for _, key := range keys {
			// Skip index keys containing `:idx:`
			if strings.Contains(key, ":idx:") {
				continue
			}

			// Skip secondary index keys (by_mission, by_severity)
			if strings.Contains(key, ":by_mission:") || strings.Contains(key, ":by_severity:") {
				continue
			}

			// Get and deserialize each finding using JSON.GET
			var finding EnhancedFinding
			if err := s.client.JSONGet(ctx, key, "$", &finding); err != nil {
				// Handle deserialization errors gracefully - skip invalid entries
				if state.IsNotFound(err) {
					continue
				}
				// Log but continue on other errors to avoid partial failures
				continue
			}

			findings = append(findings, finding)
		}

		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}

	return findings, nil
}

// Ensure RedisFindingStore implements FindingStore at compile time
var _ FindingStore = (*RedisFindingStore)(nil)
