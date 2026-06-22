package harness

import (
	"context"
	"sync"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// FindingStore provides persistent storage for security findings discovered during agent execution.
// Findings are organized by (tenantID, missionID) to enable tenant-isolated, mission-scoped
// queries and reporting.
//
// Implementations must be safe for concurrent use from multiple goroutines, as agents
// may submit findings in parallel during mission execution.
//
// Tenant isolation: tenantID is included in all storage keys/lookups to prevent cross-tenant
// data access. If tenantID is empty (single-tenant mode), the store
// falls back to mission-only scoping for backward compatibility.
type FindingStore interface {
	// Store persists a finding for a specific tenant and mission.
	// The finding is indexed by (tenantID, missionID) to enable efficient tenant-scoped queries.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeout control
	//   - tenantID: The tenant that owns this finding (empty string = no tenant scoping)
	//   - missionID: The ID of the mission that produced this finding
	//   - finding: The security finding to store (must have a valid ID)
	//
	// Returns:
	//   - error: Non-nil if storage fails (e.g., database error, invalid finding)
	//
	// Example:
	//   finding := agent.NewFinding("SQL Injection", "Vulnerable endpoint found", agent.SeverityHigh)
	//   err := store.Store(ctx, tenantID, missionID, finding)
	Store(ctx context.Context, tenantID string, missionID types.ID, finding agent.Finding) error

	// Get retrieves findings for a specific tenant and mission, optionally filtered by criteria.
	// An empty filter returns all findings for the (tenantID, missionID) pair.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeout control
	//   - tenantID: The tenant whose findings to retrieve (empty string = no tenant scoping)
	//   - missionID: The ID of the mission whose findings to retrieve
	//   - filter: Optional filter to narrow results (see FindingFilter)
	//
	// Returns:
	//   - []agent.Finding: Slice of findings matching the filter (empty if none match)
	//   - error: Non-nil if retrieval fails (e.g., database error)
	//
	// Example:
	//   // Get all critical findings for a tenant's mission
	//   filter := NewFindingFilter().WithSeverity(agent.SeverityCritical)
	//   findings, err := store.Get(ctx, tenantID, missionID, *filter)
	Get(ctx context.Context, tenantID string, missionID types.ID, filter FindingFilter) ([]agent.Finding, error)
}

// findingStoreKey is the composite key used by InMemoryFindingStore to scope
// findings by both tenant and mission, providing defense-in-depth isolation.
// When tenantID is empty (single-tenant mode), the key falls
// back to mission-only scoping for backward compatibility.
type findingStoreKey struct {
	tenantID  string
	missionID types.ID
}

// InMemoryFindingStore is a thread-safe, in-memory implementation of FindingStore.
// It stores findings in memory organized by (tenantID, missionID) composite key
// to ensure tenant-isolated storage. When tenantID is empty, findings are stored
// under a key with an empty tenant string, maintaining backward compatibility.
//
// This implementation is suitable for:
//   - Testing and development
//   - Single-instance deployments where persistence is not required
//   - Short-lived missions where findings don't need to survive restarts
//
// For production deployments with multiple instances or persistence requirements,
// consider implementing FindingStore backed by a database (PostgreSQL, MongoDB, etc.).
//
// Thread-safety: All methods use read-write locks to ensure safe concurrent access.
type InMemoryFindingStore struct {
	mu       sync.RWMutex
	findings map[findingStoreKey][]agent.Finding // (tenantID, missionID) -> findings
}

// NewInMemoryFindingStore creates a new in-memory finding store.
// The store is ready to use immediately with no additional configuration.
func NewInMemoryFindingStore() *InMemoryFindingStore {
	return &InMemoryFindingStore{
		findings: make(map[findingStoreKey][]agent.Finding),
	}
}

// Store persists a finding in memory for the specified tenant and mission.
// The finding is appended to the (tenantID, missionID) finding list.
//
// This implementation:
//   - Does not validate the finding (caller should ensure validity)
//   - Does not check for duplicate findings
//   - Ignores the context (no I/O operations to cancel)
//   - Accepts empty tenantID for backward compatibility (single-tenant mode)
func (s *InMemoryFindingStore) Store(ctx context.Context, tenantID string, missionID types.ID, finding agent.Finding) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := findingStoreKey{tenantID: tenantID, missionID: missionID}

	// Initialize slice for this (tenant, mission) pair if it doesn't exist
	if s.findings[key] == nil {
		s.findings[key] = make([]agent.Finding, 0)
	}

	// Append the finding to the (tenant, mission) list
	s.findings[key] = append(s.findings[key], finding)

	return nil
}

// Get retrieves findings for a tenant and mission, applying optional filters.
// If no findings exist for the (tenantID, missionID) pair, returns an empty slice (not an error).
//
// This implementation:
//   - Applies filters using FindingFilter.Matches()
//   - Returns a copy of matching findings (modifications won't affect stored data)
//   - Ignores the context (no I/O operations to cancel)
//   - Accepts empty tenantID for backward compatibility (single-tenant mode)
func (s *InMemoryFindingStore) Get(ctx context.Context, tenantID string, missionID types.ID, filter FindingFilter) ([]agent.Finding, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key := findingStoreKey{tenantID: tenantID, missionID: missionID}

	// Get all findings for this (tenant, mission) pair
	missionFindings, exists := s.findings[key]
	if !exists {
		// No findings for this (tenant, mission) pair - return empty slice
		return []agent.Finding{}, nil
	}

	// If no filter criteria, return all findings (copy to prevent external modification)
	result := make([]agent.Finding, 0, len(missionFindings))

	// Apply filter to each finding
	for _, finding := range missionFindings {
		if filter.Matches(finding) {
			result = append(result, finding)
		}
	}

	return result, nil
}

// Count returns the total number of findings stored for a (tenantID, missionID) pair.
// This is a convenience method for tracking mission progress.
// When tenantID is empty, counts findings for the mission regardless of tenant scoping.
func (s *InMemoryFindingStore) Count(missionID types.ID) int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Sum across all tenants for this mission to maintain backward-compatible semantics.
	// This is intentional: Count() is an internal utility method not on the interface,
	// and callers using it (tests, monitoring) expect mission-level counts.
	total := 0
	for key, findings := range s.findings {
		if key.missionID == missionID {
			total += len(findings)
		}
	}
	return total
}

// Clear removes all findings for a specific mission across all tenants.
// This is useful for cleaning up after mission completion or cancellation.
func (s *InMemoryFindingStore) Clear(missionID types.ID) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for key := range s.findings {
		if key.missionID == missionID {
			delete(s.findings, key)
		}
	}
}

// ClearAll removes all findings for all missions.
// This is primarily useful for testing scenarios.
func (s *InMemoryFindingStore) ClearAll() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.findings = make(map[findingStoreKey][]agent.Finding)
}

// Ensure InMemoryFindingStore implements FindingStore at compile time
var _ FindingStore = (*InMemoryFindingStore)(nil)
