package finding

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/zero-day-ai/gibson/internal/agent"
	"github.com/zero-day-ai/gibson/internal/types"
)

// FindingStore provides persistence for EnhancedFindings
type FindingStore interface {
	// Store persists an enhanced finding
	Store(ctx context.Context, finding EnhancedFinding) error

	// Get retrieves a finding by ID
	Get(ctx context.Context, id types.ID) (*EnhancedFinding, error)

	// List retrieves findings for a mission with optional filtering
	List(ctx context.Context, missionID types.ID, filter *FindingFilter) ([]EnhancedFinding, error)

	// Update updates an existing finding
	Update(ctx context.Context, finding EnhancedFinding) error

	// Delete removes a finding
	Delete(ctx context.Context, id types.ID) error

	// Count returns the total number of findings for a mission
	Count(ctx context.Context, missionID types.ID) (int, error)
}

// FindingFilter provides filtering options for finding queries
type FindingFilter struct {
	Severity   *agent.FindingSeverity
	Category   *FindingCategory
	Status     *FindingStatus
	MinRisk    *float64
	MaxRisk    *float64
	AgentName  *string
	SearchText *string
}

// NewFindingFilter creates a new empty filter
func NewFindingFilter() *FindingFilter {
	return &FindingFilter{}
}

// WithSeverity filters by severity
func (f *FindingFilter) WithSeverity(severity agent.FindingSeverity) *FindingFilter {
	f.Severity = &severity
	return f
}

// WithCategory filters by category
func (f *FindingFilter) WithCategory(category FindingCategory) *FindingFilter {
	f.Category = &category
	return f
}

// WithStatus filters by status
func (f *FindingFilter) WithStatus(status FindingStatus) *FindingFilter {
	f.Status = &status
	return f
}

// WithRiskRange filters by risk score range
func (f *FindingFilter) WithRiskRange(min, max float64) *FindingFilter {
	f.MinRisk = &min
	f.MaxRisk = &max
	return f
}

// InMemoryFindingStore is a simple in-memory implementation of FindingStore for testing.
// This implementation stores findings in memory and does not persist across restarts.
type InMemoryFindingStore struct {
	mu       sync.RWMutex
	findings map[types.ID]EnhancedFinding // findingID -> finding
}

// NewInMemoryFindingStore creates a new in-memory finding store.
func NewInMemoryFindingStore() *InMemoryFindingStore {
	return &InMemoryFindingStore{
		findings: make(map[types.ID]EnhancedFinding),
	}
}

// Store persists an enhanced finding in memory.
func (s *InMemoryFindingStore) Store(ctx context.Context, finding EnhancedFinding) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	finding.UpdatedAt = time.Now()
	if finding.CreatedAt.IsZero() {
		finding.CreatedAt = time.Now()
	}

	s.findings[finding.ID] = finding
	return nil
}

// Get retrieves a finding by ID.
func (s *InMemoryFindingStore) Get(ctx context.Context, id types.ID) (*EnhancedFinding, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	finding, ok := s.findings[id]
	if !ok {
		return nil, fmt.Errorf("finding not found: %s", id)
	}

	return &finding, nil
}

// List retrieves findings for a mission with optional filtering.
func (s *InMemoryFindingStore) List(ctx context.Context, missionID types.ID, filter *FindingFilter) ([]EnhancedFinding, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var results []EnhancedFinding
	for _, finding := range s.findings {
		// Filter by mission ID
		if missionID.String() != "" && finding.MissionID != missionID {
			continue
		}

		// Apply filters if provided
		if filter != nil {
			if filter.Severity != nil && finding.Severity != *filter.Severity {
				continue
			}
			if filter.Category != nil && finding.Category != string(*filter.Category) {
				continue
			}
			if filter.Status != nil && finding.Status != *filter.Status {
				continue
			}
			if filter.MinRisk != nil && finding.RiskScore < *filter.MinRisk {
				continue
			}
			if filter.MaxRisk != nil && finding.RiskScore > *filter.MaxRisk {
				continue
			}
			if filter.AgentName != nil && finding.AgentName != *filter.AgentName {
				continue
			}
			if filter.SearchText != nil {
				searchLower := strings.ToLower(*filter.SearchText)
				if !strings.Contains(strings.ToLower(finding.Title), searchLower) &&
					!strings.Contains(strings.ToLower(finding.Description), searchLower) {
					continue
				}
			}
		}

		results = append(results, finding)
	}

	return results, nil
}

// Update updates an existing finding.
func (s *InMemoryFindingStore) Update(ctx context.Context, finding EnhancedFinding) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.findings[finding.ID]; !ok {
		return fmt.Errorf("finding not found: %s", finding.ID)
	}

	finding.UpdatedAt = time.Now()
	s.findings[finding.ID] = finding
	return nil
}

// Delete removes a finding from memory.
func (s *InMemoryFindingStore) Delete(ctx context.Context, id types.ID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.findings[id]; !ok {
		return fmt.Errorf("finding not found: %s", id)
	}

	delete(s.findings, id)
	return nil
}

// Count returns the total number of findings for a mission.
func (s *InMemoryFindingStore) Count(ctx context.Context, missionID types.ID) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	count := 0
	for _, finding := range s.findings {
		if missionID.String() == "" || finding.MissionID == missionID {
			count++
		}
	}

	return count, nil
}

// ScanAll retrieves all findings in memory.
// This method is used for analytics operations that need access to all findings.
func (s *InMemoryFindingStore) ScanAll(ctx context.Context) ([]EnhancedFinding, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	results := make([]EnhancedFinding, 0, len(s.findings))
	for _, finding := range s.findings {
		results = append(results, finding)
	}

	return results, nil
}

// Ensure InMemoryFindingStore implements FindingStore at compile time
var _ FindingStore = (*InMemoryFindingStore)(nil)
