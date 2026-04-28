package finding

import (
	"context"
	"fmt"
	"time"

	"github.com/zero-day-ai/gibson/internal/agent"
	"github.com/zero-day-ai/gibson/internal/types"
)

// Severity constants re-exported from the agent package for convenience.
// These mirror agent.SeverityCritical etc. so callers can use finding.SeverityCritical.
const (
	SeverityCritical = agent.SeverityCritical
	SeverityHigh     = agent.SeverityHigh
	SeverityMedium   = agent.SeverityMedium
	SeverityLow      = agent.SeverityLow
	SeverityInfo     = agent.SeverityInfo
)

// Finding is a flat representation of a security finding used in integration
// tests and integration layers. It carries the core fields without embedding
// agent.Finding so that composite literals work without importing the agent package.
type Finding struct {
	ID          types.ID              `json:"id"`
	MissionID   types.ID              `json:"mission_id"`
	TenantID    string                `json:"tenant_id,omitempty"`
	Title       string                `json:"title"`
	Description string                `json:"description"`
	Severity    agent.FindingSeverity `json:"severity"`
	Status      FindingStatus         `json:"status"`
	RiskScore   float64               `json:"risk_score"`
	AgentName   string                `json:"agent_name,omitempty"`
	CreatedAt   time.Time             `json:"created_at"`
	UpdatedAt   time.Time             `json:"updated_at,omitempty"`
}

// SearchOptions configures a finding search query.
type SearchOptions struct {
	// Query is the full-text search string.
	Query string

	// Severity filters results to a specific severity level.
	// Zero value means no severity filter.
	Severity agent.FindingSeverity

	// MissionID restricts results to a single mission.
	MissionID types.ID

	// Limit caps the number of returned results (0 = use a sensible default).
	Limit int

	// Offset is the number of results to skip for pagination.
	Offset int
}

// Save stores a Finding in the per-tenant store. It adapts the flat Finding type
// to the EnhancedFinding structure expected by the underlying store.
// This method is now defined on ConnBoundFindingStore (post per-tenant cutover).
func (s *ConnBoundFindingStore) Save(ctx context.Context, f *Finding) error {
	if f == nil {
		return fmt.Errorf("finding must not be nil")
	}

	updatedAt := f.UpdatedAt
	if updatedAt.IsZero() {
		updatedAt = f.CreatedAt
	}

	enhanced := EnhancedFinding{
		Finding: agent.Finding{
			ID:          f.ID,
			TenantID:    f.TenantID,
			Title:       f.Title,
			Description: f.Description,
			Severity:    f.Severity,
			Confidence:  1.0,
			CreatedAt:   f.CreatedAt,
		},
		MissionID: f.MissionID,
		AgentName: f.AgentName,
		Status:    f.Status,
		RiskScore: f.RiskScore,
		UpdatedAt: updatedAt,
	}

	return s.Store(ctx, enhanced)
}

// GetByMission retrieves all Finding records for a mission.
// Results are returned as a slice of *Finding using the flat representation.
func (s *ConnBoundFindingStore) GetByMission(ctx context.Context, missionID types.ID) ([]*Finding, error) {
	enhanced, err := s.listByMission(ctx, missionID)
	if err != nil {
		return nil, err
	}

	out := make([]*Finding, 0, len(enhanced))
	for i := range enhanced {
		e := &enhanced[i]
		out = append(out, &Finding{
			ID:          e.ID,
			MissionID:   e.MissionID,
			TenantID:    e.TenantID,
			Title:       e.Title,
			Description: e.Description,
			Severity:    e.Severity,
			Status:      e.Status,
			RiskScore:   e.RiskScore,
			AgentName:   e.AgentName,
			CreatedAt:   e.CreatedAt,
			UpdatedAt:   e.UpdatedAt,
		})
	}

	return out, nil
}

