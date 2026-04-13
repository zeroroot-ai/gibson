package finding

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/zero-day-ai/gibson/internal/agent"
	"github.com/zero-day-ai/gibson/internal/state"
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

// Save stores a Finding to Redis. It adapts the flat Finding type to the
// EnhancedFinding structure expected by the underlying store.
func (s *RedisFindingStore) Save(ctx context.Context, f *Finding) error {
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
func (s *RedisFindingStore) GetByMission(ctx context.Context, missionID types.ID) ([]*Finding, error) {
	enhanced, err := s.listByMission(ctx, "", missionID)
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

// Search executes a finding search using SearchOptions and returns flat Finding results.
func (s *RedisFindingStore) Search(ctx context.Context, opts *SearchOptions) ([]*Finding, error) {
	if opts == nil {
		opts = &SearchOptions{}
	}

	limit := opts.Limit
	if limit <= 0 {
		limit = 50
	}

	searchOpts := &state.SearchOptions{
		Limit:      limit,
		Offset:     opts.Offset,
		WithScores: false,
	}

	query := buildFindingSearchQuery(opts)

	result, err := s.client.Search(ctx, "gibson:idx:findings", query, searchOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to search findings: %w", err)
	}

	out := make([]*Finding, 0, len(result.Documents))
	for _, doc := range result.Documents {
		var enhanced EnhancedFinding
		if err := json.Unmarshal(doc.JSON, &enhanced); err != nil {
			return nil, fmt.Errorf("failed to unmarshal finding: %w", err)
		}

		out = append(out, &Finding{
			ID:          enhanced.ID,
			MissionID:   enhanced.MissionID,
			TenantID:    enhanced.TenantID,
			Title:       enhanced.Title,
			Description: enhanced.Description,
			Severity:    enhanced.Severity,
			Status:      enhanced.Status,
			RiskScore:   enhanced.RiskScore,
			AgentName:   enhanced.AgentName,
			CreatedAt:   enhanced.CreatedAt,
			UpdatedAt:   enhanced.UpdatedAt,
		})
	}

	return out, nil
}

// buildFindingSearchQuery constructs a RediSearch query from SearchOptions.
func buildFindingSearchQuery(opts *SearchOptions) string {
	var parts []string

	if opts.MissionID != "" {
		parts = append(parts, fmt.Sprintf("@mission_id:{%s}", state.EscapeTag(opts.MissionID.String())))
	}

	if opts.Severity != "" {
		parts = append(parts, fmt.Sprintf("@severity:{%s}", state.EscapeTag(string(opts.Severity))))
	}

	if opts.Query != "" {
		parts = append(parts, state.EscapeQuery(opts.Query))
	}

	if len(parts) == 0 {
		return "*"
	}

	return strings.Join(parts, " ")
}
