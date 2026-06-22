package mission

import (
	"context"
	"fmt"
	"time"

	missionv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// MissionService provides business logic for mission operations.
//
// The service was previously the entry point for YAML-backed MissionConfig
// creation (via CreateFromConfig) and inline-config processing. Those paths
// were removed under spec mission-api-only-cleanup — missions are now created
// by reference only (target ID + mission definition ID).
type MissionService interface {
	// CreateByReference creates a mission that references a pre-registered target
	// and mission definition. The mission is validated and persisted; it is NOT
	// started. Callers must invoke the controller's Start/Run flow afterwards.
	CreateByReference(ctx context.Context, req CreateMissionByReferenceRequest) (*Mission, error)

	// ValidateMission validates all mission fields and references
	ValidateMission(ctx context.Context, mission *Mission) error

	// AggregateFindings collects findings from all sources for a mission
	AggregateFindings(ctx context.Context, missionID types.ID) ([]interface{}, error)

	// GetSummary returns mission summary with finding counts
	GetSummary(ctx context.Context, missionID types.ID) (*MissionSummary, error)
}

// CreateMissionByReferenceRequest is the reference-only payload for creating
// a new mission run. Inline target and inline mission are not supported.
type CreateMissionByReferenceRequest struct {
	// Name is the human-readable mission name.
	Name string

	// Description optionally describes the mission run.
	Description string

	// TargetID is the ID of a pre-registered target.
	TargetID types.ID

	// MissionDefinitionID is the ID of a pre-registered mission definition.
	MissionDefinitionID types.ID

	// Constraints optionally overrides default execution constraints.
	// Uses the canonical SDK proto type per ADR 0004.
	Constraints *missionv1.MissionConstraints

	// Metadata is free-form key/value metadata for the mission instance.
	Metadata map[string]string
}

// MissionSummary provides a high-level overview of a mission.
type MissionSummary struct {
	Mission         *Mission         `json:"mission"`
	FindingsCount   int              `json:"findings_count"`
	FindingsByLevel map[string]int   `json:"findings_by_level"`
	Progress        *MissionProgress `json:"progress"`
}

// TargetStoreInterface provides access to target entities.
type TargetStoreInterface interface {
	// Get retrieves a target by ID
	Get(ctx context.Context, id types.ID) (*types.Target, error)

	// GetByName retrieves a target by name
	GetByName(ctx context.Context, name string) (*types.Target, error)
}

// FindingStore provides access to findings.
type FindingStore interface {
	// GetByMission retrieves all findings for a mission
	GetByMission(ctx context.Context, missionID types.ID) ([]interface{}, error)

	// CountBySeverity returns finding counts grouped by severity
	CountBySeverity(ctx context.Context, missionID types.ID) (map[string]int, error)
}

// DefaultMissionService implements MissionService.
type DefaultMissionService struct {
	store        MissionStore
	findingStore FindingStore
	targetStore  TargetStoreInterface
}

// NewMissionService creates a new mission service.
func NewMissionService(store MissionStore, findingStore FindingStore) *DefaultMissionService {
	return &DefaultMissionService{
		store:        store,
		findingStore: findingStore,
	}
}

// SetTargetStore sets the target store for the service.
func (s *DefaultMissionService) SetTargetStore(targetStore TargetStoreInterface) {
	s.targetStore = targetStore
}

// CreateByReference creates a new mission referring to a pre-registered target
// and mission definition. The definition must already be registered via
// CreateMissionDefinition; inline construction is not supported.
func (s *DefaultMissionService) CreateByReference(ctx context.Context, req CreateMissionByReferenceRequest) (*Mission, error) {
	if req.Name == "" {
		return nil, fmt.Errorf("mission name is required")
	}
	if req.TargetID.IsZero() {
		return nil, fmt.Errorf("target_id is required")
	}
	if req.MissionDefinitionID.IsZero() {
		return nil, fmt.Errorf("mission_definition_id is required")
	}

	mission := &Mission{
		ID:                  types.NewID(),
		Name:                req.Name,
		Description:         req.Description,
		Status:              MissionStatusPending,
		TargetID:            req.TargetID,
		MissionDefinitionID: req.MissionDefinitionID,
		Constraints:         req.Constraints,
		CreatedAt:           NewUnixTimeNow(),
		UpdatedAt:           NewUnixTimeNow(),
	}

	if err := s.ValidateMission(ctx, mission); err != nil {
		return nil, err
	}

	if err := s.store.Save(ctx, mission); err != nil {
		return nil, fmt.Errorf("failed to save mission: %w", err)
	}

	return mission, nil
}

// ValidateMission validates all mission fields and references.
func (s *DefaultMissionService) ValidateMission(ctx context.Context, mission *Mission) error {
	// First validate basic mission fields
	if err := mission.Validate(); err != nil {
		return err
	}

	// Validate constraints are reasonable if set
	if mission.Constraints != nil {
		if err := ValidateConstraints(mission.Constraints); err != nil {
			return fmt.Errorf("constraints validation failed: %w", err)
		}

		// Additional reasonableness checks against platform minimums.
		// Proto zero = unlimited (ADR 0004), so only check when a limit is set.
		if d := constraintsDuration(mission.Constraints); d > 0 && d < 1*time.Minute {
			return fmt.Errorf("max_duration too short: minimum 1 minute required")
		}

		// Note: MaxFindings == 0 is treated as "unlimited/not set"

		if mission.Constraints.GetMaxCost() > 0 && mission.Constraints.GetMaxCost() < 0.01 {
			return fmt.Errorf("max_cost too low: minimum $0.01 required")
		}

		if mission.Constraints.GetMaxTokens() > 0 && mission.Constraints.GetMaxTokens() < 1000 {
			return fmt.Errorf("max_tokens too low: minimum 1000 tokens required")
		}
	}

	return nil
}

// AggregateFindings collects findings from all sources for a mission.
func (s *DefaultMissionService) AggregateFindings(ctx context.Context, missionID types.ID) ([]interface{}, error) {
	if missionID.IsZero() {
		return nil, fmt.Errorf("mission ID is required")
	}

	if s.findingStore == nil {
		return nil, fmt.Errorf("finding store not configured")
	}

	// Query finding store for all findings related to this mission
	findings, err := s.findingStore.GetByMission(ctx, missionID)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve findings for mission %s: %w", missionID, err)
	}

	return findings, nil
}

// GetSummary returns mission summary with finding counts.
func (s *DefaultMissionService) GetSummary(ctx context.Context, missionID types.ID) (*MissionSummary, error) {
	if missionID.IsZero() {
		return nil, fmt.Errorf("mission ID is required")
	}

	mission, err := s.store.Get(ctx, missionID)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve mission: %w", err)
	}

	summary := &MissionSummary{
		Mission:         mission,
		FindingsCount:   0,
		FindingsByLevel: make(map[string]int),
		Progress:        mission.GetProgress(),
	}

	// If finding store is configured, get actual finding counts
	if s.findingStore != nil {
		// Get findings count by severity
		countsBySeverity, err := s.findingStore.CountBySeverity(ctx, missionID)
		if err != nil {
			// Log the error but don't fail the whole summary
			// Continue with zero counts
			summary.FindingsByLevel = make(map[string]int)
		} else {
			// Calculate total findings
			totalFindings := 0
			for severity, count := range countsBySeverity {
				summary.FindingsByLevel[severity] = count
				totalFindings += count
			}
			summary.FindingsCount = totalFindings
		}
	}

	return summary, nil
}

// Ensure DefaultMissionService implements MissionService.
var _ MissionService = (*DefaultMissionService)(nil)
