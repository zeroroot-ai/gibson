package mission

import (
	"context"
	"fmt"
	"time"

	"github.com/zero-day-ai/gibson/internal/types"
)

// MissionService provides business logic for mission operations.
type MissionService interface {
	// CreateFromConfig creates a mission from a YAML configuration
	CreateFromConfig(ctx context.Context, config *MissionConfig) (*Mission, error)

	// ValidateMission validates all mission fields and references
	ValidateMission(ctx context.Context, mission *Mission) error

	// LoadWorkflow resolves workflow from store or inline definition
	LoadWorkflow(ctx context.Context, config *MissionWorkflowConfig) (interface{}, error)

	// AggregateFindings collects findings from all sources for a mission
	AggregateFindings(ctx context.Context, missionID types.ID) ([]interface{}, error)

	// GetSummary returns mission summary with finding counts
	GetSummary(ctx context.Context, missionID types.ID) (*MissionSummary, error)
}

// MissionSummary provides a high-level overview of a mission.
type MissionSummary struct {
	Mission         *Mission         `json:"mission"`
	FindingsCount   int              `json:"findings_count"`
	FindingsByLevel map[string]int   `json:"findings_by_level"`
	Progress        *MissionProgress `json:"progress"`
}

// WorkflowStore provides access to workflow definitions.
type WorkflowStore interface {
	// Get retrieves a workflow by ID
	Get(ctx context.Context, id types.ID) (*MissionDefinition, error)

	// GetByName retrieves a workflow by name
	GetByName(ctx context.Context, name string) (*MissionDefinition, error)
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
	store           MissionStore
	workflowStore   WorkflowStore
	findingStore    FindingStore
	targetStore     TargetStoreInterface
	inlineProcessor *InlineConfigProcessor
}

// NewMissionService creates a new mission service.
func NewMissionService(store MissionStore, workflowStore WorkflowStore, findingStore FindingStore) *DefaultMissionService {
	return &DefaultMissionService{
		store:         store,
		workflowStore: workflowStore,
		findingStore:  findingStore,
	}
}

// SetTargetStore sets the target store for the service.
func (s *DefaultMissionService) SetTargetStore(targetStore TargetStoreInterface) {
	s.targetStore = targetStore
}

// SetInlineProcessor sets the inline configuration processor for the service.
func (s *DefaultMissionService) SetInlineProcessor(processor *InlineConfigProcessor) {
	s.inlineProcessor = processor
}

// CreateFromConfig creates a mission from a YAML configuration.
func (s *DefaultMissionService) CreateFromConfig(ctx context.Context, config *MissionConfig) (*Mission, error) {
	// Validate mutual exclusivity of reference and inline configs
	if config.Target.Reference != "" && config.Target.Inline != nil {
		return nil, fmt.Errorf("cannot specify both target reference and inline target")
	}
	if config.Workflow.Reference != "" && config.Workflow.Inline != nil {
		return nil, fmt.Errorf("cannot specify both workflow reference and inline workflow")
	}

	// Resolve target reference or process inline target
	var targetID types.ID
	if config.Target.Reference != "" {
		target, err := s.resolveTarget(ctx, config.Target.Reference)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve target '%s': %w", config.Target.Reference, err)
		}
		targetID = target.ID
	} else if config.Target.Inline != nil {
		// Process inline target configuration
		if s.inlineProcessor == nil {
			return nil, fmt.Errorf("inline target configuration requires inline processor to be configured")
		}
		inlineTarget := config.Target.Inline.ToInlineTarget()
		id, err := s.inlineProcessor.ProcessInlineTarget(ctx, inlineTarget)
		if err != nil {
			return nil, fmt.Errorf("failed to process inline target: %w", err)
		}
		targetID = id
	} else {
		return nil, fmt.Errorf("target must be specified (reference or inline)")
	}

	// Resolve workflow reference or process inline workflow
	var workflowID types.ID
	if config.Workflow.Reference != "" {
		workflow, err := s.resolveWorkflow(ctx, config.Workflow.Reference)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve workflow '%s': %w", config.Workflow.Reference, err)
		}
		workflowID = workflow.ID

		// Validate target/workflow compatibility (only for referenced configs)
		if config.Target.Reference != "" {
			target, _ := s.resolveTarget(ctx, config.Target.Reference)
			if err := s.validateTargetWorkflowCompatibility(target, workflow); err != nil {
				return nil, fmt.Errorf("target/workflow incompatible: %w", err)
			}
		}
	} else if config.Workflow.Inline != nil {
		// Process inline workflow configuration
		if s.inlineProcessor == nil {
			return nil, fmt.Errorf("inline workflow configuration requires inline processor to be configured")
		}
		inlineWorkflow := config.Workflow.Inline.ToInlineWorkflow()
		id, err := s.inlineProcessor.ProcessInlineWorkflow(ctx, inlineWorkflow)
		if err != nil {
			return nil, fmt.Errorf("failed to process inline workflow: %w", err)
		}
		workflowID = id
	} else {
		return nil, fmt.Errorf("workflow must be specified (reference or inline)")
	}

	// Create mission
	mission := &Mission{
		ID:          types.NewID(),
		Name:        config.Name,
		Description: config.Description,
		Status:      MissionStatusPending,
		TargetID:    targetID,
		WorkflowID:  workflowID,
		CreatedAt:   NewUnixTimeNow(),
		UpdatedAt:   NewUnixTimeNow(),
	}

	// Convert constraints if specified
	if config.Constraints != nil {
		constraints, err := config.Constraints.ToConstraints()
		if err != nil {
			return nil, fmt.Errorf("failed to convert constraints: %w", err)
		}
		mission.Constraints = constraints
	}

	// Validate the mission
	if err := s.ValidateMission(ctx, mission); err != nil {
		return nil, err
	}

	// Save to store
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

	// Validate workflow exists if WorkflowID is set
	if !mission.WorkflowID.IsZero() && s.workflowStore != nil {
		_, err := s.workflowStore.Get(ctx, mission.WorkflowID)
		if err != nil {
			return fmt.Errorf("workflow validation failed: %w", err)
		}
	}

	// Validate constraints are reasonable if set
	if mission.Constraints != nil {
		if err := mission.Constraints.Validate(); err != nil {
			return fmt.Errorf("constraints validation failed: %w", err)
		}

		// Additional reasonableness checks
		if mission.Constraints.MaxDuration > 0 && mission.Constraints.MaxDuration < 1*time.Minute {
			return fmt.Errorf("max_duration too short: minimum 1 minute required")
		}

		// Note: MaxFindings == 0 is treated as "unlimited/not set"
		// Only validate if a positive value is specified but is invalid (which can't happen for int)

		if mission.Constraints.MaxCost > 0 && mission.Constraints.MaxCost < 0.01 {
			return fmt.Errorf("max_cost too low: minimum $0.01 required")
		}

		if mission.Constraints.MaxTokens > 0 && mission.Constraints.MaxTokens < 1000 {
			return fmt.Errorf("max_tokens too low: minimum 1000 tokens required")
		}
	}

	return nil
}

// resolveTarget resolves a target reference (name or ID) to a Target.
func (s *DefaultMissionService) resolveTarget(ctx context.Context, ref string) (*types.Target, error) {
	if ref == "" {
		return nil, fmt.Errorf("target reference is empty")
	}

	if s.targetStore == nil {
		return nil, fmt.Errorf("target store not configured")
	}

	// Try as ID first
	if id, err := types.ParseID(ref); err == nil {
		target, err := s.targetStore.Get(ctx, id)
		if err == nil {
			return target, nil
		}
	}

	// Try as name
	target, err := s.targetStore.GetByName(ctx, ref)
	if err != nil {
		return nil, fmt.Errorf("target not found: %s", ref)
	}

	return target, nil
}

// resolveWorkflow resolves a workflow reference to a MissionDefinition.
func (s *DefaultMissionService) resolveWorkflow(ctx context.Context, ref string) (*MissionDefinition, error) {
	if ref == "" {
		return nil, fmt.Errorf("workflow reference is empty")
	}

	if s.workflowStore == nil {
		return nil, fmt.Errorf("workflow store not configured")
	}

	// Try as ID first
	if id, err := types.ParseID(ref); err == nil {
		workflow, err := s.workflowStore.Get(ctx, id)
		if err == nil {
			return workflow, nil
		}
	}

	// Try as name
	workflow, err := s.workflowStore.GetByName(ctx, ref)
	if err != nil {
		return nil, fmt.Errorf("workflow not found: %s", ref)
	}

	return workflow, nil
}

// validateTargetWorkflowCompatibility checks if target and workflow are compatible.
func (s *DefaultMissionService) validateTargetWorkflowCompatibility(target *types.Target, workflow *MissionDefinition) error {
	if target == nil || workflow == nil {
		return fmt.Errorf("target and workflow cannot be nil")
	}

	// Check target type matches workflow requirements (if specified in metadata)
	if requiredType, ok := workflow.Metadata["required_target_type"].(string); ok {
		if requiredType != "" && target.Type != requiredType {
			return fmt.Errorf("workflow requires target type '%s', got '%s'",
				requiredType, target.Type)
		}
	}

	// Check target has required capabilities (if specified in metadata)
	if requiredCaps, ok := workflow.Metadata["required_capabilities"].([]interface{}); ok {
		for _, cap := range requiredCaps {
			capStr, ok := cap.(string)
			if !ok {
				continue
			}
			if !target.HasCapability(capStr) {
				return fmt.Errorf("target missing required capability: %s", capStr)
			}
		}
	}

	return nil
}

// LoadWorkflow resolves workflow from store or inline definition.
func (s *DefaultMissionService) LoadWorkflow(ctx context.Context, config *MissionWorkflowConfig) (interface{}, error) {
	if config == nil {
		return nil, fmt.Errorf("workflow config is required")
	}

	// If inline workflow is provided, return it directly (already validated in config)
	if config.Inline != nil {
		return config.Inline, nil
	}

	// If workflow reference is provided, load from store
	if config.Reference != "" {
		if s.workflowStore == nil {
			return nil, fmt.Errorf("workflow store not configured but workflow reference provided: %s", config.Reference)
		}

		// Try to parse reference as ID
		workflowID, err := types.ParseID(config.Reference)
		if err != nil {
			// If not a valid ID, treat as workflow name
			// For now, return error since we don't have name-based lookup
			return nil, fmt.Errorf("invalid workflow ID: %s", config.Reference)
		}

		workflow, err := s.workflowStore.Get(ctx, workflowID)
		if err != nil {
			return nil, fmt.Errorf("failed to load workflow %s: %w", config.Reference, err)
		}

		return workflow, nil
	}

	return nil, fmt.Errorf("workflow config must specify either 'reference' or 'inline'")
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
