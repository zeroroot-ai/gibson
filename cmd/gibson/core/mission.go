package core

import (
	"encoding/json"
	"fmt"

	"github.com/zero-day-ai/gibson/internal/mission"
	"github.com/zero-day-ai/gibson/internal/types"
)

// MissionListResult represents the structured output from MissionList
type MissionListResult struct {
	Missions []*mission.Mission
	Count    int
}

// MissionList lists all missions with optional status filter.
// Returns structured data that can be formatted by CLI or TUI.
func MissionList(cc *CommandContext, statusFilter string) (*CommandResult, error) {
	// Validate mission store
	if cc.MissionStore == nil {
		return nil, fmt.Errorf("mission store not initialized")
	}

	// Parse status filter
	var filter *mission.MissionFilter
	if statusFilter != "" {
		status := mission.MissionStatus(statusFilter)
		// Validate status
		if !IsValidMissionStatus(status) {
			return &CommandResult{
				Error: fmt.Errorf("invalid status filter: must be pending, running, completed, failed, or cancelled"),
			}, nil
		}
		filter = mission.NewMissionFilter().WithStatus(status)
	} else {
		filter = mission.NewMissionFilter()
	}

	// List missions
	missions, err := cc.MissionStore.List(cc.Ctx, filter)
	if err != nil {
		return &CommandResult{
			Error: fmt.Errorf("failed to list missions: %w", err),
		}, nil
	}

	return &CommandResult{
		Data: &MissionListResult{
			Missions: missions,
			Count:    len(missions),
		},
		Message: fmt.Sprintf("Found %d missions", len(missions)),
	}, nil
}

// MissionShow displays detailed information about a specific mission.
func MissionShow(cc *CommandContext, name string) (*CommandResult, error) {
	// Validate mission store
	if cc.MissionStore == nil {
		return nil, fmt.Errorf("mission store not initialized")
	}

	// Get mission
	m, err := cc.MissionStore.GetByName(cc.Ctx, name)
	if err != nil {
		return &CommandResult{
			Error: fmt.Errorf("failed to get mission: %w", err),
		}, nil
	}

	return &CommandResult{
		Data:    m,
		Message: fmt.Sprintf("Mission '%s' details", m.Name),
	}, nil
}

// MissionRunResult represents the structured output from MissionRun
type MissionRunResult struct {
	Mission     *mission.Mission
	Run         *mission.MissionRun
	Definition  *mission.MissionDefinition
	Status      string
	NodesCount  int
	EntryPoints int
	ExitPoints  int
	IsNewMission bool // True if a new mission was created, false if reusing existing
}

// MissionRun creates and runs a new mission execution from a workflow YAML file.
// If a mission with the same name already exists, it reuses the mission's stable ID
// and creates a new MissionRun to track this execution.
func MissionRun(cc *CommandContext, workflowFile string, targetFlag string) (*CommandResult, error) {
	// Validate stores
	if cc.MissionStore == nil {
		return nil, fmt.Errorf("mission store not initialized")
	}
	if cc.MissionRunStore == nil {
		return nil, fmt.Errorf("mission run store not initialized")
	}

	// Parse mission definition file
	def, err := mission.ParseDefinition(workflowFile)
	if err != nil {
		return &CommandResult{
			Error: fmt.Errorf("failed to parse mission definition: %w", err),
		}, nil
	}

	// Resolve target (use TargetRef from definition or CLI override)
	var targetID types.ID
	if targetFlag != "" {
		// CLI flag overrides definition
		targetID, err = lookupTarget(cc, targetFlag)
	} else if def.TargetRef != "" {
		// Use target reference from definition
		targetID, err = lookupTarget(cc, def.TargetRef)
	} else {
		err = fmt.Errorf("target required: specify in YAML or use --target flag")
	}

	if err != nil {
		return &CommandResult{
			Error: fmt.Errorf("failed to resolve target: %w", err),
		}, nil
	}

	// Serialize definition to JSON
	definitionJSON, err := json.Marshal(def)
	if err != nil {
		return &CommandResult{
			Error: fmt.Errorf("failed to serialize definition: %w", err),
		}, nil
	}

	// Find or create mission with stable ID
	now := mission.NewUnixTimeNow()
	missionTemplate := &mission.Mission{
		ID:               types.NewID(),
		Name:             def.Name,
		Description:      def.Description,
		Status:           mission.MissionStatusPending,
		TargetID:         targetID,
		WorkflowID:       def.ID,
		WorkflowJSON:     string(definitionJSON),
		Progress:         0.0,
		FindingsCount:    0,
		AgentAssignments: make(map[string]string),
		Metadata:         make(map[string]any),
		CreatedAt:        now,
		UpdatedAt:        now,
	}

	m, isNewMission, err := cc.MissionStore.FindOrCreateByName(cc.Ctx, missionTemplate)
	if err != nil {
		return &CommandResult{
			Error: fmt.Errorf("failed to find or create mission: %w", err),
		}, nil
	}

	// Get next run number for this mission
	runNumber, err := cc.MissionRunStore.GetNextRunNumber(cc.Ctx, m.ID)
	if err != nil {
		return &CommandResult{
			Error: fmt.Errorf("failed to get next run number: %w", err),
		}, nil
	}

	// Create new mission run
	run := mission.NewMissionRun(m.ID, runNumber)
	run.MarkStarted()

	if err := cc.MissionRunStore.Save(cc.Ctx, run); err != nil {
		return &CommandResult{
			Error: fmt.Errorf("failed to create mission run: %w", err),
		}, nil
	}

	// Note: Actual mission execution is handled by the daemon via gRPC.
	// The CLI's `gibson mission run` command calls the daemon's RunMission RPC,
	// which delegates to the mission manager for orchestration.
	// This core library function only creates the mission record.

	return &CommandResult{
		Data: &MissionRunResult{
			Mission:      m,
			Run:          run,
			Definition:   def,
			Status:       "started",
			NodesCount:   len(def.Nodes),
			EntryPoints:  len(def.EntryPoints),
			ExitPoints:   len(def.ExitPoints),
			IsNewMission: isNewMission,
		},
		Message: fmt.Sprintf("Mission '%s' run #%d started successfully (run_id: %s)", m.Name, runNumber, run.ID),
	}, nil
}

// MissionResume resumes a paused mission.
func MissionResume(cc *CommandContext, name string) (*CommandResult, error) {
	// Validate mission store
	if cc.MissionStore == nil {
		return nil, fmt.Errorf("mission store not initialized")
	}

	// Get mission
	m, err := cc.MissionStore.GetByName(cc.Ctx, name)
	if err != nil {
		return &CommandResult{
			Error: fmt.Errorf("failed to get mission: %w", err),
		}, nil
	}

	// Check if mission can be resumed (not completed or failed)
	if m.Status == mission.MissionStatusCompleted {
		return &CommandResult{
			Error: fmt.Errorf("cannot resume completed mission"),
		}, nil
	}
	if m.Status == mission.MissionStatusFailed {
		return &CommandResult{
			Error: fmt.Errorf("cannot resume failed mission"),
		}, nil
	}
	if m.Status == mission.MissionStatusCancelled {
		return &CommandResult{
			Error: fmt.Errorf("cannot resume cancelled mission"),
		}, nil
	}

	// Update status to running
	if err := cc.MissionStore.UpdateStatus(cc.Ctx, m.ID, mission.MissionStatusRunning); err != nil {
		return &CommandResult{
			Error: fmt.Errorf("failed to resume mission: %w", err),
		}, nil
	}

	return &CommandResult{
		Data: map[string]interface{}{
			"mission": m.Name,
			"status":  "resumed",
		},
		Message: fmt.Sprintf("Mission '%s' resumed successfully", m.Name),
	}, nil
}

// MissionStop stops a running mission.
func MissionStop(cc *CommandContext, name string) (*CommandResult, error) {
	// Validate mission store
	if cc.MissionStore == nil {
		return nil, fmt.Errorf("mission store not initialized")
	}

	// Get mission
	m, err := cc.MissionStore.GetByName(cc.Ctx, name)
	if err != nil {
		return &CommandResult{
			Error: fmt.Errorf("failed to get mission: %w", err),
		}, nil
	}

	// Check if mission is running
	if m.Status != mission.MissionStatusRunning {
		return &CommandResult{
			Error: fmt.Errorf("mission is not running (current status: %s)", m.Status),
		}, nil
	}

	// Update status to cancelled
	if err := cc.MissionStore.UpdateStatus(cc.Ctx, m.ID, mission.MissionStatusCancelled); err != nil {
		return &CommandResult{
			Error: fmt.Errorf("failed to stop mission: %w", err),
		}, nil
	}

	return &CommandResult{
		Data: map[string]interface{}{
			"mission": m.Name,
			"status":  "stopped",
		},
		Message: fmt.Sprintf("Mission '%s' stopped successfully", m.Name),
	}, nil
}

// MissionDelete deletes a mission by ID or name.
// The identifier can be either a UUID (mission ID) or mission name.
// The force parameter determines whether to skip confirmation prompts (handled by caller).
// This function only performs the actual deletion logic.
func MissionDelete(cc *CommandContext, identifier string, force bool) (*CommandResult, error) {
	// Validate mission store
	if cc.MissionStore == nil {
		return nil, fmt.Errorf("mission store not initialized")
	}

	// Try to parse as UUID first, then fall back to name lookup
	var m *mission.Mission
	var err error

	if id, parseErr := types.ParseID(identifier); parseErr == nil {
		// Valid UUID - look up by ID
		m, err = cc.MissionStore.Get(cc.Ctx, id)
		if err != nil {
			return &CommandResult{
				Error: fmt.Errorf("failed to get mission by ID: %w", err),
			}, nil
		}
	} else {
		// Not a valid UUID - look up by name
		m, err = cc.MissionStore.GetByName(cc.Ctx, identifier)
		if err != nil {
			return &CommandResult{
				Error: fmt.Errorf("failed to get mission by name: %w", err),
			}, nil
		}
	}

	// Delete mission
	if err := cc.MissionStore.Delete(cc.Ctx, m.ID); err != nil {
		return &CommandResult{
			Error: fmt.Errorf("failed to delete mission: %w", err),
		}, nil
	}

	return &CommandResult{
		Data: map[string]interface{}{
			"mission": m.Name,
			"id":      m.ID.String(),
			"status":  "deleted",
		},
		Message: fmt.Sprintf("Mission '%s' (ID: %s) deleted successfully", m.Name, m.ID.String()),
	}, nil
}

// Helper functions

// IsValidMissionStatus validates that a mission status is one of the valid values.
func IsValidMissionStatus(status mission.MissionStatus) bool {
	switch status {
	case mission.MissionStatusPending,
		mission.MissionStatusRunning,
		mission.MissionStatusCompleted,
		mission.MissionStatusFailed,
		mission.MissionStatusCancelled:
		return true
	default:
		return false
	}
}

// lookupTarget finds a target by name or ID in the database.
// It tries name lookup first (more common), then falls back to UUID parsing.
func lookupTarget(cc *CommandContext, nameOrID string) (types.ID, error) {
	if cc.TargetDAO == nil {
		return "", fmt.Errorf("target DAO not initialized")
	}

	// Try name first (more common)
	target, err := cc.TargetDAO.GetByName(cc.Ctx, nameOrID)
	if err == nil {
		return target.ID, nil
	}

	// Try as UUID
	id, err := types.ParseID(nameOrID)
	if err != nil {
		return "", fmt.Errorf("target not found: %s", nameOrID)
	}

	// Verify the ID exists by fetching the target
	target, err = cc.TargetDAO.Get(cc.Ctx, id)
	if err != nil || target == nil {
		return "", fmt.Errorf("target not found: %s", nameOrID)
	}

	return id, nil
}
