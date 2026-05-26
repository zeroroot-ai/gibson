package mission

import (
	"encoding/json"
	"fmt"
	"time"

	missionv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"

	"github.com/zeroroot-ai/gibson/internal/types"
)

// UnixTime wraps time.Time to marshal/unmarshal as Unix epoch milliseconds.
// This is required for RediSearch NUMERIC field compatibility.
type UnixTime struct {
	time.Time
}

// MarshalJSON converts time to Unix epoch milliseconds.
func (t UnixTime) MarshalJSON() ([]byte, error) {
	if t.Time.IsZero() {
		return []byte("0"), nil
	}
	return json.Marshal(t.Time.UnixMilli())
}

// UnmarshalJSON converts Unix epoch milliseconds to time.
func (t *UnixTime) UnmarshalJSON(data []byte) error {
	var millis int64
	if err := json.Unmarshal(data, &millis); err != nil {
		// Try parsing as string (backwards compatibility with ISO 8601)
		var timeStr string
		if err2 := json.Unmarshal(data, &timeStr); err2 == nil {
			parsed, err3 := time.Parse(time.RFC3339Nano, timeStr)
			if err3 == nil {
				t.Time = parsed
				return nil
			}
		}
		return err
	}
	if millis == 0 {
		t.Time = time.Time{}
	} else {
		t.Time = time.UnixMilli(millis)
	}
	return nil
}

// UnixTimePtr wraps *time.Time to marshal/unmarshal as Unix epoch milliseconds.
// Returns null for nil pointers and 0 for zero time values.
type UnixTimePtr struct {
	*time.Time
}

// MarshalJSON converts time pointer to Unix epoch milliseconds or null.
func (t UnixTimePtr) MarshalJSON() ([]byte, error) {
	if t.Time == nil || t.Time.IsZero() {
		return []byte("null"), nil
	}
	return json.Marshal(t.Time.UnixMilli())
}

// UnmarshalJSON converts Unix epoch milliseconds or null to time pointer.
func (t *UnixTimePtr) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		t.Time = nil
		return nil
	}
	var millis int64
	if err := json.Unmarshal(data, &millis); err != nil {
		// Try parsing as string (backwards compatibility with ISO 8601)
		var timeStr string
		if err2 := json.Unmarshal(data, &timeStr); err2 == nil {
			parsed, err3 := time.Parse(time.RFC3339Nano, timeStr)
			if err3 == nil {
				t.Time = &parsed
				return nil
			}
		}
		return err
	}
	if millis == 0 {
		t.Time = nil
	} else {
		ts := time.UnixMilli(millis)
		t.Time = &ts
	}
	return nil
}

// IsNil returns true if the time pointer is nil.
func (t UnixTimePtr) IsNil() bool {
	return t.Time == nil
}

// NewUnixTime creates a UnixTime from a time.Time value.
func NewUnixTime(t time.Time) UnixTime {
	return UnixTime{Time: t}
}

// NewUnixTimeNow creates a UnixTime set to the current time.
func NewUnixTimeNow() UnixTime {
	return UnixTime{Time: time.Now()}
}

// NewUnixTimePtr creates a UnixTimePtr from a *time.Time value.
func NewUnixTimePtr(t *time.Time) UnixTimePtr {
	return UnixTimePtr{Time: t}
}

// NewUnixTimePtrNow creates a UnixTimePtr set to the current time.
func NewUnixTimePtrNow() UnixTimePtr {
	now := time.Now()
	return UnixTimePtr{Time: &now}
}

// MissionStatus represents the lifecycle state of a mission.
type MissionStatus string

const (
	// MissionStatusPending indicates the mission is created but not yet started.
	MissionStatusPending MissionStatus = "pending"

	// MissionStatusRunning indicates the mission is currently executing.
	MissionStatusRunning MissionStatus = "running"

	// MissionStatusPaused indicates the mission is temporarily suspended.
	MissionStatusPaused MissionStatus = "paused"

	// MissionStatusCompleted indicates the mission has completed successfully.
	MissionStatusCompleted MissionStatus = "completed"

	// MissionStatusFailed indicates the mission execution has failed.
	MissionStatusFailed MissionStatus = "failed"

	// MissionStatusCancelled indicates the mission was cancelled during execution.
	MissionStatusCancelled MissionStatus = "cancelled"
)

// Memory continuity modes define how agent memory is shared across mission runs.
const (
	// MemoryContinuityIsolated indicates each mission run has isolated memory.
	// This is the default mode for backwards compatibility.
	MemoryContinuityIsolated = "isolated"

	// MemoryContinuityInherit indicates the mission inherits memory from previous runs.
	// Memory is read-only from previous runs.
	MemoryContinuityInherit = "inherit"

	// MemoryContinuityShared indicates the mission shares a common memory pool.
	// All runs with this mode can read and write to the shared memory.
	MemoryContinuityShared = "shared"
)

// String returns the string representation of the mission status.
func (s MissionStatus) String() string {
	return string(s)
}

// IsTerminal returns true if the status represents a terminal state
// (completed, failed, or cancelled). Terminal states cannot transition to other states.
func (s MissionStatus) IsTerminal() bool {
	switch s {
	case MissionStatusCompleted, MissionStatusFailed, MissionStatusCancelled:
		return true
	default:
		return false
	}
}

// CanTransitionTo validates whether a state transition is allowed.
// Returns true if the transition from the current status to the target status is valid.
func (s MissionStatus) CanTransitionTo(target MissionStatus) bool {
	// Terminal states cannot transition
	if s.IsTerminal() {
		return false
	}

	// Valid transitions based on mission lifecycle
	switch s {
	case MissionStatusPending:
		return target == MissionStatusRunning || target == MissionStatusCancelled
	case MissionStatusRunning:
		return target == MissionStatusPaused ||
			target == MissionStatusCompleted ||
			target == MissionStatusFailed ||
			target == MissionStatusCancelled
	case MissionStatusPaused:
		return target == MissionStatusRunning ||
			target == MissionStatusFailed ||
			target == MissionStatusCancelled
	default:
		return false
	}
}

// Mission represents a complete security testing mission.
// A mission coordinates execution against a target,
// aggregating findings and enforcing constraints throughout execution.
type Mission struct {
	// ID is the unique identifier for this mission.
	ID types.ID `json:"id"`

	// TenantID is the tenant identifier for multi-tenant isolation.
	// This field is optional for backward compatibility.
	TenantID string `json:"tenant_id,omitempty" yaml:"tenant_id,omitempty"`

	// Name is a human-readable name for the mission.
	Name string `json:"name"`

	// Description provides additional context about what this mission does.
	Description string `json:"description"`

	// Status represents the current lifecycle state of the mission.
	Status MissionStatus `json:"status"`

	// TargetID references the target being tested.
	TargetID types.ID `json:"target_id"`

	// MissionDefinitionID references the mission being executed.
	MissionDefinitionID types.ID `json:"mission_definition_id"`

	// MissionDefinitionJSON contains the mission definition in JSON/YAML format.
	// This is optional - if not provided, the mission must be loaded via MissionDefinitionID.
	MissionDefinitionJSON string `json:"mission_definition_json,omitempty"`

	// Constraints define execution boundaries for the mission.
	// Uses the canonical SDK proto type per ADR 0004.
	Constraints *missionv1.MissionConstraints `json:"constraints,omitempty"`

	// Metrics tracks mission execution statistics.
	Metrics *MissionMetrics `json:"metrics,omitempty"`

	// Progress represents the mission completion progress from 0.0 to 1.0.
	// This field is computed from Metrics and provides a normalized progress indicator.
	Progress float64 `json:"progress"`

	// FindingsCount is the number of findings discovered during mission execution.
	// This provides quick access to finding count without loading full metrics.
	FindingsCount int `json:"findings_count"`

	// AgentAssignments maps mission node IDs to assigned agent component names.
	// This tracks which agents are assigned to execute which mission nodes.
	AgentAssignments map[string]string `json:"agent_assignments,omitempty"`

	// Metadata provides generic key-value storage for mission-specific data.
	// This can be used for custom fields, tags, or integration-specific information.
	Metadata map[string]any `json:"metadata,omitempty"`

	// Checkpoint stores state for resume capability.
	Checkpoint *MissionCheckpoint `json:"checkpoint,omitempty"`

	// RunNumber is the sequential run number for missions with the same name.
	// This allows multiple runs of the same mission to be tracked.
	RunNumber int `json:"run_number"`

	// PreviousRunID links to the previous run of this mission (for run history).
	PreviousRunID *types.ID `json:"previous_run_id,omitempty"`

	// MemoryContinuity defines how agent memory is shared across mission runs.
	// Valid values: "isolated" (default), "inherit", "shared".
	// - isolated: Each mission run has isolated memory
	// - inherit: Mission inherits read-only memory from previous runs
	// - shared: Mission shares a common memory pool with other runs
	MemoryContinuity string `json:"memory_continuity,omitempty"`

	// ParentMissionID references the parent mission if this is a child mission.
	// This enables mission lineage tracking where agents can spawn sub-missions.
	// A nil value indicates this is a root mission with no parent.
	ParentMissionID *types.ID `json:"parent_mission_id,omitempty"`

	// Depth represents the depth in the mission hierarchy (0 = root mission).
	// Root missions have depth 0, their direct children have depth 1, etc.
	// This field is used to enforce maximum depth constraints and prevent
	// runaway mission spawning.
	Depth int `json:"depth"`

	// CheckpointAt is the timestamp of the last checkpoint save.
	CheckpointAt UnixTimePtr `json:"checkpoint_at,omitempty"`

	// Error contains error message if mission failed.
	Error string `json:"error,omitempty"`

	// CreatedAt is the timestamp when the mission was created.
	// Stored as Unix epoch milliseconds for RediSearch NUMERIC compatibility.
	CreatedAt UnixTime `json:"created_at"`

	// StartedAt is the timestamp when the mission started execution.
	// Stored as Unix epoch milliseconds for RediSearch NUMERIC compatibility.
	StartedAt UnixTimePtr `json:"started_at,omitempty"`

	// CompletedAt is the timestamp when the mission finished execution.
	// Stored as Unix epoch milliseconds for RediSearch NUMERIC compatibility.
	CompletedAt UnixTimePtr `json:"completed_at,omitempty"`

	// UpdatedAt is the timestamp of the last update to this mission.
	// Stored as Unix epoch milliseconds for RediSearch NUMERIC compatibility.
	UpdatedAt UnixTime `json:"updated_at"`
}

// MissionMetrics tracks mission execution statistics.
// These metrics are updated throughout execution to provide real-time progress information.
type MissionMetrics struct {
	// TotalNodes is the total number of nodes in the mission.
	TotalNodes int `json:"total_nodes"`

	// CompletedNodes is the number of nodes that have completed execution.
	CompletedNodes int `json:"completed_nodes"`

	// FailedNodes is the number of nodes that failed during execution.
	FailedNodes int `json:"failed_nodes"`

	// TotalFindings is the total number of findings discovered.
	TotalFindings int `json:"total_findings"`

	// FindingsBySeverity is a map of severity levels to finding counts.
	FindingsBySeverity map[string]int `json:"findings_by_severity"`

	// TotalTokens is the total number of LLM tokens consumed.
	TotalTokens int64 `json:"total_tokens"`

	// TotalCost is the total cost in dollars for LLM usage.
	TotalCost float64 `json:"total_cost"`

	// Duration is the total execution time.
	Duration time.Duration `json:"duration"`

	// StartedAt is when execution started.
	StartedAt time.Time `json:"started_at"`

	// LastUpdateAt is when metrics were last updated.
	LastUpdateAt time.Time `json:"last_update_at"`
}

// MissionCheckpoint stores state for resume capability.
// Checkpoints are created periodically during execution to enable
// resuming a mission after interruption.
type MissionCheckpoint struct {
	// ID is the unique identifier for this checkpoint.
	ID types.ID `json:"id"`

	// Version is the checkpoint format version for compatibility.
	Version int `json:"version"`

	// MissionState contains the DAG execution state.
	MissionState map[string]any `json:"mission_state"`

	// CompletedNodes lists nodes that have completed execution.
	CompletedNodes []string `json:"completed_nodes"`

	// PendingNodes lists nodes that are pending execution.
	PendingNodes []string `json:"pending_nodes"`

	// NodeResults stores results from completed nodes.
	NodeResults map[string]any `json:"node_results"`

	// LastNodeID is the ID of the last node that was executing.
	LastNodeID string `json:"last_node_id"`

	// CheckpointedAt is when this checkpoint was created.
	CheckpointedAt time.Time `json:"checkpointed_at"`

	// Checksum is a SHA256 hash for integrity validation.
	Checksum string `json:"checksum"`

	// MetricsSnapshot contains mission metrics at checkpoint time.
	MetricsSnapshot *MissionMetrics `json:"metrics_snapshot,omitempty"`

	// FindingIDs contains IDs of findings discovered up to this checkpoint.
	FindingIDs []types.ID `json:"finding_ids,omitempty"`
}

// MissionProgress provides real-time progress information.
// This is used for monitoring mission execution through CLI, TUI, or API.
type MissionProgress struct {
	// MissionID is the unique identifier for the mission.
	MissionID types.ID `json:"mission_id"`

	// Status is the current mission status.
	Status MissionStatus `json:"status"`

	// PercentComplete is the completion percentage (0-100).
	PercentComplete float64 `json:"percent_complete"`

	// CompletedNodes is the number of completed mission nodes.
	CompletedNodes int `json:"completed_nodes"`

	// TotalNodes is the total number of mission nodes.
	TotalNodes int `json:"total_nodes"`

	// RunningNodes lists nodes currently executing.
	RunningNodes []string `json:"running_nodes"`

	// PendingNodes lists nodes pending execution.
	PendingNodes []string `json:"pending_nodes"`

	// FindingsCount is the total number of findings discovered.
	FindingsCount int `json:"findings_count"`

	// EstimatedRemaining is the estimated time remaining (if calculable).
	EstimatedRemaining *time.Duration `json:"estimated_remaining,omitempty"`
}

// MissionResult contains the final mission outcome.
// This is returned after mission execution completes (successfully or not).
type MissionResult struct {
	// MissionID is the unique identifier for the mission.
	MissionID types.ID `json:"mission_id"`

	// Status is the final mission status.
	Status MissionStatus `json:"status"`

	// Metrics contains execution statistics.
	Metrics *MissionMetrics `json:"metrics"`

	// FindingIDs contains IDs of all findings discovered.
	// Full findings are stored in the finding store.
	FindingIDs []types.ID `json:"finding_ids"`

	// MissionResult contains the mission execution result.
	MissionResult map[string]any `json:"mission_result"`

	// Error contains error message if mission failed.
	Error string `json:"error,omitempty"`

	// CompletedAt is when the mission finished execution.
	CompletedAt time.Time `json:"completed_at"`
}

// Validate checks if the mission has all required fields.
func (m *Mission) Validate() error {
	if m.ID.IsZero() {
		return fmt.Errorf("mission ID is required")
	}
	if m.Name == "" {
		return fmt.Errorf("mission name is required")
	}
	if m.TargetID.IsZero() {
		return fmt.Errorf("target ID is required")
	}
	if m.MissionDefinitionID.IsZero() {
		return fmt.Errorf("mission ID is required")
	}
	if m.Status == "" {
		return fmt.Errorf("mission status is required")
	}

	// Validate memory continuity mode if specified
	if m.MemoryContinuity != "" {
		switch m.MemoryContinuity {
		case MemoryContinuityIsolated, MemoryContinuityInherit, MemoryContinuityShared:
			// valid
		default:
			return fmt.Errorf("invalid memory_continuity: %s (must be isolated, inherit, or shared)", m.MemoryContinuity)
		}
	}

	return nil
}

// CalculateProgress calculates the current progress percentage.
// Returns 0 if metrics are not available or total nodes is 0.
func (m *Mission) CalculateProgress() float64 {
	if m.Metrics == nil || m.Metrics.TotalNodes == 0 {
		return 0.0
	}
	return (float64(m.Metrics.CompletedNodes) / float64(m.Metrics.TotalNodes)) * 100.0
}

// GetProgress returns a MissionProgress snapshot.
func (m *Mission) GetProgress() *MissionProgress {
	progress := &MissionProgress{
		MissionID:       m.ID,
		Status:          m.Status,
		PercentComplete: m.CalculateProgress(),
		FindingsCount:   0,
	}

	if m.Metrics != nil {
		progress.CompletedNodes = m.Metrics.CompletedNodes
		progress.TotalNodes = m.Metrics.TotalNodes
		progress.FindingsCount = m.Metrics.TotalFindings
	}

	if m.Checkpoint != nil {
		progress.PendingNodes = m.Checkpoint.PendingNodes
		// Running nodes would be derived from mission state
		progress.RunningNodes = []string{}
	}

	return progress
}

// GetDuration returns the mission execution duration.
// Returns 0 if the mission hasn't started.
func (m *Mission) GetDuration() time.Duration {
	if m.StartedAt.IsNil() {
		return 0
	}

	endTime := time.Now()
	if !m.CompletedAt.IsNil() {
		endTime = *m.CompletedAt.Time
	}

	return endTime.Sub(*m.StartedAt.Time)
}

// GetMemoryContinuity returns the memory continuity mode, defaulting to isolated.
// This ensures backwards compatibility for missions created before this feature.
func (m *Mission) GetMemoryContinuity() string {
	if m.MemoryContinuity == "" {
		return MemoryContinuityIsolated
	}
	return m.MemoryContinuity
}

// WithMemoryContinuity sets the memory continuity mode and returns the mission
// for method chaining. This enables fluent API usage when building missions.
func (m *Mission) WithMemoryContinuity(mode string) *Mission {
	m.MemoryContinuity = mode
	return m
}

// WithParent sets the parent mission ID and depth for a child mission.
// The depth is automatically set to parent's depth + 1.
// This method returns the mission for method chaining.
func (m *Mission) WithParent(parentID types.ID, parentDepth int) *Mission {
	m.ParentMissionID = &parentID
	m.Depth = parentDepth + 1
	return m
}

// WithTenant sets the tenant ID for multi-tenant isolation.
// This method returns the mission for method chaining.
func (m *Mission) WithTenant(tenantID string) *Mission {
	m.TenantID = tenantID
	return m
}

// IsRootMission returns true if this mission has no parent (is a root mission).
func (m *Mission) IsRootMission() bool {
	return m.ParentMissionID == nil
}

// GetParentMissionID returns the parent mission ID if this is a child mission,
// or an empty ID if this is a root mission.
func (m *Mission) GetParentMissionID() types.ID {
	if m.ParentMissionID == nil {
		return types.ID("")
	}
	return *m.ParentMissionID
}
