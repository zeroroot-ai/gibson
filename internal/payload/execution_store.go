package payload

import (
	"context"
	"time"

	"github.com/zero-day-ai/gibson/internal/types"
)

// ExecutionStore provides database access for Execution entities
type ExecutionStore interface {
	// Save inserts a new execution record
	Save(ctx context.Context, execution *Execution) error

	// Get retrieves an execution by ID
	Get(ctx context.Context, id types.ID) (*Execution, error)

	// List retrieves executions with optional filtering
	List(ctx context.Context, filter *ExecutionFilter) ([]*Execution, error)

	// GetByPayload retrieves executions for a specific payload
	GetByPayload(ctx context.Context, payloadID types.ID, limit int) ([]*Execution, error)

	// GetByMission retrieves executions for a specific mission
	GetByMission(ctx context.Context, missionID types.ID, limit int) ([]*Execution, error)

	// GetStats retrieves aggregate statistics for analytics
	GetStats(ctx context.Context, filter *ExecutionFilter) (*ExecutionStats, error)

	// Update updates an existing execution record
	Update(ctx context.Context, execution *Execution) error

	// Count returns the total number of executions matching the filter
	Count(ctx context.Context, filter *ExecutionFilter) (int, error)
}

// ExecutionFilter defines filter criteria for querying executions
type ExecutionFilter struct {
	PayloadIDs      []types.ID         `json:"payload_ids,omitempty"`
	TargetIDs       []types.ID         `json:"target_ids,omitempty"`
	AgentIDs        []types.ID         `json:"agent_ids,omitempty"`
	MissionIDs      []types.ID         `json:"mission_ids,omitempty"`
	Statuses        []ExecutionStatus  `json:"statuses,omitempty"`
	Success         *bool              `json:"success,omitempty"`
	TargetTypes     []types.TargetType `json:"target_types,omitempty"`
	TargetProviders []types.Provider   `json:"target_providers,omitempty"`
	MinConfidence   *float64           `json:"min_confidence,omitempty"`
	After           *time.Time         `json:"after,omitempty"`  // CreatedAt after this time
	Before          *time.Time         `json:"before,omitempty"` // CreatedAt before this time
	Limit           int                `json:"limit,omitempty"`
	Offset          int                `json:"offset,omitempty"`
}

// ExecutionStats contains aggregate statistics for executions
type ExecutionStats struct {
	TotalExecutions   int           `json:"total_executions"`
	SuccessfulAttacks int           `json:"successful_attacks"`
	FailedExecutions  int           `json:"failed_executions"`
	SuccessRate       float64       `json:"success_rate"`
	AverageConfidence float64       `json:"average_confidence"`
	AverageDuration   time.Duration `json:"average_duration"`
	TotalTokensUsed   int           `json:"total_tokens_used"`
	TotalCost         float64       `json:"total_cost"`
	FindingsCreated   int           `json:"findings_created"`
	UniquePayloads    int           `json:"unique_payloads"`
	UniqueTargets     int           `json:"unique_targets"`
}
