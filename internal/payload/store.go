package payload

import (
	"context"
	"time"

	"github.com/zero-day-ai/gibson/internal/agent"
	"github.com/zero-day-ai/gibson/internal/types"
)

// PayloadStore provides database access for Payload entities
type PayloadStore interface {
	// Save inserts a new payload with version tracking
	Save(ctx context.Context, payload *Payload) error

	// Get retrieves a payload by ID
	Get(ctx context.Context, id types.ID) (*Payload, error)

	// List retrieves payloads with optional filtering
	List(ctx context.Context, filter *PayloadFilter) ([]*Payload, error)

	// Search performs full-text search on payloads using FTS5
	Search(ctx context.Context, query string, filter *PayloadFilter) ([]*Payload, error)

	// Update modifies an existing payload and increments version
	Update(ctx context.Context, payload *Payload) error

	// Delete soft-deletes a payload by disabling it
	Delete(ctx context.Context, id types.ID) error

	// GetVersionHistory retrieves all versions of a payload
	GetVersionHistory(ctx context.Context, id types.ID) ([]*PayloadVersion, error)

	// Exists checks if a payload exists by ID
	Exists(ctx context.Context, id types.ID) (bool, error)

	// ExistsByName checks if a payload exists by name
	ExistsByName(ctx context.Context, name string) (bool, error)

	// Count returns the total number of payloads matching the filter
	Count(ctx context.Context, filter *PayloadFilter) (int, error)

	// ImportBatch imports multiple payloads with validation
	ImportBatch(ctx context.Context, payloads []*Payload) (*ImportResult, error)

	// GetSummaryForTargetType returns payload summary for orchestrator context
	GetSummaryForTargetType(ctx context.Context, targetType string) (*PayloadSummary, error)

	// CreateChain creates a new payload chain
	CreateChain(ctx context.Context, chain *PayloadChain) error

	// GetChain retrieves a chain by ID
	GetChain(ctx context.Context, id types.ID) (*PayloadChain, error)

	// ListChains retrieves all chains
	ListChains(ctx context.Context) ([]*PayloadChain, error)

	// UpdateChain updates an existing chain
	UpdateChain(ctx context.Context, chain *PayloadChain) error

	// DeleteChain deletes a chain by ID
	DeleteChain(ctx context.Context, id types.ID) error
}

// PayloadVersion represents a historical version of a payload
type PayloadVersion struct {
	ID            types.ID  `json:"id"`
	PayloadID     types.ID  `json:"payload_id"`
	Version       string    `json:"version"`
	Payload       Payload   `json:"payload"`
	ChangeType    string    `json:"change_type"` // 'created', 'updated', 'disabled', 'enabled'
	ChangeSummary string    `json:"change_summary,omitempty"`
	ChangedBy     string    `json:"changed_by,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
}

// PayloadSummary provides aggregate statistics for payloads
type PayloadSummary struct {
	Total        int                           `json:"total"`
	ByCategory   map[PayloadCategory]int       `json:"by_category"`
	ByTargetType map[string]int                `json:"by_target_type"`
	BySeverity   map[agent.FindingSeverity]int `json:"by_severity"`
	EnabledCount int                           `json:"enabled_count"`
	BuiltInCount int                           `json:"built_in_count"`
}

// ImportResult contains the results of a batch import operation
type ImportResult struct {
	Total    int      `json:"total"`
	Imported int      `json:"imported"`
	Skipped  int      `json:"skipped"`
	Failed   int      `json:"failed"`
	Errors   []string `json:"errors,omitempty"`
}

// PayloadChain represents a sequence of payloads to execute in order
type PayloadChain struct {
	ID          types.ID        `json:"id" yaml:"id"`
	Name        string          `json:"name" yaml:"name"`
	Description string          `json:"description" yaml:"description"`
	Steps       []ChainStep     `json:"steps" yaml:"steps"`
	Metadata    PayloadMetadata `json:"metadata" yaml:"metadata"`
	CreatedAt   time.Time       `json:"created_at" yaml:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at" yaml:"updated_at"`
}

// ChainStep represents a single step in a payload chain
type ChainStep struct {
	ID        string         `json:"id" yaml:"id"`
	PayloadID types.ID       `json:"payload_id" yaml:"payload_id"`
	Params    map[string]any `json:"params,omitempty" yaml:"params,omitempty"`
	OnSuccess StepAction     `json:"on_success" yaml:"on_success"`
	OnFailure StepAction     `json:"on_failure" yaml:"on_failure"`
	Requires  []string       `json:"requires,omitempty" yaml:"requires,omitempty"` // step IDs
}

// StepAction defines what to do after a step completes
type StepAction string

const (
	StepActionContinue StepAction = "continue" // Continue to next step
	StepActionAbort    StepAction = "abort"    // Stop chain execution
	StepActionTryNext  StepAction = "try_next" // Try next alternative step
	StepActionSkipTo   StepAction = "skip_to"  // Skip to specific step ID
)
