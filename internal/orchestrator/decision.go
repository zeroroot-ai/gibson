package orchestrator

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/zeroroot-ai/gibson/internal/llm"
)

// DecisionAction represents the type of action the orchestrator decides to take
type DecisionAction string

const (
	// ActionExecuteAgent runs the specified mission node/agent
	ActionExecuteAgent DecisionAction = "execute_agent"

	// ActionSkipAgent skips execution of a mission node
	ActionSkipAgent DecisionAction = "skip_agent"

	// ActionModifyParams modifies parameters for a target node before execution
	ActionModifyParams DecisionAction = "modify_params"

	// ActionRetry retries execution of a failed node
	ActionRetry DecisionAction = "retry"

	// ActionSpawnAgent dynamically creates and adds a new node to the mission
	ActionSpawnAgent DecisionAction = "spawn_agent"

	// ActionComplete marks the mission as complete and stops orchestration
	ActionComplete DecisionAction = "complete"

	// ActionRequestApproval pauses mission for human approval before sensitive operations
	ActionRequestApproval DecisionAction = "request_approval"

	// ActionAbort immediately stops execution due to safety violation
	ActionAbort DecisionAction = "abort"

	// ActionEscalate formally escalates to humans or specialist agents
	ActionEscalate DecisionAction = "escalate"

	// ActionRollback reverts mission state to a previous checkpoint
	ActionRollback DecisionAction = "rollback"

	// ActionReflect pauses for self-evaluation of current strategy
	ActionReflect DecisionAction = "reflect"

	// ActionRecall queries memory for relevant prior context
	ActionRecall DecisionAction = "recall"
)

// String returns the string representation of a DecisionAction
func (d DecisionAction) String() string {
	return string(d)
}

// IsValid checks if the DecisionAction is one of the defined constants
func (d DecisionAction) IsValid() bool {
	switch d {
	case ActionExecuteAgent, ActionSkipAgent, ActionModifyParams,
		ActionRetry, ActionSpawnAgent, ActionComplete,
		ActionRequestApproval, ActionAbort, ActionEscalate,
		ActionRollback, ActionReflect, ActionRecall:
		return true
	default:
		return false
	}
}

// IsTerminal returns true if this action ends the orchestration loop
func (d DecisionAction) IsTerminal() bool {
	return d == ActionComplete || d == ActionAbort
}

// Decision represents the orchestrator's reasoning output from the LLM.
// This struct is designed to be JSON serializable for structured output.
type Decision struct {
	// Reasoning is the chain-of-thought explanation of why this decision was made
	Reasoning string `json:"reasoning"`

	// Action is what the orchestrator should do
	Action DecisionAction `json:"action"`

	// TargetNodeID is which mission node to act on (if applicable)
	// Required for: execute_agent, skip_agent, modify_params, retry
	TargetNodeID string `json:"target_node_id,omitempty"`

	// Modifications are parameter overrides for the target node
	// Used with: modify_params action
	Modifications map[string]interface{} `json:"modifications,omitempty"`

	// SpawnConfig is configuration for dynamically creating new nodes
	// Required for: spawn_agent action
	SpawnConfig *SpawnNodeConfig `json:"spawn_config,omitempty"`

	// Confidence is a value between 0.0 and 1.0 indicating the orchestrator's
	// certainty in this decision
	Confidence float64 `json:"confidence"`

	// StopReason explains why the mission is complete
	// Required for: complete action
	StopReason string `json:"stop_reason,omitempty"`

	// ApprovalContext describes what needs approval
	// Required for: request_approval action
	ApprovalContext string `json:"approval_context,omitempty"`

	// ApprovalTimeout is the duration string for approval timeout (e.g., "24h", "1h30m")
	// Used with: request_approval action
	ApprovalTimeout string `json:"approval_timeout,omitempty"`

	// TimeoutAction specifies what happens on approval timeout: "reject" or "skip"
	// Used with: request_approval action
	TimeoutAction string `json:"timeout_action,omitempty"`

	// AbortReason explains why the mission is being aborted
	// Required for: abort action
	AbortReason string `json:"abort_reason,omitempty"`

	// AbortSeverity indicates the severity level: "critical", "high", or "medium"
	// Required for: abort action
	AbortSeverity string `json:"abort_severity,omitempty"`

	// CleanupRequired indicates if cleanup is needed after abort
	// Used with: abort action
	CleanupRequired bool `json:"cleanup_required,omitempty"`

	// EscalationLevel specifies the escalation target: "human", "senior_agent", or "specialist"
	// Required for: escalate action
	EscalationLevel string `json:"escalation_level,omitempty"`

	// EscalationUrgency indicates urgency: "critical", "high", or "normal"
	// Required for: escalate action
	EscalationUrgency string `json:"escalation_urgency,omitempty"`

	// EscalationContext provides context for the escalation
	// Required for: escalate action
	EscalationContext string `json:"escalation_context,omitempty"`

	// CheckpointID is the ID of an explicit checkpoint to restore
	// Used with: rollback action (either this or RollbackToNode required)
	CheckpointID string `json:"checkpoint_id,omitempty"`

	// RollbackToNode specifies a node to rollback to (reverts to before this node executed)
	// Used with: rollback action (either this or CheckpointID required)
	RollbackToNode string `json:"rollback_to_node,omitempty"`

	// ReflectionScope specifies the scope: "mission", "recent_decisions", or "specific_node"
	// Required for: reflect action
	ReflectionScope string `json:"reflection_scope,omitempty"`

	// ReflectionPrompt provides guidance for the reflection
	// Used with: reflect action
	ReflectionPrompt string `json:"reflection_prompt,omitempty"`

	// RecallQuery is the query string for memory search
	// Required for: recall action
	RecallQuery string `json:"recall_query,omitempty"`

	// RecallMemoryTier specifies which tier to query: "mission", "long_term", or "both"
	// Required for: recall action
	RecallMemoryTier string `json:"recall_memory_tier,omitempty"`

	// RecallFilters provides additional filters for memory search (e.g., target_ip, time_range)
	// Used with: recall action
	RecallFilters map[string]string `json:"recall_filters,omitempty"`

	// InjectIntoContext indicates if recalled information should persist in subsequent observations
	// Used with: recall action
	InjectIntoContext bool `json:"inject_into_context,omitempty"`
}

// SpawnNodeConfig contains configuration for dynamically spawning a new mission node
type SpawnNodeConfig struct {
	// AgentName is the type of agent to spawn (must exist in registry)
	AgentName string `json:"agent_name"`

	// Description explains the purpose of this dynamically spawned node
	Description string `json:"description"`

	// TaskConfig contains parameters specific to this spawned agent
	TaskConfig map[string]interface{} `json:"task_config"`

	// DependsOn lists node IDs that must complete before this spawned node can run
	DependsOn []string `json:"depends_on"`
}

// Validate checks if the Decision is properly formed and all required fields
// are present for the specified action
func (d *Decision) Validate() error {
	if d == nil {
		return fmt.Errorf("decision is nil")
	}

	// Check reasoning is present
	if strings.TrimSpace(d.Reasoning) == "" {
		return fmt.Errorf("reasoning is required")
	}

	// Validate action is known
	if !d.Action.IsValid() {
		return fmt.Errorf("invalid action: %s", d.Action)
	}

	// Validate confidence range
	if d.Confidence < 0.0 || d.Confidence > 1.0 {
		return fmt.Errorf("confidence must be between 0.0 and 1.0, got: %f", d.Confidence)
	}

	// Action-specific validation
	switch d.Action {
	case ActionExecuteAgent, ActionSkipAgent, ActionRetry:
		if strings.TrimSpace(d.TargetNodeID) == "" {
			return fmt.Errorf("target_node_id is required for action: %s", d.Action)
		}

	case ActionModifyParams:
		if strings.TrimSpace(d.TargetNodeID) == "" {
			return fmt.Errorf("target_node_id is required for modify_params action")
		}
		if len(d.Modifications) == 0 {
			return fmt.Errorf("modifications are required for modify_params action")
		}

	case ActionSpawnAgent:
		if d.SpawnConfig == nil {
			return fmt.Errorf("spawn_config is required for spawn_agent action")
		}
		if err := d.SpawnConfig.Validate(); err != nil {
			return fmt.Errorf("invalid spawn_config: %w", err)
		}

	case ActionComplete:
		if strings.TrimSpace(d.StopReason) == "" {
			return fmt.Errorf("stop_reason is required for complete action")
		}

	case ActionRequestApproval:
		if strings.TrimSpace(d.TargetNodeID) == "" {
			return fmt.Errorf("target_node_id is required for request_approval action")
		}
		if strings.TrimSpace(d.ApprovalContext) == "" {
			return fmt.Errorf("approval_context is required for request_approval action")
		}

	case ActionAbort:
		if strings.TrimSpace(d.AbortReason) == "" {
			return fmt.Errorf("abort_reason is required for abort action")
		}
		if strings.TrimSpace(d.AbortSeverity) == "" {
			return fmt.Errorf("abort_severity is required for abort action")
		}
		// Validate abort_severity enum values
		validAbortSeverities := map[string]bool{"critical": true, "high": true, "medium": true}
		if !validAbortSeverities[d.AbortSeverity] {
			return fmt.Errorf("abort_severity must be one of: critical, high, medium; got: %s", d.AbortSeverity)
		}

	case ActionEscalate:
		if strings.TrimSpace(d.EscalationLevel) == "" {
			return fmt.Errorf("escalation_level is required for escalate action")
		}
		if strings.TrimSpace(d.EscalationUrgency) == "" {
			return fmt.Errorf("escalation_urgency is required for escalate action")
		}
		if strings.TrimSpace(d.EscalationContext) == "" {
			return fmt.Errorf("escalation_context is required for escalate action")
		}
		// Validate escalation_level enum values
		validEscalationLevels := map[string]bool{"human": true, "senior_agent": true, "specialist": true}
		if !validEscalationLevels[d.EscalationLevel] {
			return fmt.Errorf("escalation_level must be one of: human, senior_agent, specialist; got: %s", d.EscalationLevel)
		}
		// Validate escalation_urgency enum values
		validEscalationUrgencies := map[string]bool{"critical": true, "high": true, "normal": true}
		if !validEscalationUrgencies[d.EscalationUrgency] {
			return fmt.Errorf("escalation_urgency must be one of: critical, high, normal; got: %s", d.EscalationUrgency)
		}

	case ActionRollback:
		// Require at least one of checkpoint_id or rollback_to_node
		if strings.TrimSpace(d.CheckpointID) == "" && strings.TrimSpace(d.RollbackToNode) == "" {
			return fmt.Errorf("either checkpoint_id or rollback_to_node is required for rollback action")
		}

	case ActionReflect:
		if strings.TrimSpace(d.ReflectionScope) == "" {
			return fmt.Errorf("reflection_scope is required for reflect action")
		}
		// Validate reflection_scope enum values
		validReflectionScopes := map[string]bool{"mission": true, "recent_decisions": true, "specific_node": true}
		if !validReflectionScopes[d.ReflectionScope] {
			return fmt.Errorf("reflection_scope must be one of: mission, recent_decisions, specific_node; got: %s", d.ReflectionScope)
		}

	case ActionRecall:
		if strings.TrimSpace(d.RecallQuery) == "" {
			return fmt.Errorf("recall_query is required for recall action")
		}
		if strings.TrimSpace(d.RecallMemoryTier) == "" {
			return fmt.Errorf("recall_memory_tier is required for recall action")
		}
		// Validate recall_memory_tier enum values
		validRecallMemoryTiers := map[string]bool{"mission": true, "long_term": true, "both": true}
		if !validRecallMemoryTiers[d.RecallMemoryTier] {
			return fmt.Errorf("recall_memory_tier must be one of: mission, long_term, both; got: %s", d.RecallMemoryTier)
		}
	}

	return nil
}

// Validate checks if the SpawnNodeConfig is properly formed
func (s *SpawnNodeConfig) Validate() error {
	if s == nil {
		return fmt.Errorf("spawn config is nil")
	}

	if strings.TrimSpace(s.AgentName) == "" {
		return fmt.Errorf("agent_name is required")
	}

	if strings.TrimSpace(s.Description) == "" {
		return fmt.Errorf("description is required")
	}

	// TaskConfig can be empty but not nil
	if s.TaskConfig == nil {
		return fmt.Errorf("task_config cannot be nil (use empty map if no config needed)")
	}

	// DependsOn can be empty but not nil
	if s.DependsOn == nil {
		return fmt.Errorf("depends_on cannot be nil (use empty slice if no dependencies)")
	}

	return nil
}

// ParseDecision parses a JSON string (typically from LLM structured output)
// into a Decision struct and validates it.
// Supports both raw JSON and markdown-wrapped JSON (```json ... ```).
func ParseDecision(jsonStr string) (*Decision, error) {
	if strings.TrimSpace(jsonStr) == "" {
		return nil, fmt.Errorf("empty JSON string")
	}

	// Extract JSON from markdown code blocks if present
	extractedJSON, err := llm.ExtractJSON(jsonStr)
	if err != nil {
		return nil, fmt.Errorf("failed to extract JSON from response: %w", err)
	}

	var decision Decision
	if err := json.Unmarshal([]byte(extractedJSON), &decision); err != nil {
		return nil, fmt.Errorf("failed to parse decision JSON: %w", err)
	}

	if err := decision.Validate(); err != nil {
		return nil, fmt.Errorf("invalid decision: %w", err)
	}

	return &decision, nil
}

// IsTerminal returns true if this decision ends the orchestration loop
func (d *Decision) IsTerminal() bool {
	return d != nil && d.Action.IsTerminal()
}

// String returns a human-readable representation of the decision
func (d *Decision) String() string {
	if d == nil {
		return "<nil decision>"
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Decision{Action: %s", d.Action))

	if d.TargetNodeID != "" {
		sb.WriteString(fmt.Sprintf(", Target: %s", d.TargetNodeID))
	}

	if d.SpawnConfig != nil {
		sb.WriteString(fmt.Sprintf(", SpawnAgent: %s", d.SpawnConfig.AgentName))
	}

	sb.WriteString(fmt.Sprintf(", Confidence: %.2f", d.Confidence))

	if d.StopReason != "" {
		sb.WriteString(fmt.Sprintf(", Reason: %s", d.StopReason))
	}

	sb.WriteString("}")
	return sb.String()
}

// ToJSON serializes the Decision to a JSON string
func (d *Decision) ToJSON() (string, error) {
	if d == nil {
		return "", fmt.Errorf("cannot serialize nil decision")
	}

	data, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal decision: %w", err)
	}

	return string(data), nil
}
