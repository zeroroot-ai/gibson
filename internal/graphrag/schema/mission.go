// Package schema provides graph schema types for the Gibson orchestrator.
// These types represent nodes in the Neo4j graph that track mission execution state.
package schema

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/zeroroot-ai/gibson/internal/types"
)

// Node label constants for Cypher queries
const (
	// LabelMission is the Neo4j label for Mission nodes
	LabelMission = "Mission"
	// LabelMissionNode is the Neo4j label for MissionNode nodes
	LabelMissionNode = "MissionNode"
)

// MissionStatus represents the execution status of a mission
type MissionStatus string

const (
	MissionStatusPending   MissionStatus = "pending"
	MissionStatusRunning   MissionStatus = "running"
	MissionStatusCompleted MissionStatus = "completed"
	MissionStatusFailed    MissionStatus = "failed"
)

// String returns the string representation of MissionStatus
func (s MissionStatus) String() string {
	return string(s)
}

// Validate checks if the MissionStatus is valid
func (s MissionStatus) Validate() error {
	switch s {
	case MissionStatusPending, MissionStatusRunning, MissionStatusCompleted, MissionStatusFailed:
		return nil
	default:
		return fmt.Errorf("invalid mission status: %s", s)
	}
}

// MissionNodeStatus represents the execution status of a mission node
type MissionNodeStatus string

const (
	MissionNodeStatusPending   MissionNodeStatus = "pending"
	MissionNodeStatusReady     MissionNodeStatus = "ready"
	MissionNodeStatusRunning   MissionNodeStatus = "running"
	MissionNodeStatusCompleted MissionNodeStatus = "completed"
	MissionNodeStatusFailed    MissionNodeStatus = "failed"
	MissionNodeStatusSkipped   MissionNodeStatus = "skipped"
)

// String returns the string representation of MissionNodeStatus
func (s MissionNodeStatus) String() string {
	return string(s)
}

// Validate checks if the MissionNodeStatus is valid
func (s MissionNodeStatus) Validate() error {
	switch s {
	case MissionNodeStatusPending, MissionNodeStatusReady, MissionNodeStatusRunning,
		MissionNodeStatusCompleted, MissionNodeStatusFailed, MissionNodeStatusSkipped:
		return nil
	default:
		return fmt.Errorf("invalid mission node status: %s", s)
	}
}

// MissionNodeType represents the type of mission node (agent or tool)
type MissionNodeType string

const (
	MissionNodeTypeAgent MissionNodeType = "agent"
	MissionNodeTypeTool  MissionNodeType = "tool"
)

// String returns the string representation of MissionNodeType
func (t MissionNodeType) String() string {
	return string(t)
}

// Validate checks if the MissionNodeType is valid
func (t MissionNodeType) Validate() error {
	switch t {
	case MissionNodeTypeAgent, MissionNodeTypeTool:
		return nil
	default:
		return fmt.Errorf("invalid mission node type: %s", t)
	}
}

// RetryPolicy defines the retry behavior for a mission node
type RetryPolicy struct {
	MaxRetries int           `json:"max_retries"`           // Maximum number of retry attempts
	Backoff    time.Duration `json:"backoff"`               // Backoff duration between retries
	Strategy   string        `json:"strategy,omitempty"`    // Retry strategy (e.g., "exponential", "linear")
	MaxBackoff time.Duration `json:"max_backoff,omitempty"` // Maximum backoff duration for exponential strategy
}

// Validate checks if the RetryPolicy is valid
func (p *RetryPolicy) Validate() error {
	if p.MaxRetries < 0 {
		return fmt.Errorf("max_retries must be non-negative, got %d", p.MaxRetries)
	}
	if p.Backoff < 0 {
		return fmt.Errorf("backoff must be non-negative, got %v", p.Backoff)
	}
	if p.MaxBackoff < 0 {
		return fmt.Errorf("max_backoff must be non-negative, got %v", p.MaxBackoff)
	}
	if p.Strategy != "" && p.Strategy != "exponential" && p.Strategy != "linear" {
		return fmt.Errorf("invalid retry strategy: %s", p.Strategy)
	}
	return nil
}

// ToJSON converts the RetryPolicy to a JSON string for storage in Neo4j
func (p *RetryPolicy) ToJSON() (string, error) {
	data, err := json.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("failed to marshal retry policy: %w", err)
	}
	return string(data), nil
}

// Mission represents a mission node in the graph.
// Missions track the overall execution state of a security testing mission.
type Mission struct {
	ID          types.ID      `json:"id"`
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Objective   string        `json:"objective"`
	TargetRef   string        `json:"target_ref"`             // Reference to target system
	Status      MissionStatus `json:"status"`                 // Current execution status
	CreatedAt   time.Time     `json:"created_at"`             // When mission was created
	StartedAt   *time.Time    `json:"started_at,omitempty"`   // When execution started
	CompletedAt *time.Time    `json:"completed_at,omitempty"` // When execution completed
	YAMLSource  string        `json:"yaml_source"`            // Original YAML for reconstruction
}

// NewMission creates a new Mission with the given parameters.
// The mission is initialized with pending status and current timestamp.
func NewMission(id types.ID, name, description, objective, targetRef, yamlSource string) *Mission {
	now := time.Now()
	return &Mission{
		ID:          id,
		Name:        name,
		Description: description,
		Objective:   objective,
		TargetRef:   targetRef,
		Status:      MissionStatusPending,
		CreatedAt:   now,
		YAMLSource:  yamlSource,
	}
}

// Validate checks that all required fields are set correctly.
// Note: target_ref is optional to support orchestration/discovery missions without specific targets.
func (m *Mission) Validate() error {
	if err := m.ID.Validate(); err != nil {
		return fmt.Errorf("invalid mission ID: %w", err)
	}
	if m.Name == "" {
		return fmt.Errorf("mission name is required")
	}
	// target_ref is optional - some missions (discovery, orchestration) don't target a specific system
	if err := m.Status.Validate(); err != nil {
		return err
	}
	if m.YAMLSource == "" {
		return fmt.Errorf("mission yaml_source is required")
	}
	return nil
}

// WithStatus sets the status and returns the mission for method chaining.
func (m *Mission) WithStatus(status MissionStatus) *Mission {
	m.Status = status
	return m
}

// WithStartedAt sets the started_at timestamp and returns the mission for method chaining.
func (m *Mission) WithStartedAt(t time.Time) *Mission {
	m.StartedAt = &t
	return m
}

// WithCompletedAt sets the completed_at timestamp and returns the mission for method chaining.
func (m *Mission) WithCompletedAt(t time.Time) *Mission {
	m.CompletedAt = &t
	return m
}

// MarkStarted sets status to running and records the start time.
func (m *Mission) MarkStarted() {
	now := time.Now()
	m.Status = MissionStatusRunning
	m.StartedAt = &now
}

// MarkCompleted sets status to completed and records the completion time.
func (m *Mission) MarkCompleted() {
	now := time.Now()
	m.Status = MissionStatusCompleted
	m.CompletedAt = &now
}

// MarkFailed sets status to failed and records the completion time.
func (m *Mission) MarkFailed() {
	now := time.Now()
	m.Status = MissionStatusFailed
	m.CompletedAt = &now
}

// MissionNode represents a task node in a mission.
// Each node represents either an agent execution or tool invocation.
type MissionNode struct {
	ID          types.ID          `json:"id"`                     // Unique within mission
	MissionID   types.ID          `json:"mission_id"`             // Parent mission ID (stable SQLite ID)
	Type        MissionNodeType   `json:"type"`                   // "agent" or "tool"
	Name        string            `json:"name"`                   // Node name/identifier
	Description string            `json:"description"`            // Human-readable description
	AgentName   string            `json:"agent_name,omitempty"`   // If type=agent
	ToolName    string            `json:"tool_name,omitempty"`    // If type=tool
	Timeout     time.Duration     `json:"timeout,omitempty"`      // Execution timeout
	RetryPolicy *RetryPolicy      `json:"retry_policy,omitempty"` // Retry configuration
	TaskConfig  map[string]any    `json:"task_config,omitempty"`  // Original task configuration
	Status      MissionNodeStatus `json:"status"`                 // Current execution status
	IsDynamic   bool              `json:"is_dynamic"`             // True if spawned at runtime
	SpawnedBy   string            `json:"spawned_by,omitempty"`   // ID of execution that spawned this
	CreatedAt   time.Time         `json:"created_at"`             // When node was created
	UpdatedAt   time.Time         `json:"updated_at"`             // When node was last updated
}

// NewMissionNode creates a new MissionNode with the given parameters.
// The node is initialized with pending status and current timestamp.
func NewMissionNode(id, missionID types.ID, nodeType MissionNodeType, name, description string) *MissionNode {
	now := time.Now()
	return &MissionNode{
		ID:          id,
		MissionID:   missionID,
		Type:        nodeType,
		Name:        name,
		Description: description,
		Status:      MissionNodeStatusPending,
		IsDynamic:   false,
		TaskConfig:  make(map[string]any),
		CreatedAt:   now,
		UpdatedAt:   now,
	}
}

// NewAgentNode creates a new MissionNode for an agent execution.
func NewAgentNode(id, missionID types.ID, name, description, agentName string) *MissionNode {
	node := NewMissionNode(id, missionID, MissionNodeTypeAgent, name, description)
	node.AgentName = agentName
	return node
}

// NewToolNode creates a new MissionNode for a tool invocation.
func NewToolNode(id, missionID types.ID, name, description, toolName string) *MissionNode {
	node := NewMissionNode(id, missionID, MissionNodeTypeTool, name, description)
	node.ToolName = toolName
	return node
}

// Validate checks that all required fields are set correctly.
func (n *MissionNode) Validate() error {
	if err := n.ID.Validate(); err != nil {
		return fmt.Errorf("invalid mission node ID: %w", err)
	}
	if err := n.MissionID.Validate(); err != nil {
		return fmt.Errorf("invalid mission ID: %w", err)
	}
	if err := n.Type.Validate(); err != nil {
		return err
	}
	if n.Name == "" {
		return fmt.Errorf("mission node name is required")
	}
	if err := n.Status.Validate(); err != nil {
		return err
	}

	// Type-specific validation
	switch n.Type {
	case MissionNodeTypeAgent:
		if n.AgentName == "" {
			return fmt.Errorf("agent_name is required for agent nodes")
		}
	case MissionNodeTypeTool:
		if n.ToolName == "" {
			return fmt.Errorf("tool_name is required for tool nodes")
		}
	}

	// Validate retry policy if present
	if n.RetryPolicy != nil {
		if err := n.RetryPolicy.Validate(); err != nil {
			return fmt.Errorf("invalid retry policy: %w", err)
		}
	}

	return nil
}

// WithStatus sets the status and updates the timestamp.
func (n *MissionNode) WithStatus(status MissionNodeStatus) *MissionNode {
	n.Status = status
	n.UpdatedAt = time.Now()
	return n
}

// WithTimeout sets the timeout duration.
func (n *MissionNode) WithTimeout(timeout time.Duration) *MissionNode {
	n.Timeout = timeout
	return n
}

// WithRetryPolicy sets the retry policy.
func (n *MissionNode) WithRetryPolicy(policy *RetryPolicy) *MissionNode {
	n.RetryPolicy = policy
	return n
}

// WithTaskConfig sets the task configuration.
func (n *MissionNode) WithTaskConfig(config map[string]any) *MissionNode {
	n.TaskConfig = config
	return n
}

// MarkDynamic marks the node as dynamically spawned.
func (n *MissionNode) MarkDynamic(spawnedBy string) *MissionNode {
	n.IsDynamic = true
	n.SpawnedBy = spawnedBy
	n.UpdatedAt = time.Now()
	return n
}

// TaskConfigJSON converts the TaskConfig to a JSON string for storage in Neo4j.
func (n *MissionNode) TaskConfigJSON() (string, error) {
	if n.TaskConfig == nil || len(n.TaskConfig) == 0 {
		return "{}", nil
	}
	data, err := json.Marshal(n.TaskConfig)
	if err != nil {
		return "", fmt.Errorf("failed to marshal task config: %w", err)
	}
	return string(data), nil
}

// RetryPolicyJSON converts the RetryPolicy to a JSON string for storage in Neo4j.
// Returns empty JSON object if no retry policy is set.
func (n *MissionNode) RetryPolicyJSON() (string, error) {
	if n.RetryPolicy == nil {
		return "{}", nil
	}
	return n.RetryPolicy.ToJSON()
}
