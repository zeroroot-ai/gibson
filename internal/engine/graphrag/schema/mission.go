// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package schema provides graph schema types for the Gibson orchestrator.
// These types represent nodes in the Neo4j graph that track mission execution state.
package schema

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// MissionStatus represents the execution status of a mission
type MissionStatus string

const (
	MissionStatusPending   MissionStatus = "pending"
	MissionStatusRunning   MissionStatus = "running"
	MissionStatusCompleted MissionStatus = "completed"
	MissionStatusFailed    MissionStatus = "failed"
)

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
	// TargetID is the target this node ran against, as a UUID string.
	//
	// It is the node's target and not the mission's. A fan-out mission runs one
	// instance per target, so the mission's own target cannot answer "which
	// target did this node assess" — and without an answer the graph shows one
	// node for a ten-target scan and findings that cannot be split by host
	// (gibson#528).
	//
	// Empty when the node is not bound to a target, which is every node in a
	// mission authored before fan-out.
	TargetID  string    `json:"target_id,omitempty"`
	CreatedAt time.Time `json:"created_at"` // When node was created
	UpdatedAt time.Time `json:"updated_at"` // When node was last updated
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

// MarkDynamic marks the node as dynamically spawned.
func (n *MissionNode) MarkDynamic(spawnedBy string) *MissionNode {
	n.IsDynamic = true
	n.SpawnedBy = spawnedBy
	n.UpdatedAt = time.Now()
	return n
}

// WithTargetID records the target this node ran against. A fan-out instance uses
// it so the graph can answer "what did we learn about target X" without guessing
// (gibson#528).
func (n *MissionNode) WithTargetID(targetID string) *MissionNode {
	n.TargetID = targetID
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
