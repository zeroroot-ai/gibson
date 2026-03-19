package mission

import (
	"math"
	"time"

	"github.com/zero-day-ai/gibson/internal/agent"
	"github.com/zero-day-ai/gibson/internal/types"
)

// NodeType defines the type of mission node
type NodeType string

const (
	NodeTypeAgent     NodeType = "agent"
	NodeTypeTool      NodeType = "tool"
	NodeTypePlugin    NodeType = "plugin"
	NodeTypeCondition NodeType = "condition"
	NodeTypeParallel  NodeType = "parallel"
	NodeTypeJoin      NodeType = "join"
)

// BackoffStrategy defines the strategy for calculating retry delays
type BackoffStrategy string

const (
	// BackoffConstant returns a constant delay for all retry attempts
	BackoffConstant BackoffStrategy = "constant"
	// BackoffLinear increases the delay linearly with each retry attempt
	BackoffLinear BackoffStrategy = "linear"
	// BackoffExponential increases the delay exponentially with each retry attempt
	BackoffExponential BackoffStrategy = "exponential"
)

// MissionDefinition represents a mission template/definition loaded from YAML.
// This is the installable, shareable mission specification that can be stored
// in git repositories and managed through the mission install/uninstall commands.
type MissionDefinition struct {
	// ID is the unique identifier for this mission definition.
	ID types.ID `json:"id" yaml:"id,omitempty"`

	// Name is a human-readable name for the mission.
	Name string `json:"name" yaml:"name"`

	// Description provides additional context about what this mission does.
	Description string `json:"description" yaml:"description,omitempty"`

	// Version is the semantic version of the mission definition.
	Version string `json:"version" yaml:"version,omitempty"`

	// TargetRef is a reference to the target (name or ID) from the YAML.
	// This needs to be resolved to a TargetID when creating a mission instance.
	TargetRef string `json:"target_ref,omitempty" yaml:"target,omitempty"`

	// Nodes contains all the nodes in the mission, indexed by node ID.
	Nodes map[string]*MissionNode `json:"nodes" yaml:"nodes"`

	// Edges contains all the directed edges connecting nodes in the mission.
	Edges []MissionEdge `json:"edges" yaml:"edges,omitempty"`

	// EntryPoints contains the IDs of nodes that can serve as entry points to the mission.
	// These are nodes with no incoming edges.
	EntryPoints []string `json:"entry_points,omitempty" yaml:"entry_points,omitempty"`

	// ExitPoints contains the IDs of nodes that can serve as exit points from the mission.
	// These are nodes with no outgoing edges.
	ExitPoints []string `json:"exit_points,omitempty" yaml:"exit_points,omitempty"`

	// Metadata contains additional custom metadata for the mission.
	Metadata map[string]any `json:"metadata,omitempty" yaml:"metadata,omitempty"`

	// Dependencies specifies required agents and tools for this mission.
	// These will be auto-installed when the mission is installed.
	Dependencies *MissionDependencies `json:"dependencies,omitempty" yaml:"dependencies,omitempty"`

	// Workspace contains configuration for Git repository cloning and workspace management.
	// Agents can access cloned repositories through the harness interface.
	Workspace *WorkspaceConfig `json:"workspace,omitempty" yaml:"workspace,omitempty"`

	// Source is the git URL this mission was installed from (if applicable).
	Source string `json:"source,omitempty" yaml:"source,omitempty"`

	// InstalledAt is the timestamp when this mission was installed.
	InstalledAt time.Time `json:"installed_at,omitempty" yaml:"installed_at,omitempty"`

	// CreatedAt is the timestamp when the mission definition was created.
	CreatedAt time.Time `json:"created_at" yaml:"created_at,omitempty"`
}

// MissionDependencies specifies required components for a mission
type MissionDependencies struct {
	// Agents lists required agent components by name or URL
	Agents []string `json:"agents,omitempty" yaml:"agents,omitempty"`

	// Tools lists required tool components by name or URL
	Tools []string `json:"tools,omitempty" yaml:"tools,omitempty"`

	// Plugins lists required plugin components by name or URL
	Plugins []string `json:"plugins,omitempty" yaml:"plugins,omitempty"`
}

// GetNode retrieves a node by its ID from the mission definition.
// Returns nil if the node is not found.
func (m *MissionDefinition) GetNode(id string) *MissionNode {
	if m.Nodes == nil {
		return nil
	}
	return m.Nodes[id]
}

// GetEntryNodes returns all nodes that are designated as entry points.
// Returns an empty slice if there are no entry points or if nodes cannot be found.
func (m *MissionDefinition) GetEntryNodes() []*MissionNode {
	if m.EntryPoints == nil || m.Nodes == nil {
		return []*MissionNode{}
	}

	nodes := make([]*MissionNode, 0, len(m.EntryPoints))
	for _, id := range m.EntryPoints {
		if node := m.Nodes[id]; node != nil {
			nodes = append(nodes, node)
		}
	}
	return nodes
}

// GetExitNodes returns all nodes that are designated as exit points.
// Returns an empty slice if there are no exit points or if nodes cannot be found.
func (m *MissionDefinition) GetExitNodes() []*MissionNode {
	if m.ExitPoints == nil || m.Nodes == nil {
		return []*MissionNode{}
	}

	nodes := make([]*MissionNode, 0, len(m.ExitPoints))
	for _, id := range m.ExitPoints {
		if node := m.Nodes[id]; node != nil {
			nodes = append(nodes, node)
		}
	}
	return nodes
}

// MissionNode represents a single node in a mission DAG
type MissionNode struct {
	// Core identity fields
	ID          string   `json:"id" yaml:"id"`
	Type        NodeType `json:"type" yaml:"type"`
	Name        string   `json:"name" yaml:"name,omitempty"`
	Description string   `json:"description" yaml:"description,omitempty"`

	// Agent node fields
	AgentName string      `json:"agent_name,omitempty" yaml:"agent_name,omitempty"`
	AgentTask *agent.Task `json:"agent_task,omitempty" yaml:"agent_task,omitempty"`

	// Tool node fields
	ToolName  string         `json:"tool_name,omitempty" yaml:"tool_name,omitempty"`
	ToolInput map[string]any `json:"tool_input,omitempty" yaml:"tool_input,omitempty"`

	// Plugin node fields
	PluginName   string         `json:"plugin_name,omitempty" yaml:"plugin_name,omitempty"`
	PluginMethod string         `json:"plugin_method,omitempty" yaml:"plugin_method,omitempty"`
	PluginParams map[string]any `json:"plugin_params,omitempty" yaml:"plugin_params,omitempty"`

	// Condition node fields
	Condition *NodeCondition `json:"condition,omitempty" yaml:"condition,omitempty"`

	// Parallel node fields
	SubNodes []*MissionNode `json:"sub_nodes,omitempty" yaml:"sub_nodes,omitempty"`

	// Execution control fields
	Dependencies []string      `json:"dependencies,omitempty" yaml:"dependencies,omitempty"`
	Timeout      time.Duration `json:"timeout,omitempty" yaml:"timeout,omitempty"`
	RetryPolicy  *RetryPolicy  `json:"retry_policy,omitempty" yaml:"retry_policy,omitempty"`
	DataPolicy   *DataPolicy   `json:"data_policy,omitempty" yaml:"data_policy,omitempty"`

	// Additional metadata
	Metadata map[string]any `json:"metadata,omitempty" yaml:"metadata,omitempty"`
}

// NodeCondition defines conditional branching logic for condition nodes
type NodeCondition struct {
	// Expression to evaluate (e.g., "result.status == 'success'")
	Expression string `json:"expression" yaml:"expression"`

	// Node IDs to execute if condition is true
	TrueBranch []string `json:"true_branch,omitempty" yaml:"true_branch,omitempty"`

	// Node IDs to execute if condition is false
	FalseBranch []string `json:"false_branch,omitempty" yaml:"false_branch,omitempty"`
}

// RetryPolicy defines the retry behavior for a mission node
type RetryPolicy struct {
	// MaxRetries is the maximum number of retry attempts
	MaxRetries int `json:"max_retries" yaml:"max_retries"`

	// BackoffStrategy determines how delays are calculated between retries
	BackoffStrategy BackoffStrategy `json:"backoff_strategy" yaml:"backoff_strategy"`

	// InitialDelay is the delay before the first retry attempt
	InitialDelay time.Duration `json:"initial_delay" yaml:"initial_delay"`

	// MaxDelay is the maximum delay between retry attempts (used for exponential backoff)
	MaxDelay time.Duration `json:"max_delay,omitempty" yaml:"max_delay,omitempty"`

	// Multiplier is the factor by which the delay increases (used for exponential backoff)
	Multiplier float64 `json:"multiplier,omitempty" yaml:"multiplier,omitempty"`
}

// CalculateDelay calculates the delay duration for a given retry attempt
// based on the configured backoff strategy
func (rp *RetryPolicy) CalculateDelay(attempt int) time.Duration {
	switch rp.BackoffStrategy {
	case BackoffConstant:
		return rp.InitialDelay
	case BackoffLinear:
		return rp.InitialDelay + (rp.InitialDelay * time.Duration(attempt))
	case BackoffExponential:
		delay := time.Duration(float64(rp.InitialDelay) * math.Pow(rp.Multiplier, float64(attempt)))
		if delay > rp.MaxDelay {
			return rp.MaxDelay
		}
		return delay
	default:
		return rp.InitialDelay
	}
}

// MissionEdge represents a directed edge in the mission DAG
type MissionEdge struct {
	// From is the source node ID
	From string `json:"from" yaml:"from"`

	// To is the destination node ID
	To string `json:"to" yaml:"to"`

	// Condition is an optional condition that must be satisfied for the edge to be traversed
	Condition string `json:"condition,omitempty" yaml:"condition,omitempty"`
}
