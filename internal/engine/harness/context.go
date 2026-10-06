// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/infra/contextkeys"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/platform/principal"
)

// MissionContext represents the broader mission context for agent execution.
// It provides agents with awareness of the overall mission, current phase,
// constraints, and other mission-level metadata.
type MissionContext struct {
	ID           types.ID       `json:"id"`
	Name         string         `json:"name"`
	CurrentAgent string         `json:"current_agent"`
	Phase        string         `json:"phase"`
	Constraints  []string       `json:"constraints"`
	Metadata     map[string]any `json:"metadata,omitempty"`
	// MissionRunID is the unique identifier for this specific mission execution.
	// Assigned when the mission run starts.
	// Used for mission-scoped GraphRAG storage.
	MissionRunID string `json:"mission_run_id,omitempty"`
	// AgentRunID is the unique identifier for this specific agent execution.
	// Used for DISCOVERED relationships and provenance tracking.
	AgentRunID string `json:"agent_run_id,omitempty"`
	// RunNumber is the sequential run number for this mission (1, 2, 3...).
	// Used for mission memory queries and historical comparisons.
	RunNumber int `json:"run_number,omitempty"`
	// TenantID is the tenant identifier for multi-tenant isolation.
	// Used by the callback harness to prevent cross-tenant access.
	TenantID string `json:"tenant_id,omitempty"`
	// Secrets is the mission's declaration of which named tenant secrets its
	// components may be handed at dispatch (gibson#485). Names only; the daemon
	// resolves the value as itself at dispatch. Zero value hands nothing to
	// anything, which is the behaviour before missions could declare secrets.
	//
	// json:"-" on purpose. A MissionContext is serialised into places a
	// component can read, and while these are names rather than values, a name
	// is a hint about what a tenant holds and the component already receives
	// exactly the subset it is entitled to.
	Secrets MissionSecretScopes `json:"-"`
	// DelegationDepth tracks how many delegation hops have occurred to reach
	// this agent. Zero means this is a top-level agent (no delegation). Each
	// DelegateToAgent call increments this by one in the child mission context.
	// Capped at maxDelegationDepth in the harness to prevent runaway chains.
	DelegationDepth int `json:"delegation_depth,omitempty"`
	// NodeSlotOverrides carries per-slot LLM provider/model bindings declared
	// on the executing agent node (from AgentNodeConfig.llm_slots in the proto
	// mission definition). Keyed by slot name; a nil value for a given slot name
	// means no override and resolution falls through to the tenant default.
	//
	// These overrides are populated by the orchestrator's executeAgent path from
	// the stored LLM slot bindings and threaded into the harness by
	// DefaultHarnessFactory.Create. They are NOT inherited by child harnesses
	// created during DelegateToAgent — child nodes carry their own bindings.
	//
	// Spec: per-node-slot-override (gibson#539).
	NodeSlotOverrides map[string]*agent.SlotConfig `json:"node_slot_overrides,omitempty"`

	// BlockedTools is the mission-level deny list (MissionConstraints.blocked_tools)
	// of tool ids that must not be invoked during this mission. Entries are matched
	// against the canonical tool id (mcp:<connector>:<tool> / native:<tool>) and the
	// raw tool name. The daemon enforces this at CallToolProto — including the
	// invoke_tool meta-tool — so it fails closed regardless of the agent. Because it
	// is mission-level it is inherited unchanged by delegated child harnesses.
	BlockedTools []string `json:"blocked_tools,omitempty"`

	// NodeNetwork is the network scope of the mission node that this harness
	// serves (gibson#865). Each tool sandbox that the node starts gets it.
	// Nil keeps the egress of the catalog manifest.
	NodeNetwork *agent.NodeNetwork `json:"-"`

	// CreatedBy is the principal that created the mission (hosted#205). When
	// it is a person, the harness factory puts that person on the context of
	// every slot resolution of the run as the mission initiator, so the model
	// gate decides for the person who asked for the run (hosted#358). A
	// delegated child harness copies it with the rest of the MissionContext.
	CreatedBy principal.Principal `json:"created_by,omitempty"`
}

// NewMissionContext creates a new mission context with the given ID, name, and current agent.
// Phase, constraints, and metadata are initialized to empty/default values.
func NewMissionContext(id types.ID, name, currentAgent string) MissionContext {
	return MissionContext{
		ID:           id,
		Name:         name,
		CurrentAgent: currentAgent,
		Phase:        "",
		Constraints:  []string{},
		Metadata:     make(map[string]any),
	}
}

// WithPhase sets the mission phase
func (m MissionContext) WithPhase(phase string) MissionContext {
	m.Phase = phase
	return m
}

// WithConstraints sets the mission constraints
func (m MissionContext) WithConstraints(constraints ...string) MissionContext {
	m.Constraints = constraints
	return m
}

// WithMetadata sets a metadata key-value pair
func (m MissionContext) WithMetadata(key string, value any) MissionContext {
	if m.Metadata == nil {
		m.Metadata = make(map[string]any)
	}
	m.Metadata[key] = value
	return m
}

// WithMissionRunID sets the mission run ID for GraphRAG mission-scoped storage.
func (m MissionContext) WithMissionRunID(missionRunID string) MissionContext {
	m.MissionRunID = missionRunID
	return m
}

// WithRunNumber sets the sequential run number for this mission.
func (m MissionContext) WithRunNumber(runNumber int) MissionContext {
	m.RunNumber = runNumber
	return m
}

// WithCreatedBy sets the principal that created the mission.
func (m MissionContext) WithCreatedBy(p principal.Principal) MissionContext {
	m.CreatedBy = p
	return m
}

// WithTenant sets the tenant ID for cross-tenant access prevention.
func (m MissionContext) WithTenant(tenantID string) MissionContext {
	m.TenantID = tenantID
	return m
}

// WithSecrets sets the mission's declaration of which named tenant secrets its
// components may be handed at dispatch (gibson#485).
//
// Mission-level, so a delegated child inherits it unchanged — a child
// MissionContext is a value copy. A child that could declare its own would be a
// component naming a secret, which is the property this design does not have.
func (m MissionContext) WithSecrets(s MissionSecretScopes) MissionContext {
	m.Secrets = s
	return m
}

// WithDelegationDepth sets the delegation depth for sub-agent execution tracking.
func (m MissionContext) WithDelegationDepth(depth int) MissionContext {
	m.DelegationDepth = depth
	return m
}

// WithBlockedTools sets the mission-level tool deny list. The slice is stored as
// given; matching is case-insensitive and applied at invocation time.
func (m MissionContext) WithBlockedTools(blocked []string) MissionContext {
	m.BlockedTools = blocked
	return m
}

// WithNodeSlotOverrides sets the per-slot LLM provider/model overrides for the
// executing agent node. The map is keyed by slot name; a nil pointer value for a
// given slot means no override (fall through to tenant default). An empty map
// (or nil) means no per-node overrides at all — identical to the pre-#539 behavior.
//
// Callers should pass only slots with a non-empty provider to avoid shadowing the
// tenant default unnecessarily; the factory's Create path already applies this filter.
//
// Spec: per-node-slot-override (gibson#539).
func (m MissionContext) WithNodeSlotOverrides(overrides map[string]*agent.SlotConfig) MissionContext {
	m.NodeSlotOverrides = overrides
	return m
}

// TargetInfo represents information about a target system or service.
// It provides agents with the necessary details to interact with targets
// including authentication headers and provider-specific metadata.
type TargetInfo struct {
	ID         types.ID       `json:"id"`
	Name       string         `json:"name"`
	Type       string         `json:"type"`
	Provider   string         `json:"provider,omitempty"`
	Connection map[string]any `json:"connection,omitempty"` // Schema-based connection parameters
	Metadata   map[string]any `json:"metadata,omitempty"`
}

// NewTargetInfo creates a new target info with the given ID, name, URL, and
// type. A non-empty URL is stored as Connection["url"], the one place that
// holds the address of a target. For targets with more connection
// parameters, use NewTargetInfoFull instead.
func NewTargetInfo(id types.ID, name, url, targetType string) TargetInfo {
	return NewTargetInfoFull(id, name, url, targetType, nil)
}

// NewTargetInfoFull creates a new target info with full connection parameters.
// This constructor should be used when creating TargetInfo from a Target entity
// that has schema-based connection configuration. A non-empty URL is stored
// as Connection["url"] when the connection does not already name one.
func NewTargetInfoFull(id types.ID, name, url, targetType string, connection map[string]any) TargetInfo {
	conn := make(map[string]any, len(connection)+1)
	for k, v := range connection {
		conn[k] = v
	}
	if _, has := conn["url"]; !has && url != "" {
		conn["url"] = url
	}
	return TargetInfo{
		ID:         id,
		Name:       name,
		Type:       targetType,
		Provider:   "",
		Connection: conn,
		Metadata:   make(map[string]any),
	}
}

// URL returns the address of the target, from Connection["url"]. It returns
// "" when the connection names no URL.
func (t TargetInfo) URL() string {
	if u, ok := t.Connection["url"].(string); ok {
		return u
	}
	return ""
}

// GetConnection returns the connection parameters for this target.
// Returns nil if no connection parameters are set.
func (t TargetInfo) GetConnection() map[string]any {
	return t.Connection
}

// WithProvider sets the provider for this target
func (t TargetInfo) WithProvider(provider string) TargetInfo {
	t.Provider = provider
	return t
}

// WithMetadata sets a metadata key-value pair
func (t TargetInfo) WithMetadata(key string, value any) TargetInfo {
	if t.Metadata == nil {
		t.Metadata = make(map[string]any)
	}
	t.Metadata[key] = value
	return t
}

// ContextWithAgentRunID returns a new context with the agent run ID set.
// The agent run ID format should be: agent_run:{trace_id}:{span_id}
func ContextWithAgentRunID(ctx context.Context, agentRunID string) context.Context {
	return contextkeys.WithAgentRunID(ctx, agentRunID)
}

// AgentRunIDFromContext retrieves the agent run ID from context.
// Returns empty string if not set.
func AgentRunIDFromContext(ctx context.Context) string {
	return contextkeys.GetAgentRunID(ctx)
}

// ContextWithToolExecutionID returns a new context with the tool execution ID set.
// The tool execution ID format should be: tool_execution:{trace_id}:{span_id}:{timestamp}
func ContextWithToolExecutionID(ctx context.Context, toolExecutionID string) context.Context {
	return contextkeys.WithToolExecutionID(ctx, toolExecutionID)
}

// ToolExecutionIDFromContext retrieves the tool execution ID from context.
// Returns empty string if not set.
func ToolExecutionIDFromContext(ctx context.Context) string {
	return contextkeys.GetToolExecutionID(ctx)
}

// MissionRunIDFromContext retrieves the mission run ID from context.
// Returns empty string if not set.
func MissionRunIDFromContext(ctx context.Context) string {
	return contextkeys.GetMissionRunID(ctx)
}
