// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package contextkeys provides shared context key definitions used across Gibson packages.
// This package exists to avoid circular imports between packages that need to read/write
// context values (e.g., harness and registry).
package contextkeys

import "context"

// Key is the type for all Gibson context keys.
type Key string

const (
	// AgentRunID stores the unique identifier for an agent execution.
	// Used for DISCOVERED relationships and provenance tracking in GraphRAG.
	AgentRunID Key = "gibson.agent_run_id"

	// ToolExecutionID stores the unique identifier for a tool execution.
	ToolExecutionID Key = "gibson.tool_execution_id"

	// MissionRunID stores the unique identifier for a mission run.
	// Used for mission-scoped GraphRAG storage.
	MissionRunID Key = "gibson.mission_run_id"

	// AgentName stores the current agent name for policy lookup.
	AgentName Key = "gibson.agent_name"

	// MissionID stores the mission ID (raw string, not types.ID).
	MissionID Key = "gibson.mission_id"
)

// WithAgentRunID returns a new context with the agent run ID set.
func WithAgentRunID(ctx context.Context, agentRunID string) context.Context {
	return context.WithValue(ctx, AgentRunID, agentRunID)
}

// GetAgentRunID retrieves the agent run ID from context.
// Returns empty string if not set.
func GetAgentRunID(ctx context.Context) string {
	if v := ctx.Value(AgentRunID); v != nil {
		return v.(string)
	}
	return ""
}

// WithToolExecutionID returns a new context with the tool execution ID set.
func WithToolExecutionID(ctx context.Context, toolExecutionID string) context.Context {
	return context.WithValue(ctx, ToolExecutionID, toolExecutionID)
}

// GetToolExecutionID retrieves the tool execution ID from context.
// Returns empty string if not set.
func GetToolExecutionID(ctx context.Context) string {
	if v := ctx.Value(ToolExecutionID); v != nil {
		return v.(string)
	}
	return ""
}

// WithMissionRunID returns a new context with the mission run ID set.
func WithMissionRunID(ctx context.Context, missionRunID string) context.Context {
	return context.WithValue(ctx, MissionRunID, missionRunID)
}

// GetMissionRunID retrieves the mission run ID from context.
// Returns empty string if not set.
func GetMissionRunID(ctx context.Context) string {
	if v := ctx.Value(MissionRunID); v != nil {
		return v.(string)
	}
	return ""
}

// Identity and chain propagation keys (added for audit/compliance support).
// These follow the (T, bool) accessor convention — getters return zero value + false when absent.
const (
	// TenantID stores the tenant identifier for the current request.
	TenantID Key = "gibson.tenant_id"

	// ActorID stores the authenticated subject (user or service account) initiating the request.
	ActorID Key = "gibson.actor_id"

	// APIKeyID stores the API key ID used to authenticate the request, if applicable.
	APIKeyID Key = "gibson.api_key_id"

	// ParentAgentRunID stores the run ID of the parent agent that delegated to the current agent.
	// Used to reconstruct the delegation chain without overwriting the existing caller chain.
	ParentAgentRunID Key = "gibson.parent_agent_run_id"

	// CallerChain stores the ordered list of agent run IDs in the delegation ancestry.
	// Each hop appends the delegating agent's run ID before constructing the child harness.
	CallerChain Key = "gibson.caller_chain"

	// PerCallTokenCap stores the effective per-call LLM token cap derived from
	// EffectivePerCallCap(node, constraints). When present and > 0, the daemon
	// ExecuteLLM / StreamLLM handlers clamp MaxTokens before dispatch.
	// When absent or 0, no cap from this mechanism is applied.
	//
	// The value type is int32 (matching MissionConstraints.MaxTokensPerCall).
	// Callers that have mission context set this via harness.WithPerCallCapCtx;
	// the daemon handlers read it via harness.PerCallTokenCapFromCtx.
	//
	// Spec: mission-author-experience M4 (gibson#133).
	PerCallTokenCap Key = "gibson.per_call_token_cap"
)

// WithTenantID returns a new context with the tenant ID set.
func WithTenantID(ctx context.Context, v string) context.Context {
	return context.WithValue(ctx, TenantID, v)
}

// GetTenantID retrieves the tenant ID from context.
// Returns ("", false) if not set.
func GetTenantID(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(TenantID).(string)
	return v, ok
}

// WithActorID returns a new context with the actor ID set.
func WithActorID(ctx context.Context, v string) context.Context {
	return context.WithValue(ctx, ActorID, v)
}

// GetActorID retrieves the actor ID from context.
// Returns ("", false) if not set.
func GetActorID(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(ActorID).(string)
	return v, ok
}

// WithAPIKeyID returns a new context with the API key ID set.
func WithAPIKeyID(ctx context.Context, v string) context.Context {
	return context.WithValue(ctx, APIKeyID, v)
}

// GetAPIKeyID retrieves the API key ID from context.
// Returns ("", false) if not set.
func GetAPIKeyID(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(APIKeyID).(string)
	return v, ok
}

// WithParentAgentRunID returns a new context with the parent agent run ID set.
func WithParentAgentRunID(ctx context.Context, v string) context.Context {
	return context.WithValue(ctx, ParentAgentRunID, v)
}

// GetParentAgentRunID retrieves the parent agent run ID from context.
// Returns ("", false) if not set.
func GetParentAgentRunID(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(ParentAgentRunID).(string)
	return v, ok
}

// WithCallerChain returns a new context with the caller chain set.
// The chain is an ordered slice of agent run IDs from the root to the immediate parent.
func WithCallerChain(ctx context.Context, v []string) context.Context {
	return context.WithValue(ctx, CallerChain, v)
}

// GetCallerChain retrieves the caller chain from context.
// Returns (nil, false) if not set.
func GetCallerChain(ctx context.Context) ([]string, bool) {
	v, ok := ctx.Value(CallerChain).([]string)
	return v, ok
}

// WithPerCallTokenCap returns a new context carrying cap as the effective
// per-call LLM token cap. cap == 0 means "no cap from this mechanism"
// and is a no-op (the handler ignores zero caps).
//
// Intended to be set by orchestrator / harness code that has already
// resolved EffectivePerCallCap(node, constraints) and wants to propagate
// the result into daemon RPC handlers (ExecuteLLM, StreamLLM).
//
// Spec: mission-author-experience M4 (gibson#133).
func WithPerCallTokenCap(ctx context.Context, cap int32) context.Context {
	if cap <= 0 {
		return ctx
	}
	return context.WithValue(ctx, PerCallTokenCap, cap)
}

// GetPerCallTokenCap retrieves the effective per-call token cap from context.
// Returns (0, false) when no cap has been set.
func GetPerCallTokenCap(ctx context.Context) (int32, bool) {
	v, ok := ctx.Value(PerCallTokenCap).(int32)
	return v, ok
}
