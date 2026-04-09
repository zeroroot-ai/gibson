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

	// CallerComponent stores the component identifier of the direct caller (e.g., "agent:gitlab-agent").
	CallerComponent Key = "gibson.caller_component"

	// CallerComponentVersion stores the version of the calling component.
	CallerComponentVersion Key = "gibson.caller_component_version"

	// AuthzDecision stores the authorization decision made by
	// AuthorizingHarness for the current harness call, so the
	// ComplianceMiddleware can read it when stamping the signal.
	// Added by audit-compliance-emitter task 11.
	AuthzDecision Key = "gibson.authz_decision"
)

// AuthzDecisionValue is the payload stored under the AuthzDecision context
// key. Carries the decision enum, matched policy id, and a human reason.
// All fields are plain strings so this package has no dependencies on the
// authz package (which would create an import cycle).
type AuthzDecisionValue struct {
	// Decision is one of "allow", "deny", "not_checked".
	Decision string

	// PolicyID is the matched policy identifier (e.g., "tools.execute").
	PolicyID string

	// Reason is a human-readable rationale. Never contains sensitive data.
	Reason string
}

// WithAuthzDecision returns a new context with the authorization decision set.
func WithAuthzDecision(ctx context.Context, v AuthzDecisionValue) context.Context {
	return context.WithValue(ctx, AuthzDecision, v)
}

// GetAuthzDecision returns the authorization decision previously stamped
// onto context, or (zero, false) if none is present.
func GetAuthzDecision(ctx context.Context) (AuthzDecisionValue, bool) {
	v, ok := ctx.Value(AuthzDecision).(AuthzDecisionValue)
	return v, ok
}

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

// WithCallerComponent returns a new context with the caller component identifier set.
func WithCallerComponent(ctx context.Context, v string) context.Context {
	return context.WithValue(ctx, CallerComponent, v)
}

// GetCallerComponent retrieves the caller component identifier from context.
// Returns ("", false) if not set.
func GetCallerComponent(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(CallerComponent).(string)
	return v, ok
}

// WithCallerComponentVersion returns a new context with the caller component version set.
func WithCallerComponentVersion(ctx context.Context, v string) context.Context {
	return context.WithValue(ctx, CallerComponentVersion, v)
}

// GetCallerComponentVersion retrieves the caller component version from context.
// Returns ("", false) if not set.
func GetCallerComponentVersion(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(CallerComponentVersion).(string)
	return v, ok
}
