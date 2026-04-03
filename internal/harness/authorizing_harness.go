package harness

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/casbin/casbin/v2"
	"github.com/zero-day-ai/gibson/internal/agent"
	"github.com/zero-day-ai/gibson/internal/auth"
	"github.com/zero-day-ai/gibson/internal/llm"
	"github.com/zero-day-ai/gibson/internal/memory"
	"github.com/zero-day-ai/gibson/internal/types"
	sdktypes "github.com/zero-day-ai/sdk/types"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// AuthorizingHarness wraps an AgentHarness and enforces Casbin capability policies
// on every method call. If no identity is present in the context (e.g., dev mode),
// enforcement is skipped and the call is delegated directly to the inner harness.
//
// The enforcer uses a four-tuple (sub, dom, obj, act) policy model where:
//   - sub is the identity Subject (API key ID or OIDC subject)
//   - dom is the tenant ID extracted from the context
//   - obj is the resource being accessed (e.g., "llm", "tools", "graphrag")
//   - act is the action being performed (e.g., "complete", "execute", "read", "write")
//
// When Casbin denies access, the identity's own Capabilities slice is consulted as
// a fallback. This supports identities whose policies have not yet been loaded into
// Redis (e.g., legacy keys or newly created tenants) while Casbin handles
// production policy evaluation for all other cases.
type AuthorizingHarness struct {
	inner    AgentHarness
	enforcer *casbin.Enforcer
}

// NewAuthorizingHarness creates an AuthorizingHarness that wraps inner and gates
// every AgentHarness method behind a Casbin capability check.
func NewAuthorizingHarness(inner AgentHarness, enforcer *casbin.Enforcer) *AuthorizingHarness {
	return &AuthorizingHarness{
		inner:    inner,
		enforcer: enforcer,
	}
}

// enforce checks whether the identity in ctx holds the given capability.
// It first delegates to the Casbin enforcer for policy evaluation, then falls
// back to the identity's Capabilities slice if Casbin denies or errors.
//
// If no identity is present in the context, enforcement is skipped (returns nil).
// This preserves backward compatibility for unauthenticated / dev-mode callers.
func (h *AuthorizingHarness) enforce(ctx context.Context, resource, action string) error {
	identity, ok := auth.GibsonIdentityFromContext(ctx)
	if !ok {
		// No identity — dev mode or pre-auth path. Skip enforcement.
		return nil
	}

	tenant := auth.TenantFromContext(ctx)

	allowed, err := h.enforcer.Enforce(identity.Subject, tenant, resource, action)
	if err != nil {
		// Casbin internal error — fall back to capability check rather than hard-failing.
		slog.WarnContext(ctx, "authorizing_harness: casbin enforcer error, falling back to capability check",
			"subject", identity.Subject,
			"tenant", tenant,
			"resource", resource,
			"action", action,
			"error", err,
		)
	}

	if allowed {
		return nil
	}

	// Casbin denied (or errored). Check the identity's own Capabilities slice as fallback.
	// This handles legacy keys and recently-created tenants whose policies may not yet
	// be present in the Redis-backed policy store.
	cap := fmt.Sprintf("%s:%s", resource, action)
	if identity.HasCapability(cap) || identity.HasCapability("*") {
		return nil
	}

	return status.Errorf(codes.PermissionDenied, "missing capability: %s:%s", resource, action)
}

// ────────────────────────────────────────────────────────────────────────────
// LLM Access — resource "llm", action "complete"
// ────────────────────────────────────────────────────────────────────────────

func (h *AuthorizingHarness) Complete(ctx context.Context, slot string, messages []llm.Message, opts ...CompletionOption) (*llm.CompletionResponse, error) {
	if err := h.enforce(ctx, "llm", "complete"); err != nil {
		return nil, err
	}
	return h.inner.Complete(ctx, slot, messages, opts...)
}

func (h *AuthorizingHarness) CompleteWithTools(ctx context.Context, slot string, messages []llm.Message, tools []llm.ToolDef, opts ...CompletionOption) (*llm.CompletionResponse, error) {
	if err := h.enforce(ctx, "llm", "complete"); err != nil {
		return nil, err
	}
	return h.inner.CompleteWithTools(ctx, slot, messages, tools, opts...)
}

func (h *AuthorizingHarness) Stream(ctx context.Context, slot string, messages []llm.Message, opts ...CompletionOption) (<-chan llm.StreamChunk, error) {
	if err := h.enforce(ctx, "llm", "complete"); err != nil {
		return nil, err
	}
	return h.inner.Stream(ctx, slot, messages, opts...)
}

func (h *AuthorizingHarness) CompleteStructuredAny(ctx context.Context, slot string, messages []llm.Message, schemaType any, opts ...CompletionOption) (any, error) {
	if err := h.enforce(ctx, "llm", "complete"); err != nil {
		return nil, err
	}
	return h.inner.CompleteStructuredAny(ctx, slot, messages, schemaType, opts...)
}

func (h *AuthorizingHarness) CompleteStructuredAnyWithUsage(ctx context.Context, slot string, messages []llm.Message, schemaType any, opts ...CompletionOption) (*StructuredCompletionResult, error) {
	if err := h.enforce(ctx, "llm", "complete"); err != nil {
		return nil, err
	}
	return h.inner.CompleteStructuredAnyWithUsage(ctx, slot, messages, schemaType, opts...)
}

// ────────────────────────────────────────────────────────────────────────────
// Tool Execution — resource "tools", actions "execute" (write) / "read"
// ────────────────────────────────────────────────────────────────────────────

func (h *AuthorizingHarness) CallToolProto(ctx context.Context, name string, request, response proto.Message) error {
	if err := h.enforce(ctx, "tools", "execute"); err != nil {
		return err
	}
	return h.inner.CallToolProto(ctx, name, request, response)
}

// ListTools is a read operation — resource "tools", action "read".
func (h *AuthorizingHarness) ListTools() []ToolDescriptor {
	// ListTools has no context parameter; enforcement is not possible here.
	// Delegate directly — callers that need enforcement should pass context.
	// TODO: extend AgentHarness.ListTools to accept context.Context for enforcement.
	return h.inner.ListTools()
}

func (h *AuthorizingHarness) GetToolDescriptor(ctx context.Context, name string) (*ToolDescriptor, error) {
	if err := h.enforce(ctx, "tools", "read"); err != nil {
		return nil, err
	}
	return h.inner.GetToolDescriptor(ctx, name)
}

func (h *AuthorizingHarness) GetToolCapabilities(ctx context.Context, toolName string) (*sdktypes.Capabilities, error) {
	if err := h.enforce(ctx, "tools", "read"); err != nil {
		return nil, err
	}
	return h.inner.GetToolCapabilities(ctx, toolName)
}

func (h *AuthorizingHarness) GetAllToolCapabilities(ctx context.Context) (map[string]*sdktypes.Capabilities, error) {
	if err := h.enforce(ctx, "tools", "read"); err != nil {
		return nil, err
	}
	return h.inner.GetAllToolCapabilities(ctx)
}

// ────────────────────────────────────────────────────────────────────────────
// Plugin Access — resource "plugins", action "read" for listing;
//                resource "plugin:<name>", action "read" for queries
// ────────────────────────────────────────────────────────────────────────────

func (h *AuthorizingHarness) QueryPlugin(ctx context.Context, name string, method string, params map[string]any) (any, error) {
	// Use a compound resource key so per-plugin policies can be expressed:
	// e.g., "plugin:gitlab:read" grants access only to the gitlab plugin.
	resource := fmt.Sprintf("plugin:%s", name)
	if err := h.enforce(ctx, resource, "read"); err != nil {
		return nil, err
	}
	return h.inner.QueryPlugin(ctx, name, method, params)
}

// ListPlugins has no context parameter; enforcement is not possible here.
// TODO: extend AgentHarness.ListPlugins to accept context.Context for enforcement.
func (h *AuthorizingHarness) ListPlugins() []PluginDescriptor {
	return h.inner.ListPlugins()
}

// ────────────────────────────────────────────────────────────────────────────
// Sub-Agent Delegation — resource "agents", action "delegate"
// ────────────────────────────────────────────────────────────────────────────

func (h *AuthorizingHarness) DelegateToAgent(ctx context.Context, name string, task agent.Task) (agent.Result, error) {
	if err := h.enforce(ctx, "agents", "delegate"); err != nil {
		return agent.Result{}, err
	}
	return h.inner.DelegateToAgent(ctx, name, task)
}

// ListAgents has no context parameter; enforcement is not possible here.
// TODO: extend AgentHarness.ListAgents to accept context.Context for enforcement.
func (h *AuthorizingHarness) ListAgents() []AgentDescriptor {
	return h.inner.ListAgents()
}

// ────────────────────────────────────────────────────────────────────────────
// Findings Management — resource "findings", actions "write" / "read"
// ────────────────────────────────────────────────────────────────────────────

func (h *AuthorizingHarness) SubmitFinding(ctx context.Context, finding agent.Finding) error {
	if err := h.enforce(ctx, "findings", "write"); err != nil {
		return err
	}
	return h.inner.SubmitFinding(ctx, finding)
}

func (h *AuthorizingHarness) GetFindings(ctx context.Context, filter FindingFilter) ([]agent.Finding, error) {
	if err := h.enforce(ctx, "findings", "read"); err != nil {
		return nil, err
	}
	return h.inner.GetFindings(ctx, filter)
}

// ────────────────────────────────────────────────────────────────────────────
// Memory Access — no enforcement on Memory() itself; the MemoryStore interface
// has no context on individual tier accessors so enforcement would be intrusive.
// TODO: wrap the returned MemoryStore in an authorizing adapter when memory
//       enforcement is required at tier resolution time.
// ────────────────────────────────────────────────────────────────────────────

func (h *AuthorizingHarness) Memory() memory.MemoryStore {
	return h.inner.Memory()
}

// ────────────────────────────────────────────────────────────────────────────
// Context / Identity Access — pure getters, no enforcement needed
// ────────────────────────────────────────────────────────────────────────────

func (h *AuthorizingHarness) MissionID() types.ID {
	return h.inner.MissionID()
}

func (h *AuthorizingHarness) Mission() MissionContext {
	return h.inner.Mission()
}

func (h *AuthorizingHarness) MissionExecutionContext() MissionExecutionContextSDK {
	return h.inner.MissionExecutionContext()
}

func (h *AuthorizingHarness) GetMissionRunHistory(ctx context.Context) ([]MissionRunSummarySDK, error) {
	return h.inner.GetMissionRunHistory(ctx)
}

func (h *AuthorizingHarness) GetPreviousRunFindings(ctx context.Context, filter FindingFilter) ([]agent.Finding, error) {
	if err := h.enforce(ctx, "findings", "read"); err != nil {
		return nil, err
	}
	return h.inner.GetPreviousRunFindings(ctx, filter)
}

func (h *AuthorizingHarness) GetAllRunFindings(ctx context.Context, filter FindingFilter) ([]agent.Finding, error) {
	if err := h.enforce(ctx, "findings", "read"); err != nil {
		return nil, err
	}
	return h.inner.GetAllRunFindings(ctx, filter)
}

func (h *AuthorizingHarness) Target() TargetInfo {
	return h.inner.Target()
}

// ────────────────────────────────────────────────────────────────────────────
// Checkpoint — pass through; checkpointing is mission-internal state
// ────────────────────────────────────────────────────────────────────────────

func (h *AuthorizingHarness) Checkpoint() CheckpointAccess {
	return h.inner.Checkpoint()
}

// ────────────────────────────────────────────────────────────────────────────
// Observability — pure getters, no enforcement needed
// ────────────────────────────────────────────────────────────────────────────

func (h *AuthorizingHarness) Tracer() trace.Tracer {
	return h.inner.Tracer()
}

func (h *AuthorizingHarness) Logger() *slog.Logger {
	return h.inner.Logger()
}

func (h *AuthorizingHarness) Metrics() MetricsRecorder {
	return h.inner.Metrics()
}

func (h *AuthorizingHarness) TokenUsage() *llm.TokenTracker {
	return h.inner.TokenUsage()
}

// Compile-time assertion: AuthorizingHarness must implement AgentHarness.
var _ AgentHarness = (*AuthorizingHarness)(nil)
