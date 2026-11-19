// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/modelclient"
	"github.com/zeroroot-ai/gibson/internal/platform/budget"
	"github.com/zeroroot-ai/gibson/internal/platform/principal"
	"github.com/zeroroot-ai/gibson/internal/platform/providerconfig"
	"github.com/zeroroot-ai/gibson/internal/platform/ratelimit"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	"github.com/zeroroot-ai/gibson/internal/server/extauthz/modelcall"

	// As of sdk#106 the budget surface is split: customer-visible value
	// types (`BudgetExceeded` + `BudgetScope`) live in the OSS SDK at
	// `gibson.budget_status.v1`; the admin `BudgetService` lives in
	// platform-sdk at `gibson.budget.v1`. This file only attaches the
	// status-detail wire shape to a gRPC error and never references the
	// service descriptor, so it imports the OSS path only.
	budgetstatuspb "github.com/zeroroot-ai/sdk/api/gen/gibson/budget_status/v1"
	"github.com/zeroroot-ai/sdk/auth"
	"github.com/zeroroot-ai/sdk/schema"
)

// ---------------------------------------------------------------------------
// Narrow interfaces (for testability)
// ---------------------------------------------------------------------------

// execLimiterIface is the subset of ratelimit.TenantLimiter used by the
// execution handlers. Using an interface allows tests to inject a mock.
type execLimiterIface interface {
	Check(ctx context.Context, tenantID, rpcName string) error
}

// ---------------------------------------------------------------------------
// Wiring helpers (With* methods on DaemonServer)
// ---------------------------------------------------------------------------

// WithExecLimiter wires the Redis-backed tenant rate limiter so that
// ExecuteLLM enforces per-(tenant, RPC) request budgets.
// Call this immediately after NewDaemonServer and before registering the server.
// Added by spec 25-daemon-driven-provider-config task 4.
func (s *DaemonServer) WithExecLimiter(l execLimiterIface) *DaemonServer {
	s.execLimiter = l
	return s
}

// WithBudgetEnforcer wires the per-user/team/tenant LLM budget enforcer
// so ExecuteLLM checks projected-post-call usage before dispatch and
// records authoritative usage after dispatch. Pass nil to
// disable enforcement (which is also the default).
// Spec: llm-user-attribution-governance (Requirement 3).
func (s *DaemonServer) WithBudgetEnforcer(e budgetEnforcerIface) *DaemonServer {
	s.budgetEnforcer = e
	return s
}

// WithModelGateInvalidator wires the modelgate filter's cache-
// invalidation hook so Grant / Revoke RPCs invalidate cached FGA
// check results immediately. Without this the next call after a
// grant/revoke may still see the prior state for up to 30s (the
// filter's TTL).
// Spec: llm-user-attribution-governance (Requirement 4.6).
func (s *DaemonServer) WithModelGateInvalidator(inv modelGateInvalidator) *DaemonServer {
	s.modelGateInvalidator = inv
	return s
}

// WithAuditQuery wires the audit-log read backend for
// ListModelResolutionEvents. When nil the RPC returns an empty
// response rather than Unimplemented (so dashboard callers render
// "no events" cleanly on environments without dashboard Postgres).
// Spec: llm-user-attribution-governance (Requirement 4.9).
func (s *DaemonServer) WithAuditQuery(q auditQueryIface) *DaemonServer {
	s.auditQuery = q
	return s
}

// enforceBudgetCheck runs the budget Check and maps an exceedance error to a
// gRPC ResourceExhausted status carrying a gibson.budget.v1.BudgetExceeded
// detail so SDK callers can decode it via the budget detail. It returns nil
// when the call is allowed. The enforcer is required: the daemon wires it at
// start ([[0003]]).
func (s *DaemonServer) enforceBudgetCheck(ctx context.Context, estimatedTokens int64) error {
	_, err := s.budgetEnforcer.Check(ctx, estimatedTokens)
	if err == nil {
		return nil
	}
	// Map exceedance to gRPC status with a typed detail.
	detail, hasDetail := budget.DetailFromError(err)
	st := status_grpc.New(codes.ResourceExhausted, err.Error())
	if hasDetail {
		pbDetail := &budgetstatuspb.BudgetExceeded{
			Scope:             budgetScopeToProto(detail.Scope),
			Dimension:         detail.Dimension,
			CurrentUsage:      detail.CurrentUsage,
			Limit:             detail.Limit,
			PeriodResetAtUnix: detail.PeriodResetAt.Unix(),
			SubjectId:         detail.SubjectID,
		}
		if withDetails, detailErr := st.WithDetails(pbDetail); detailErr == nil {
			st = withDetails
		}
	}
	return st.Err()
}

// budgetScopeToProto maps the internal Scope string to the proto enum.
func budgetScopeToProto(s budget.Scope) budgetstatuspb.BudgetScope {
	switch s {
	case budget.ScopeUser:
		return budgetstatuspb.BudgetScope_BUDGET_SCOPE_USER
	case budget.ScopeTeam:
		return budgetstatuspb.BudgetScope_BUDGET_SCOPE_TEAM
	case budget.ScopeTenant:
		return budgetstatuspb.BudgetScope_BUDGET_SCOPE_TENANT
	}
	return budgetstatuspb.BudgetScope_BUDGET_SCOPE_UNSPECIFIED
}

// defaultMaxOutputTokens is the max_tokens floor applied when a caller omits
// it. max_tokens is REQUIRED by Anthropic and several other providers; sending
// 0 (the zero value when the request leaves it unset) makes
// the provider return an empty completion with finishReason "length", which
// surfaces to the user as a blank chat reply. The dashboard chat client does
// not set maxOutputTokens (it is optional in the AI SDK), so the daemon must
// supply a sane floor. Matches the budget pre-check reservation in
// estimateTokens.
const defaultMaxOutputTokens = 4096

// applyDefaultMaxTokens sets a sane max_tokens floor when the caller and any
// per-call cap left it at 0. Without this the provider produces an empty
// "length"-terminated completion.
func applyDefaultMaxTokens(req *execRequest) {
	if req.MaxTokens <= 0 {
		req.MaxTokens = defaultMaxOutputTokens
	}
}

// estimateTokens returns a conservative input-token + max-tokens estimate
// for an LLM call. Used by the budget pre-check. The estimate is
// intentionally conservative — over-reserving is preferable to letting
// a large call slip under the limit.
func estimateTokens(req *tenantv1.ExecuteLLMRequest) int64 {
	var est int64
	for _, m := range req.GetMessages() {
		// Rough heuristic: 1 token per 4 chars. The token recorder uses
		// the provider's authoritative count post-dispatch; this is only
		// the pre-dispatch reservation.
		est += int64(len(m.GetContent())) / 4
	}
	if req.MaxTokens != nil && req.GetMaxTokens() > 0 {
		est += int64(req.GetMaxTokens())
	} else {
		// If the caller didn't specify max_tokens the provider's default
		// applies. Reserve a pessimistic 4k completion.
		est += 4096
	}
	return est
}

// ---------------------------------------------------------------------------
// ExecuteLLM — unary RPC
// ---------------------------------------------------------------------------

// chatModels is the part of the model client that ExecuteLLM uses.
type chatModels interface {
	Respond(ctx context.Context, caller modelclient.Caller, target modelclient.Target,
		req modelclient.Request) (*modelclient.Response, error)
}

// WithModelClient wires the model client that ExecuteLLM sends its call through
// (gibson#1392). The daemon calls no provider and holds no credential for it.
func (s *DaemonServer) WithModelClient(c chatModels) *DaemonServer {
	s.chatModels = c
	return s
}

// ExecuteLLM sends one chat call to the model gateway through the provider that
// the tenant named. The provider record gives the default model. The gateway
// holds the credential, checks the access of the user and the state of the
// mission, and records the call in its trace. This handler emits no
// llm_call.observed and no token.used: the trace is the one source of both.
//
// A call with a mission id gets a task grant of that mission. Any other call
// gets a daemon call grant with the purpose chat and the user as initiator.
func (s *DaemonServer) ExecuteLLM(ctx context.Context, req *tenantv1.ExecuteLLMRequest) (*tenantv1.ExecuteLLMResponse, error) {
	// 1. Tenant from identity context (resolved from Envoy-signed headers).
	tenantID := auth.TenantStringFromContext(ctx)
	if tenantID == "" || tenantID == auth.SystemTenantString {
		return nil, status_grpc.Errorf(codes.Unauthenticated, "tenant context required")
	}

	// 2. Rate-limit check.
	if s.execLimiter != nil {
		if limitErr := s.execLimiter.Check(ctx, tenantID, "ExecuteLLM"); limitErr != nil {
			if errors.Is(limitErr, ratelimit.ErrRateLimited) {
				return nil, status_grpc.Errorf(codes.ResourceExhausted, "rate limit exceeded for ExecuteLLM: %s", limitErr.Error())
			}
		}
	}

	// 2b. Budget check — returns ResourceExhausted with a typed
	// gibson.budget.v1.BudgetExceeded detail when denied.
	// Spec: llm-user-attribution-governance Requirement 3.3, 3.4.
	if err := s.enforceBudgetCheck(ctx, estimateTokens(req)); err != nil {
		return nil, err
	}

	// 3. The provider record gives the default model. It holds no credential.
	if s.providerConfig == nil {
		return nil, status_grpc.Errorf(codes.FailedPrecondition,
			"provider credential store is not configured (security.key_provider must be set)")
	}
	if s.chatModels == nil {
		return nil, status_grpc.Errorf(codes.FailedPrecondition, "the model gateway client is not configured")
	}
	rec, err := s.providerConfig.Get(ctx, tenantID, req.GetProviderName())
	if err != nil {
		if errors.Is(err, providerconfig.ErrNotFound) {
			return nil, status_grpc.Errorf(codes.NotFound, "provider %q not found for tenant", req.GetProviderName())
		}
		s.logger.WarnContext(ctx, "failed to read the provider record", "provider", req.GetProviderName(), "tenant", tenantID)
		return nil, status_grpc.Errorf(codes.Internal, "failed to read the provider record")
	}
	model := strings.TrimSpace(req.GetModel())
	if model == "" {
		model = rec.DefaultModel
	}
	if model == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "no model: the request names none and the provider has no default model")
	}

	// 4. The request, in Open Responses items.
	cr := execRequest{Model: model, Messages: protoMessagesToLLM(req.GetMessages())}
	if req.MaxTokens != nil {
		cr.MaxTokens = int(req.GetMaxTokens())
	}
	applyDefaultMaxTokens(&cr)
	mreq, err := toGatewayRequest(req, cr)
	if err != nil {
		return nil, err
	}

	// 5. The identity of the call.
	initiator, err := callerInitiator(ctx)
	if err != nil {
		return nil, err
	}
	caller := modelclient.Caller{Tenant: tenantID, Initiator: initiator}
	if req.GetMissionId() != "" {
		caller.Mission, caller.Task, caller.Purpose = req.GetMissionId(), "chat-"+uuid.NewString(), "dashboard-chat"
	} else {
		caller.Purpose = modelcall.PurposeChat
	}
	resp, err := s.chatModels.Respond(ctx, caller,
		modelclient.Target{Tenant: tenantID, Provider: req.GetProviderName(), Model: model}, mreq)
	if err != nil {
		return nil, s.chatError(ctx, req.GetProviderName(), err)
	}
	return gatewayRespToProto(resp), nil
}

// callerInitiator returns the FGA user of the caller. A call with no identity
// or with an empty subject fails. The model access check of the gateway needs
// a real person, so the call must not go on with an empty one.
func callerInitiator(ctx context.Context) (string, error) {
	id, err := auth.IdentityFromContext(ctx)
	if err != nil || id.Subject == "" {
		return "", status_grpc.Errorf(codes.Unauthenticated, "caller identity required")
	}
	return principal.FGAUser(id), nil
}

// chatError maps an error of the gateway to a gRPC status. The text names no
// credential and no header.
func (s *DaemonServer) chatError(ctx context.Context, provider string, err error) error {
	var api *modelclient.APIError
	if errors.As(err, &api) {
		switch {
		case api.Refused():
			return status_grpc.Errorf(codes.PermissionDenied, "model_access_denied: the gateway refused the call")
		case api.NoRoute():
			return status_grpc.Errorf(codes.Unavailable, "the route of provider %q is not ready yet", provider)
		case api.Status == http.StatusTooManyRequests:
			return status_grpc.Errorf(codes.ResourceExhausted, "the provider is rate limited")
		}
	}
	s.logger.WarnContext(ctx, "LLM completion failed", "provider", provider)
	return status_grpc.Errorf(codes.Internal, "LLM completion failed")
}

// toGatewayRequest builds the Open Responses request of an ExecuteLLM call.
func toGatewayRequest(req *tenantv1.ExecuteLLMRequest, cr execRequest) (modelclient.Request, error) {
	out := modelclient.Request{MaxOutputTokens: cr.MaxTokens}
	for _, m := range cr.Messages {
		switch m.Role {
		case roleSystem:
			out.Input = append(out.Input, modelclient.SystemMessage(m.Content))
		case roleAssistant:
			if m.Content != "" {
				out.Input = append(out.Input, modelclient.AssistantMessage(m.Content))
			}
			for _, tc := range m.ToolCalls {
				out.Input = append(out.Input, modelclient.FunctionCall(tc.ID, tc.Name, tc.Arguments))
			}
		case roleTool:
			out.Input = append(out.Input, modelclient.FunctionCallOutput(m.ToolCallID, m.Content))
		default:
			out.Input = append(out.Input, modelclient.UserMessage(m.Content))
		}
	}
	if req.Temperature != nil {
		t := float64(req.GetTemperature())
		out.Temperature = &t
	}
	for _, td := range protoToolDefsToLLM(req.GetTools()) {
		params, err := json.Marshal(td.Parameters)
		if err != nil {
			return modelclient.Request{}, status_grpc.Errorf(codes.InvalidArgument, "invalid parameters of tool %q", td.Name)
		}
		out.Tools = append(out.Tools, modelclient.FunctionTool(td.Name, td.Description, params))
	}
	if rf := req.GetResponseFormat(); rf != nil && rf.GetType() == "json_schema" {
		raw := rf.GetSchemaJson()
		if raw != "" && !json.Valid([]byte(raw)) {
			return modelclient.Request{}, status_grpc.Errorf(codes.InvalidArgument, "invalid schema_json: not valid JSON")
		}
		out.Text = modelclient.JSONSchemaFormat(rf.GetName(), json.RawMessage(raw))
		out.Text.Format.Strict = rf.GetStrict()
	}
	return out, nil
}

// gatewayRespToProto converts the reply of the gateway to the proto wire type.
func gatewayRespToProto(resp *modelclient.Response) *tenantv1.ExecuteLLMResponse {
	out := &tenantv1.ExecuteLLMResponse{
		Content:      resp.OutputText(),
		FinishReason: "stop",
		Usage: &tenantv1.LLMTokenUsage{
			InputTokens:  int32(resp.Usage.InputTokens),  //nolint:gosec // a token count
			OutputTokens: int32(resp.Usage.OutputTokens), //nolint:gosec // a token count
			TotalTokens:  int32(resp.Usage.TotalTokens),  //nolint:gosec // a token count
		},
	}
	for _, c := range resp.FunctionCalls() {
		out.ToolCalls = append(out.ToolCalls, &tenantv1.LLMToolCall{Id: c.CallID, Name: c.Name, Arguments: c.Arguments})
		out.FinishReason = "tool_calls"
	}
	return out
}

// ---------------------------------------------------------------------------
// Translation helpers — proto ↔ llm types
// ---------------------------------------------------------------------------

// protoMessagesToLLM converts the repeated LLMMessageContent proto messages
// into the execMessage slice expected by the provider interfaces.
func protoMessagesToLLM(protoMsgs []*tenantv1.LLMMessageContent) []execMessage {
	if len(protoMsgs) == 0 {
		return nil
	}
	out := make([]execMessage, 0, len(protoMsgs))
	for _, pm := range protoMsgs {
		msg := execMessage{
			Role:    execRole(pm.GetRole()),
			Content: pm.GetContent(),
			Name:    pm.GetName(),
		}

		// Tool calls requested by the assistant.
		for _, tc := range pm.GetToolCalls() {
			msg.ToolCalls = append(msg.ToolCalls, execToolCall{
				ID:        tc.GetId(),
				Name:      tc.GetName(),
				Arguments: tc.GetArguments(),
			})
		}

		// Tool results (role == "tool" messages that carry ToolCallID).
		for _, tr := range pm.GetToolResults() {
			// Tool result messages are modelled as a separate message per result
			// in the llm package.  If multiple results arrive in a single proto
			// message we promote each into its own execMessage.
			resultMsg := execMessage{
				Role:       roleTool,
				Content:    tr.GetContent(),
				ToolCallID: tr.GetToolCallId(),
			}
			out = append(out, resultMsg)
		}

		// Only append the parent message if it carries role-level content
		// (content text, tool calls, or is a non-tool role).  If the proto
		// message only held tool results, the results were already appended above.
		if len(pm.GetToolResults()) == 0 {
			out = append(out, msg)
		}
	}
	return out
}

// protoToolDefsToLLM converts LLMToolDef proto messages to execToolDef.
// The ParametersJson field is expected to be a JSON-encoded object schema;
// if it is empty or invalid JSON, the tool is included with an empty schema
// (object with no properties) so the request still proceeds.
func protoToolDefsToLLM(protoTools []*tenantv1.LLMToolDef) []execToolDef {
	if len(protoTools) == 0 {
		return nil
	}
	out := make([]execToolDef, 0, len(protoTools))
	for _, pt := range protoTools {
		params := schema.JSON{Type: "object"}
		if raw := pt.GetParametersJson(); raw != "" {
			var parsed schema.JSON
			if err := json.Unmarshal([]byte(raw), &parsed); err == nil {
				params = parsed
			}
		}
		out = append(out, execToolDef{
			Name:        pt.GetName(),
			Description: pt.GetDescription(),
			Parameters:  params,
		})
	}
	return out
}
