package api

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/budget"
	"github.com/zeroroot-ai/gibson/internal/contextkeys"
	"github.com/zeroroot-ai/gibson/internal/llm"
	"github.com/zeroroot-ai/gibson/internal/llm/providers"
	"github.com/zeroroot-ai/gibson/internal/providerconfig"
	"github.com/zeroroot-ai/gibson/internal/ratelimit"
	"github.com/zeroroot-ai/gibson/internal/types"
	tenantv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/tenant/v1"
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
// Factory injection seam
// ---------------------------------------------------------------------------

// providerFactoryFunc is the default factory used to construct LLM providers
// from a resolved ProviderConfig. The DaemonServer.providerFactory field
// defaults to this at construction time so tests can substitute a mock.
var providerFactoryFunc = func(cfg llm.ProviderConfig) (llm.LLMProvider, error) {
	return providers.NewProvider(cfg)
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

// WithProviderFactory replaces the default providers.NewProvider factory with
// the given function. Intended for tests that need to inject a mock provider
// without hitting real upstream LLM APIs.
// Added by spec 25-daemon-driven-provider-config task 4.
func (s *DaemonServer) WithProviderFactory(f func(cfg llm.ProviderConfig) (llm.LLMProvider, error)) *DaemonServer {
	s.providerFactory = f
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

// enforceBudgetCheck runs the budget Check if an enforcer is wired and
// maps an exceedance error to a gRPC ResourceExhausted status carrying
// a gibson.budget.v1.BudgetExceeded detail so SDK callers can decode it
// via llm.IsBudgetExceeded. Returns (nil, nil) when the call is allowed
// OR when no enforcer is configured.
func (s *DaemonServer) enforceBudgetCheck(ctx context.Context, estimatedTokens int64) error {
	if s.budgetEnforcer == nil {
		return nil
	}
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

// applyContextPerCallCap clamps req.MaxTokens to the effective per-call cap
// stored in context (if any). The cap is injected by harness / orchestrator
// code that has already resolved EffectivePerCallCap(node, constraints) for
// the executing mission node.
//
// When no cap is present in context, or when the cap is 0, req.MaxTokens is
// left unchanged. When the caller already requested fewer tokens than the cap,
// the lower value is preserved (the cap is a ceiling, not a floor).
//
// Spec: mission-author-experience M4 (gibson#133).
func applyContextPerCallCap(ctx context.Context, req *llm.CompletionRequest) {
	cap, ok := contextkeys.GetPerCallTokenCap(ctx)
	if !ok || cap <= 0 {
		return
	}
	capInt := int(cap)
	if req.MaxTokens == 0 || req.MaxTokens > capInt {
		req.MaxTokens = capInt
	}
}

// defaultMaxOutputTokens is the max_tokens floor applied when a caller omits
// it. max_tokens is REQUIRED by Anthropic and several other providers; sending
// 0 (the zero value when the request and any per-call cap leave it unset) makes
// the provider return an empty completion with finishReason "length", which
// surfaces to the user as a blank chat reply. The dashboard chat client does
// not set maxOutputTokens (it is optional in the AI SDK), so the daemon must
// supply a sane floor. Matches the budget pre-check reservation in
// estimateTokens.
const defaultMaxOutputTokens = 4096

// applyDefaultMaxTokens sets a sane max_tokens floor when the caller and any
// per-call cap left it at 0. Without this the provider produces an empty
// "length"-terminated completion.
func applyDefaultMaxTokens(req *llm.CompletionRequest) {
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

// ExecuteLLM resolves a named provider from the tenant's encrypted credential
// store, constructs an Eino-backed provider for the duration of this
// call, dispatches the completion request, and translates the response into
// proto. The decrypted credential is scoped strictly to this stack frame and
// is never logged, cached, or embedded in any response field.
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

	// 3. Resolve the named provider — decrypts credentials.
	if s.providerConfig == nil {
		return nil, status_grpc.Errorf(codes.FailedPrecondition,
			"provider credential store is not configured (security.key_provider must be set)")
	}
	dec, err := s.providerConfig.Resolve(ctx, tenantID, req.GetProviderName())
	if err != nil {
		if errors.Is(err, providerconfig.ErrNotFound) {
			return nil, status_grpc.Errorf(codes.NotFound,
				"provider %q not found for tenant", req.GetProviderName())
		}
		// Do NOT include err directly — it may contain credential material in
		// wrapped error chains from the crypto layer.
		s.logger.WarnContext(ctx, "failed to resolve provider",
			"provider", req.GetProviderName(), "tenant", tenantID)
		return nil, status_grpc.Errorf(codes.Internal, "failed to resolve provider credentials")
	}

	// 4. Translate DecryptedConfig → llm.ProviderConfig.
	// dec goes out of scope at the end of this function; credentials are not
	// stored or forwarded anywhere beyond the prov instance below.
	provCfg := decryptedConfigToLLMConfig(dec, req.GetModel())

	// 5. Construct provider.
	prov, err := s.providerFactory(provCfg)
	if err != nil {
		s.logger.WarnContext(ctx, "failed to construct provider", "type", string(dec.Type))
		return nil, status_grpc.Errorf(codes.Internal, "failed to construct LLM provider")
	}
	// dec is no longer needed after prov is built.

	// 6. Translate request messages.
	msgs := protoMessagesToLLM(req.GetMessages())
	completionReq := llm.CompletionRequest{
		Model:         provCfg.DefaultModel,
		Messages:      msgs,
		StopSequences: req.GetStop(),
	}
	if req.Temperature != nil {
		completionReq.Temperature = req.GetTemperature()
	}
	if req.MaxTokens != nil {
		completionReq.MaxTokens = int(req.GetMaxTokens())
	}
	if req.TopP != nil {
		completionReq.TopP = req.GetTopP()
	}

	// 6b. Apply per-call token cap from context (set by mission-aware callers
	// that have resolved EffectivePerCallCap for the executing node).
	// When no cap is present in context this is a no-op.
	// Spec: mission-author-experience M4 (gibson#133).
	applyContextPerCallCap(ctx, &completionReq)

	// 6c. Floor max_tokens. A request that omits max_tokens (and has no
	// per-call cap) leaves MaxTokens at 0; providers like Anthropic then
	// return an empty completion with finishReason "length" — a blank chat
	// reply. Default to a sane value so callers that don't specify a budget
	// (e.g. the dashboard chat client) still get output.
	applyDefaultMaxTokens(&completionReq)

	// 7. Dispatch: tools → CompleteWithTools, json_schema → CompleteStructured, else Complete.
	var resp *llm.CompletionResponse

	rf := req.GetResponseFormat()
	if rf != nil && rf.GetType() == "json_schema" {
		// Structured output path.
		sp, ok := prov.(llm.StructuredOutputProvider)
		if !ok {
			return nil, status_grpc.Errorf(codes.Unimplemented,
				"provider %q does not support structured output (json_schema response format)",
				req.GetProviderName())
		}
		var parsedSchema *types.JSONSchema
		if raw := rf.GetSchemaJson(); raw != "" {
			parsedSchema = &types.JSONSchema{}
			if jsonErr := json.Unmarshal([]byte(raw), parsedSchema); jsonErr != nil {
				return nil, status_grpc.Errorf(codes.InvalidArgument,
					"invalid schema_json: not valid JSON")
			}
		}
		completionReq.ResponseFormat = &types.ResponseFormat{
			Type:   types.ResponseFormatJSONSchema,
			Name:   rf.GetName(),
			Schema: parsedSchema,
			Strict: rf.GetStrict(),
		}
		resp, err = sp.CompleteStructured(ctx, completionReq)
	} else if len(req.GetTools()) > 0 {
		// Tool-calling path.
		toolDefs := protoToolDefsToLLM(req.GetTools())
		resp, err = prov.CompleteWithTools(ctx, completionReq, toolDefs)
	} else {
		resp, err = prov.Complete(ctx, completionReq)
	}

	if err != nil {
		s.logger.WarnContext(ctx, "LLM completion failed", "provider", req.GetProviderName())
		return nil, status_grpc.Errorf(codes.Internal, "LLM completion failed")
	}

	// 8. Budget record — authoritative usage post-dispatch. Runs
	// independently of the error path so only successful calls
	// increment counters. Cost accounting can be added later from the
	// provider's pricing table; for now pass 0 cents.
	// Spec: llm-user-attribution-governance Requirement 3.10.
	if s.budgetEnforcer != nil && resp != nil {
		totalTokens := int64(resp.Usage.PromptTokens) + int64(resp.Usage.CompletionTokens)
		if totalTokens > 0 {
			if recErr := s.budgetEnforcer.Record(ctx, totalTokens, 0); recErr != nil {
				s.logger.WarnContext(ctx, "budget record failed (non-blocking)",
					"error", recErr, "tenant", tenantID)
			}
		}
	}

	// 8b. World capture — fold the completed call into the per-tenant ECS brain
	// World as an LlmCall entity (gibson#755), the replacement for the Langfuse
	// trace/cost views. Best-effort + metadata-only (resolved model + token
	// counts); a fresh CallID gives each call a stable World/graph identity.
	// Scope/run linkage is left empty here (not carried on ExecuteLLM) — a
	// mission-level call until a richer request context supplies them.
	if s.llmCallSink != nil && resp != nil {
		msgs := make([]LLMMessage, 0, len(completionReq.Messages))
		for _, m := range completionReq.Messages {
			msgs = append(msgs, LLMMessage{Role: string(m.Role), Content: m.Content})
		}
		s.llmCallSink(ctx, tenantID, LLMCallRecord{
			CallID:           uuid.NewString(),
			Model:            completionReq.Model,
			PromptTokens:     resp.Usage.PromptTokens,
			CompletionTokens: resp.Usage.CompletionTokens,
			Messages:         msgs,
			Completion:       resp.Message.Content,
		})
	}

	// 9. Translate response to proto.
	return completionRespToProto(resp), nil
}

// ---------------------------------------------------------------------------
// Translation helpers — proto ↔ llm types
// ---------------------------------------------------------------------------

// decryptedConfigToLLMConfig converts a DecryptedConfig into an llm.ProviderConfig
// suitable for passing to providers.NewProvider. The modelOverride, if non-empty,
// replaces the stored default_model.
//
// SECURITY: dec.Credentials is read here and embedded into llm.ProviderConfig
// fields. The ProviderConfig is consumed by the provider constructor and should
// not be stored beyond that call.
func decryptedConfigToLLMConfig(dec *providerconfig.DecryptedConfig, modelOverride string) llm.ProviderConfig {
	model := dec.DefaultModel
	if modelOverride != "" {
		model = modelOverride
	}

	// extra collects provider-specific credentials beyond api_key / base_url.
	extra := make(map[string]string)
	for k, v := range dec.Credentials {
		switch k {
		case "api_key", "base_url":
			// handled as typed fields below
		default:
			extra[k] = v
		}
	}

	return llm.ProviderConfig{
		Type:         dec.Type,
		APIKey:       dec.Credentials["api_key"],
		BaseURL:      dec.Credentials["base_url"],
		DefaultModel: model,
		Extra:        extra,
	}
}

// protoMessagesToLLM converts the repeated LLMMessageContent proto messages
// into the llm.Message slice expected by the provider interfaces.
func protoMessagesToLLM(protoMsgs []*tenantv1.LLMMessageContent) []llm.Message {
	if len(protoMsgs) == 0 {
		return nil
	}
	out := make([]llm.Message, 0, len(protoMsgs))
	for _, pm := range protoMsgs {
		msg := llm.Message{
			Role:    llm.Role(pm.GetRole()),
			Content: pm.GetContent(),
			Name:    pm.GetName(),
		}

		// Tool calls requested by the assistant.
		for _, tc := range pm.GetToolCalls() {
			msg.ToolCalls = append(msg.ToolCalls, llm.ToolCall{
				ID:        tc.GetId(),
				Name:      tc.GetName(),
				Arguments: tc.GetArguments(),
			})
		}

		// Tool results (role == "tool" messages that carry ToolCallID).
		for _, tr := range pm.GetToolResults() {
			// Tool result messages are modelled as a separate message per result
			// in the llm package.  If multiple results arrive in a single proto
			// message we promote each into its own llm.Message.
			resultMsg := llm.Message{
				Role:       llm.RoleTool,
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

// protoToolDefsToLLM converts LLMToolDef proto messages to llm.ToolDef.
// The ParametersJson field is expected to be a JSON-encoded object schema;
// if it is empty or invalid JSON, the tool is included with an empty schema
// (object with no properties) so the request still proceeds.
func protoToolDefsToLLM(protoTools []*tenantv1.LLMToolDef) []llm.ToolDef {
	if len(protoTools) == 0 {
		return nil
	}
	out := make([]llm.ToolDef, 0, len(protoTools))
	for _, pt := range protoTools {
		params := schema.JSON{Type: "object"}
		if raw := pt.GetParametersJson(); raw != "" {
			var parsed schema.JSON
			if err := json.Unmarshal([]byte(raw), &parsed); err == nil {
				params = parsed
			}
		}
		out = append(out, llm.ToolDef{
			Name:        pt.GetName(),
			Description: pt.GetDescription(),
			Parameters:  params,
		})
	}
	return out
}

// completionRespToProto converts an llm.CompletionResponse to the proto wire type.
// Credentials must never appear in the response — this helper only operates on
// the completion result (content, tool_calls, finish_reason, usage).
func completionRespToProto(resp *llm.CompletionResponse) *tenantv1.ExecuteLLMResponse {
	if resp == nil {
		return &tenantv1.ExecuteLLMResponse{}
	}

	out := &tenantv1.ExecuteLLMResponse{
		Content:      resp.Message.Content,
		FinishReason: string(resp.FinishReason),
		Usage: &tenantv1.LLMTokenUsage{
			InputTokens:  int32(resp.Usage.PromptTokens),
			OutputTokens: int32(resp.Usage.CompletionTokens),
			TotalTokens:  int32(resp.Usage.TotalTokens),
		},
	}

	for _, tc := range resp.Message.ToolCalls {
		out.ToolCalls = append(out.ToolCalls, &tenantv1.LLMToolCall{
			Id:        tc.ID,
			Name:      tc.Name,
			Arguments: tc.Arguments,
		})
	}

	return out
}
