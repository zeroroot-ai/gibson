// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	commonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/common/v1"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	"github.com/zeroroot-ai/sdk/schema"

	"github.com/zeroroot-ai/gibson/internal/engine/catalog"
	"github.com/zeroroot-ai/gibson/internal/engine/metatool"
	"github.com/zeroroot-ai/gibson/internal/engine/toolid"
	"github.com/zeroroot-ai/gibson/internal/platform/component"
	"github.com/zeroroot-ai/sdk/auth"
)

// metaToolsWired reports whether the connector catalog is fully wired on this
// daemon. The two meta-tools are advertised and served only when it is, so a
// daemon without the catalog behaves exactly as before.
func (s *HarnessCallbackService) metaToolsWired() bool {
	return s.componentRegistry != nil && s.componentAuthorizer != nil && s.authzStore != nil
}

// metaToolDescriptors returns the two synthetic tools (ADR-0065) that
// the harness presents to the LLM in place of the full connector surface:
// search_tools for discovery and invoke_tool for invocation by canonical id.
func metaToolDescriptors() []ToolDescriptor {
	return []ToolDescriptor{
		{
			Name: metatool.SearchToolsName,
			Description: "Search the connector tool catalog for tools relevant to a task and " +
				"return a small, authorized, ranked set of candidates. Use this to discover " +
				"which tools exist before calling invoke_tool. Returns each candidate's " +
				"canonical id, description, and input schema.",
			InputSchema: schema.Object(map[string]schema.JSON{
				"query":     schema.StringWithDesc("Free-text description of the capability you need (e.g. \"open a gitlab issue\")."),
				"sources":   schema.Array(schema.StringWithDesc("Restrict to a source: \"mcp\" or \"native\".")),
				"connector": schema.StringWithDesc("Restrict to a single connector/plugin name. Optional."),
				"limit":     schema.Int(),
			}),
		},
		{
			Name: metatool.InvokeToolName,
			Description: "Invoke a catalog tool by its canonical id (from search_tools), passing the " +
				"tool's arguments. The id has the form mcp:<connector>:<tool> or native:<tool>. Authorization is " +
				"enforced; only ids returned by search_tools are invocable.",
			InputSchema: schema.Object(map[string]schema.JSON{
				"id":   schema.StringWithDesc("Canonical tool id, e.g. mcp:gitlab:create_issue."),
				"args": schema.Any(),
			}, "id"),
		},
	}
}

// isMetaTool reports whether name is one of the reserved meta-tool names.
func isMetaTool(name string) bool {
	return name == metatool.SearchToolsName || name == metatool.InvokeToolName
}

// callMetaTool serves the two meta-tools from CallToolProto. It establishes the
// caller (user + tenant) from the run's authz state — exactly as the Authorize
// and SearchTools handlers do — builds the catalog engine + authorizer, and
// dispatches through metatool.Handler. invoke_tool re-checks can_execute there,
// because this in-process path does not pass the per-plugin ext-authz gate.
// A native:<tool> id then goes through the direct tool call handler, so it
// takes the sandbox path or the work queue path like a direct call (ADR-0065).
func (s *HarnessCallbackService) callMetaTool(ctx context.Context, req *harnesspb.CallToolProtoRequest) (*harnesspb.CallToolProtoResponse, error) {
	if !s.metaToolsWired() {
		// gibson:no-tool-executed — the catalog is not wired; nothing runs.
		return metaToolErr(commonpb.ErrorCode_ERROR_CODE_INTERNAL, "meta-tools are not wired on this daemon"), nil
	}

	h, err := s.getHarness(ctx, req.GetContext())
	if err != nil {
		return nil, err
	}

	runID := req.GetContext().GetMissionRunId()
	if runID == "" {
		runID = req.GetContext().GetAgentRunId()
	}
	if runID == "" {
		// gibson:no-tool-executed — rejected before any dispatch is attempted.
		return metaToolErr(commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, "meta-tool call requires a mission_run_id or agent_run_id"), nil
	}
	state, err := s.authzStore.Get(ctx, runID)
	if err != nil {
		s.logger.WarnContext(ctx, "meta-tool: run authz state not found", "run_id", runID, "err", err)
		// gibson:no-tool-executed — no resolvable run state, so nothing ran.
		return metaToolErr(commonpb.ErrorCode_ERROR_CODE_NOT_FOUND, "run authz state not found"), nil
	}
	policy, err := s.policyFromState(ctx, state)
	if err != nil {
		s.logger.ErrorContext(ctx, "meta-tool: the mission policy could not be loaded", "run_id", runID, "err", err)
		// gibson:no-tool-executed — no policy, so nothing ran.
		return metaToolErr(commonpb.ErrorCode_ERROR_CODE_UNAVAILABLE, "the mission policy could not be loaded"), nil
	}

	authorizer := catalog.NewFGAAuthorizer(s.componentAuthorizer)
	handler := metatool.NewHandler(
		catalog.NewEngine(component.NewCatalogToolLister(s.componentRegistry, s.connectors), authorizer),
		authorizer,
		s.connectors,
	)
	caller := catalog.Caller{Subject: "user:" + state.UserID, Tenant: state.TenantID}

	switch req.GetName() {
	case metatool.SearchToolsName:
		if err := policy.CheckRun(ctx); err != nil { //nolint:nilerr // the denial is the response, not a transport error
			// gibson:no-tool-executed — denied before the search.
			return metaToolErr(commonpb.ErrorCode_ERROR_CODE_PERMISSION_DENIED, "mission run is not active"), nil
		}
		return s.metaSearch(ctx, handler, caller, req.GetInputJson())
	case metatool.InvokeToolName:
		return s.metaInvoke(ctx, req.GetContext(), handler, h, caller, policy, req.GetInputJson())
	default:
		// gibson:no-tool-executed — not one of the two known meta-tools.
		return metaToolErr(commonpb.ErrorCode_ERROR_CODE_NOT_FOUND, "unknown meta-tool: "+req.GetName()), nil
	}
}

func (s *HarnessCallbackService) metaSearch(ctx context.Context, h *metatool.Handler, caller catalog.Caller, inputJSON []byte) (*harnesspb.CallToolProtoResponse, error) {
	var in struct {
		Query     string   `json:"query"`
		Sources   []string `json:"sources"`
		Connector string   `json:"connector"`
		Limit     int      `json:"limit"`
	}
	if len(inputJSON) > 0 {
		if err := json.Unmarshal(inputJSON, &in); err != nil {
			// gibson:no-tool-executed — malformed request, nothing dispatched.
			return metaToolErr(commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, "search_tools input is not valid JSON: "+err.Error()), nil
		}
	}

	candidates, err := h.Search(ctx, caller, catalog.Query{
		Text:      in.Query,
		Sources:   toToolSources(in.Sources),
		Connector: in.Connector,
		Limit:     in.Limit,
	})
	if err != nil {
		s.logger.ErrorContext(ctx, "meta-tool search failed", "tenant", caller.Tenant, "err", err)
		// gibson:no-tool-executed — search_tools only queries the catalog; it
		// never invokes a tool, so a search failure has nothing to record.
		return metaToolErr(commonpb.ErrorCode_ERROR_CODE_INTERNAL, "tool search failed"), nil
	}

	out := struct {
		Candidates []metaSearchCandidate `json:"candidates"`
	}{Candidates: make([]metaSearchCandidate, len(candidates))}
	for i, c := range candidates {
		out.Candidates[i] = metaSearchCandidate{
			ID:          c.ID,
			Source:      c.Source,
			Connector:   c.Connector,
			Tool:        c.Tool,
			Description: c.Description,
		}
		if len(c.InputSchema) > 0 {
			out.Candidates[i].InputSchema = json.RawMessage(c.InputSchema)
		}
	}
	// gibson:no-tool-executed — search_tools never invokes a tool; only
	// invoke_tool does, and that path records below.
	return marshalMetaResult(s, out)
}

func (s *HarnessCallbackService) metaInvoke(ctx context.Context, contextInfo *harnesspb.ContextInfo, h *metatool.Handler, harness AgentHarness, caller catalog.Caller, policy metatool.MissionPolicy, inputJSON []byte) (*harnesspb.CallToolProtoResponse, error) {
	var in struct {
		ID   string         `json:"id"`
		Args map[string]any `json:"args"`
	}
	if err := json.Unmarshal(inputJSON, &in); err != nil {
		// gibson:no-tool-executed — malformed request, nothing dispatched.
		return metaToolErr(commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, "invoke_tool input is not valid JSON: "+err.Error()), nil
	}
	if in.ID == "" {
		// gibson:no-tool-executed — no id to dispatch to.
		return metaToolErr(commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, "invoke_tool requires a non-empty id"), nil
	}

	// argsJSON is the agent's own "args" bytes, captured verbatim as evidence —
	// a second, narrower decode of the SAME already-validated inputJSON,
	// rather than a re-marshal of in.Args, so the recorded evidence is
	// exactly what the agent sent instead of a re-serialized copy.
	var rawArgs struct {
		Args json.RawMessage `json:"args"`
	}
	_ = json.Unmarshal(inputJSON, &rawArgs) // inputJSON already parsed successfully above
	argsJSON := []byte(rawArgs.Args)
	if len(argsJSON) == 0 {
		argsJSON = []byte("{}")
	}

	// The one connector call: mission policy, can_execute, the intent record,
	// the dispatch, and the flight recorder and audit records of the result.
	result, err := h.Call(ctx, metatool.Call{
		Caller:    caller,
		ID:        in.ID,
		Args:      in.Args,
		ArgsJSON:  argsJSON,
		Policy:    policy,
		MissionID: contextInfo.GetMissionId(),
		RunID:     callerRun(ctx, contextInfo),
		// Flight recorder completeness (ADR-0131): invoke_tool dispatches a
		// real catalog tool through the same trust boundary as a native
		// CallToolProto call, so each call is recorded, a failed one too.
		Recorder: func(rctx context.Context, rec metatool.CallRecord, resultJSON []byte, errText string) {
			s.captureToolCall(rctx, contextInfo, rec.Canonical, string(rec.ArgsJSON), string(resultJSON), errText)
		},
		Observer: &harnessCallObserver{s: s},
	})
	switch {
	case err == nil:
		return marshalMetaResult(s, struct {
			Result any `json:"result"`
		}{Result: result})
	case errors.Is(err, metatool.ErrNativeID):
		// The tool call handler owns a native call and its one record.
		tid, perr := toolid.Parse(in.ID)
		if perr != nil {
			tid, perr = toolid.Unflatten(in.ID)
		}
		if perr != nil {
			// gibson:no-tool-executed — the id was authorized, so it parses.
			return metaToolErr(commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, perr.Error()), nil
		}
		return s.invokeNativeTool(ctx, contextInfo, harness, tid.Tool, tid.Canonical(), argsJSON)
	case errors.Is(err, metatool.ErrBlocked):
		// gibson:no-tool-executed — denied before dispatch.
		return metaToolErr(commonpb.ErrorCode_ERROR_CODE_PERMISSION_DENIED, err.Error()), nil
	case errors.Is(err, metatool.ErrRunInactive):
		// gibson:no-tool-executed — denied before dispatch.
		return metaToolErr(commonpb.ErrorCode_ERROR_CODE_PERMISSION_DENIED, "mission run is not active"), nil
	case errors.Is(err, metatool.ErrAuditUnavailable):
		s.logger.ErrorContext(ctx, "meta-tool invoke refused: the audit record could not be written", "id", in.ID, "tenant", caller.Tenant, "err", err)
		// gibson:no-tool-executed — no call happens without its record.
		return metaToolErr(commonpb.ErrorCode_ERROR_CODE_UNAVAILABLE, "the audit record of the call could not be written"), nil
	}
	code := commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT
	if errors.Is(err, metatool.ErrUnauthorized) {
		code = commonpb.ErrorCode_ERROR_CODE_PERMISSION_DENIED
	}
	s.logger.WarnContext(ctx, "meta-tool invoke failed", "id", in.ID, "tenant", caller.Tenant, "err", err)
	// gibson:no-tool-executed — the observer recorded the failed call.
	return metaToolErr(code, err.Error()), nil
}

// runActiveCheck returns the run check of a mission policy for the status of a
// run in the authz store.
func runActiveCheck(status string) func(context.Context) error {
	return func(context.Context) error {
		if status != "active" {
			return fmt.Errorf("%w: status %q", metatool.ErrRunInactive, status)
		}
		return nil
	}
}

// MissionBlockedToolsSource reads the deny list of a mission from its stored
// definition. It reads the record of the tenant, not the memory of this replica.
type MissionBlockedToolsSource func(ctx context.Context, tenant, missionID string) ([]string, error)

// WithMissionBlockedTools wires the source of the mission deny list. A daemon
// with none refuses a connector call, because an unread deny list is not an
// empty one.
func WithMissionBlockedTools(src MissionBlockedToolsSource) CallbackServiceOption {
	return func(s *HarnessCallbackService) {
		s.missionBlockedTools = src
	}
}

// policyFromState builds the mission policy of the run in state: its active
// check from the run record, and its deny list from the stored definition of
// its mission. It fails when either cannot be read.
func (s *HarnessCallbackService) policyFromState(ctx context.Context, state *RunAuthzState) (metatool.MissionPolicy, error) {
	if s.missionBlockedTools == nil {
		return metatool.MissionPolicy{}, errors.New("the mission deny list source is not wired")
	}
	if state.MissionID == "" {
		return metatool.MissionPolicy{}, fmt.Errorf("run %q names no mission", state.RunID)
	}
	blocked, err := s.missionBlockedTools(ctx, state.TenantID, state.MissionID)
	if err != nil {
		return metatool.MissionPolicy{}, fmt.Errorf("read the deny list of mission %q: %w", state.MissionID, err)
	}
	return metatool.MissionPolicy{Blocked: blocked, RunActive: runActiveCheck(state.Status)}, nil
}

// storedBlockedTools reads the deny list of the mission of a callback from its
// stored definition. It is the one source of the deny list: the native tool
// path, the plugin path and invoke_tool all read it here. An unwired source and
// an unreadable list are errors, and the caller refuses the call.
func (s *HarnessCallbackService) storedBlockedTools(ctx context.Context, contextInfo *harnesspb.ContextInfo) ([]string, error) {
	if s.missionBlockedTools == nil {
		return nil, errors.New("the mission deny list source is not wired")
	}
	missionID := contextInfo.GetMissionId()
	if missionID == "" {
		return nil, errors.New("the callback names no mission")
	}
	blocked, err := s.missionBlockedTools(ctx, auth.TenantStringFromContext(ctx), missionID)
	if err != nil {
		return nil, fmt.Errorf("read the deny list of mission %q: %w", missionID, err)
	}
	return blocked, nil
}

// MissionPolicyForRun returns the mission policy of a run of the tenant, for a
// path that has no harness of its own, such as ComponentService.CallTool. A run
// of another tenant is refused.
func (s *HarnessCallbackService) MissionPolicyForRun(ctx context.Context, tenant, runID string) (metatool.MissionPolicy, error) {
	if s.authzStore == nil {
		return metatool.MissionPolicy{}, errors.New("the run authz store is not wired")
	}
	state, err := s.authzStore.Get(ctx, runID)
	if err != nil {
		return metatool.MissionPolicy{}, fmt.Errorf("read the authz state of run %q: %w", runID, err)
	}
	if state.TenantID != tenant {
		return metatool.MissionPolicy{}, fmt.Errorf("run %q does not belong to the tenant", runID)
	}
	return s.policyFromState(ctx, state)
}

// RecordToolCall writes the flight recorder record of a tool call that has no
// harness callback context, such as a connector call through
// ComponentService.CallTool. The tenant is on ctx.
func (s *HarnessCallbackService) RecordToolCall(ctx context.Context, rec metatool.CallRecord, resultJSON []byte, errText string) {
	s.captureToolCall(ctx, &harnesspb.ContextInfo{MissionId: rec.MissionID, MissionRunId: rec.RunID}, rec.Canonical, string(rec.ArgsJSON), string(resultJSON), errText)
}

// harnessCallObserver writes the intent and result audit records of an
// invoke_tool call of the harness.
type harnessCallObserver struct {
	s *HarnessCallbackService
}

var _ metatool.CallObserver = (*harnessCallObserver)(nil)

// auditCtx gives the audit logger an actor. A call from the callback listener
// carries no identity of its own, so the user of the run is the actor then.
func auditCtx(ctx context.Context, rec metatool.CallRecord) context.Context {
	if id, err := auth.IdentityFromContext(ctx); err == nil && id.Subject != "" {
		return ctx
	}
	tid, err := auth.NewTenantID(rec.Tenant)
	if err != nil {
		return ctx
	}
	return auth.WithIdentity(ctx, auth.Identity{Subject: rec.Subject, Tenant: tid, CredentialType: auth.CredentialOIDCUser})
}

func (o *harnessCallObserver) Intent(ctx context.Context, rec metatool.CallRecord) error {
	if err := (metatool.AuditRecorder{Log: o.s.connectorAudit}).Intent(auditCtx(ctx, rec), rec); err != nil {
		return fmt.Errorf("audit intent of %s: %w", rec.Canonical, err)
	}
	return nil
}

func (o *harnessCallObserver) Result(ctx context.Context, rec metatool.CallRecord, _ []byte, callErr error) {
	if rec.Connector == "" {
		return
	}
	if err := (metatool.AuditRecorder{Log: o.s.connectorAudit}).Result(auditCtx(ctx, rec), rec, callErr); err != nil {
		o.s.logger.ErrorContext(ctx, "meta-tool invoke: the result audit record was not written", "tenant", rec.Tenant, "err", err)
	}
}

// invokeNativeTool sends an authorized native:<tool> id from invoke_tool to
// the tool call handler of this service. That handler owns the whole call:
// the mission deny list, the execute gate of the dispatch, the sandbox path
// or the work queue path, the discovery ingest and the one record of the
// call. A tool with no usable descriptor never reaches it, and this function
// records that refusal.
func (s *HarnessCallbackService) invokeNativeTool(ctx context.Context, contextInfo *harnesspb.ContextInfo, harness AgentHarness, tool, canon string, argsJSON []byte) (*harnesspb.CallToolProtoResponse, error) {
	desc, err := harness.GetToolDescriptor(ctx, tool)
	if err == nil && (desc.InputProtoType == "" || desc.OutputProtoType == "") {
		err = fmt.Errorf("native tool %q declares no input or output message type", tool)
	}
	if err != nil {
		s.captureToolCall(ctx, contextInfo, canon, string(argsJSON), "", err.Error())
		return metaToolErr(commonpb.ErrorCode_ERROR_CODE_NOT_FOUND, fmt.Sprintf("native tool %q: %v", tool, err)), nil
	}

	resp, err := s.CallToolProto(ctx, &harnesspb.CallToolProtoRequest{
		Context:    contextInfo,
		Name:       tool,
		InputType:  desc.InputProtoType,
		OutputType: desc.OutputProtoType,
		InputJson:  argsJSON,
	})
	if err != nil {
		return nil, err
	}
	if e := resp.GetError(); e != nil {
		return metaToolErr(e.GetCode(), e.GetMessage()), nil
	}
	return marshalMetaResult(s, struct {
		Result json.RawMessage `json:"result"`
	}{Result: json.RawMessage(resp.GetOutputJson())})
}

// metaSearchCandidate is the LLM-facing shape of a catalog candidate. InputSchema
// is embedded raw so the agent sees the tool's own JSON schema verbatim.
type metaSearchCandidate struct {
	ID          string          `json:"id"`
	Source      string          `json:"source,omitempty"`
	Connector   string          `json:"connector,omitempty"`
	Tool        string          `json:"tool,omitempty"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"input_schema,omitempty"`
}

func marshalMetaResult(s *HarnessCallbackService, v any) (*harnesspb.CallToolProtoResponse, error) {
	b, err := json.Marshal(v)
	if err != nil {
		s.logger.Error("meta-tool: failed to marshal result", "err", err)
		return metaToolErr(commonpb.ErrorCode_ERROR_CODE_INTERNAL, "failed to marshal meta-tool result"), nil
	}
	return &harnesspb.CallToolProtoResponse{OutputJson: b}, nil
}

func metaToolErr(code commonpb.ErrorCode, msg string) *harnesspb.CallToolProtoResponse {
	return &harnesspb.CallToolProtoResponse{
		Error: &harnesspb.HarnessError{Code: code, Message: msg},
	}
}
